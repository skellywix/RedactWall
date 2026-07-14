'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const anchorModule = require('../server/monotonic-anchor-authority');
const {
  ANCHOR_STATE_MIGRATION_STATUS,
  INDEPENDENT_WITNESS_ASSURANCE,
  TEST_WITNESS_ASSURANCE,
  ZERO_DIGEST,
  createProductionMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorStorage,
} = anchorModule;

const DIGEST_ONE = '1'.repeat(64);
const DIGEST_TWO = '2'.repeat(64);
const WITNESS = 'a'.repeat(64);
const OTHER_WITNESS = 'b'.repeat(64);
const STORAGE_IDENTITY = 'c'.repeat(64);
const OTHER_STORAGE_IDENTITY = 'd'.repeat(64);
const DIGEST_THREE = '3'.repeat(64);
const PURPOSE = 'customer_catalog_witness';
const STORAGE_CONTEXT = 'customer-catalog-reference';
const REFERENCE_WITNESS_NAMESPACE_CAP = 64;
const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

process.env.NODE_ENV = 'test';
test.after(() => setNodeEnvironment(ORIGINAL_NODE_ENV));

function transition(overrides = {}) {
  return {
    namespace: 'catalog:customer_one:deployment_one',
    expectedRevision: 0,
    expectedDigest: ZERO_DIGEST,
    targetRevision: 1,
    targetDigest: DIGEST_ONE,
    witnessDigest: WITNESS,
    ...overrides,
  };
}

function authorityOptions(storage, overrides = {}) {
  return {
    storage,
    keyId: 'rw-anchor-catalog-customer',
    secret: Buffer.alloc(32, 0x6a),
    purpose: PURPOSE,
    storageContext: STORAGE_CONTEXT,
    storageIdentity: STORAGE_IDENTITY,
    ...overrides,
  };
}

function setup(storage = createReferenceMonotonicAnchorStorage(), overrides = {}) {
  return {
    storage,
    authority: createReferenceMonotonicAnchorAuthority(authorityOptions(storage, overrides)),
  };
}

function expectedBinding(overrides = {}) {
  return {
    assurance: TEST_WITNESS_ASSURANCE,
    keyId: 'rw-anchor-catalog-customer',
    purpose: PURPOSE,
    storageContext: STORAGE_CONTEXT,
    storageIdentity: STORAGE_IDENTITY,
    ...overrides,
  };
}

function expectedPending(overrides = {}) {
  const value = transition(overrides);
  return {
    expectedRevision: value.expectedRevision,
    expectedDigest: value.expectedDigest,
    targetRevision: value.targetRevision,
    targetDigest: value.targetDigest,
    witnessDigest: value.witnessDigest,
  };
}

test('separate authority prepares and finalizes one exact monotonic transition', () => {
  const { authority } = setup();
  const initial = authority.read(transition().namespace);
  assert.equal(initial.schemaVersion, 3);
  assert.deepEqual(initial.binding, expectedBinding());
  assert.equal(initial.namespace, transition().namespace);
  assert.equal(initial.generation, 0);
  assert.equal(initial.revision, 0);
  assert.equal(initial.headDigest, ZERO_DIGEST);
  assert.match(initial.lineageDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(initial.ancestry, []);
  assert.deepEqual(initial.abortedTransitionDigests, []);
  assert.equal(initial.pending, null);
  assert.equal(initial.lastResolution, null);
  const prepared = authority.prepare(transition());
  assert.equal(prepared.generation, 1);
  assert.deepEqual(prepared.pending, expectedPending());
  assert.equal(prepared.lastResolution, null);
  assert.deepEqual(authority.prepare(transition()), prepared);
  assert.equal(authority.listPending()[0].namespace, transition().namespace);
  const finalized = authority.finalize(transition());
  assert.equal(finalized.generation, 2);
  assert.equal(finalized.revision, 1);
  assert.equal(finalized.headDigest, DIGEST_ONE);
  assert.equal(finalized.pending, null);
  assert.deepEqual(finalized.lastResolution, {
    outcome: 'finalized',
    resolvedGeneration: 2,
    transition: expectedPending(),
  });
  assert.deepEqual(authority.finalize(transition()), finalized);
  assert.deepEqual(authority.listPending(), []);
});

test('reference factories are test-only and caller assurance cannot mint production trust',
  { concurrency: false }, () => {
    const previous = process.env.NODE_ENV;
    const referenceStorage = createReferenceMonotonicAnchorStorage();
    const existingReference = setup(referenceStorage).authority;
    try {
      for (const environment of [
        undefined, '', '   ', '\t\r\n', 'production', ' Production ', 'PROD',
        'production-us', 'preview', 'release', 'staging', 'dev', 't-e-s-t', 'develop_ment',
        'TEST', 'DEVELOPMENT', 'test ', ' development ',
      ]) {
        setNodeEnvironment(environment);
        assert.throws(() => createReferenceMonotonicAnchorStorage(), {
          code: 'reference_anchor_forbidden_in_production',
        });
        assert.throws(() => createReferenceMonotonicAnchorAuthority(
          authorityOptions(referenceStorage),
        ), {
          code: 'reference_anchor_forbidden_in_production',
        });
        assert.throws(() => existingReference.read(transition().namespace), {
          code: 'reference_anchor_forbidden_in_production',
        });
        assert.throws(() => existingReference.describe(), {
          code: 'reference_anchor_forbidden_in_production',
        });
        for (const operation of Object.values(referenceStorage).filter(
          (value) => typeof value === 'function',
        )) {
          assert.throws(() => operation(), {
            code: 'reference_anchor_forbidden_in_production',
          });
        }
      }
    } finally {
      setNodeEnvironment(previous);
    }

    try {
      for (const environment of ['test', 'development']) {
        setNodeEnvironment(environment);
        const allowedStorage = createReferenceMonotonicAnchorStorage();
        const allowedAuthority = createReferenceMonotonicAnchorAuthority(
          authorityOptions(allowedStorage),
        );
        assert.equal(allowedAuthority.read(transition().namespace).revision, 0);
      }
    } finally {
      setNodeEnvironment(previous);
    }

    const labeled = Object.freeze({ assurance: INDEPENDENT_WITNESS_ASSURANCE });
    assert.throws(() => createReferenceMonotonicAnchorAuthority(authorityOptions(labeled)), {
      code: 'anchor_authority_invalid',
    });
    assert.throws(() => createReferenceMonotonicAnchorAuthority({
      ...authorityOptions(createReferenceMonotonicAnchorStorage()),
      assurance: INDEPENDENT_WITNESS_ASSURANCE,
    }), { code: 'anchor_authority_invalid' });
    assert.throws(() => createProductionMonotonicAnchorAuthority({
      adapter: { assurance: INDEPENDENT_WITNESS_ASSURANCE },
      ...authorityOptions(createReferenceMonotonicAnchorStorage()),
    }), { code: 'production_anchor_adapter_unavailable' });

    assert.throws(() => createReferenceMonotonicAnchorAuthority({
      ...authorityOptions(createReferenceMonotonicAnchorStorage()),
      clock: () => 0,
    }), { code: 'anchor_authority_invalid' });
    const accessorOptions = authorityOptions(createReferenceMonotonicAnchorStorage());
    Object.defineProperty(accessorOptions, 'storageContext', {
      enumerable: true,
      get: () => STORAGE_CONTEXT,
    });
    assert.throws(() => createReferenceMonotonicAnchorAuthority(accessorOptions), {
      code: 'anchor_authority_invalid',
    });
  });

test('generic monotonic authority entry point is not exported', () => {
  assert.equal(Object.hasOwn(anchorModule, 'createMonotonicAnchorAuthority'), false);
});

test('storage-private witness rejects a restore hidden from the original authority', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  const authorityA = setup(storage).authority;
  const authorityB = setup(storage).authority;
  authorityA.prepare(transition());
  authorityA.finalize(transition());
  const revisionOne = storage.snapshot();
  const second = transition({
    expectedRevision: 1,
    expectedDigest: DIGEST_ONE,
    targetRevision: 2,
    targetDigest: DIGEST_TWO,
  });
  authorityB.prepare(second);
  assert.equal(authorityB.finalize(second).revision, 2);

  storage.restore(revisionOne);
  const conflictingSecond = {
    ...second,
    targetDigest: DIGEST_THREE,
    witnessDigest: OTHER_WITNESS,
  };
  assert.throws(() => authorityA.prepare(conflictingSecond), {
    code: 'anchor_reference_witness_rewind',
  });
});

test('public row controls cannot alter or export the private witness', () => {
  const mutations = [
    (storage) => storage.restore(new Map()),
    (storage) => storage.delete(transition().namespace),
    (storage) => storage.replace(transition().namespace, {
      ...storage.readRaw(transition().namespace), mac: '0'.repeat(64),
    }),
    (storage) => storage.tamper((rows) => {
      rows.get(transition().namespace).mac = '0'.repeat(64);
    }),
  ];
  for (const mutate of mutations) {
    const { authority, storage } = setup();
    authority.prepare(transition());
    const snapshot = storage.snapshot();
    assert.equal(snapshot instanceof Map, true);
    assert.equal(Object.hasOwn(storage, 'acceptedWitnesses'), false);
    mutate(storage);
    assert.throws(() => authority.read(transition().namespace), {
      code: 'anchor_reference_witness_rewind',
    });
  }
});

test('an authenticated row cannot bootstrap an unwitnessed reference storage', () => {
  const source = setup();
  source.authority.prepare(transition());

  const target = setup();
  target.storage.replace(
    transition().namespace,
    source.storage.readRaw(transition().namespace),
  );

  assert.throws(() => target.authority.read(transition().namespace), {
    code: 'anchor_reference_witness_rewind',
  });
});

test('reference witness is capped, missing reads do not allocate, and entries are not evicted', () => {
  const { authority, storage } = setup();
  for (let index = 0; index < REFERENCE_WITNESS_NAMESPACE_CAP + 8; index += 1) {
    const state = authority.read(`catalog:missing_customer:deployment_${index}`);
    assert.equal(state.revision, 0);
  }

  for (let index = 0; index < REFERENCE_WITNESS_NAMESPACE_CAP; index += 1) {
    authority.prepare(transition({ namespace: `catalog:cap_customer:deployment_${index}` }));
  }
  const overflow = transition({
    namespace: `catalog:cap_customer:deployment_${REFERENCE_WITNESS_NAMESPACE_CAP}`,
  });
  assert.throws(() => authority.prepare(overflow), {
    code: 'anchor_reference_witness_capacity',
  });
  assert.equal(storage.readRaw(overflow.namespace), undefined);

  const source = setup();
  source.authority.prepare(overflow);
  storage.replace(overflow.namespace, source.storage.readRaw(overflow.namespace));
  assert.throws(() => authority.read(overflow.namespace), {
    code: 'anchor_reference_witness_rewind',
  });

  const firstNamespace = 'catalog:cap_customer:deployment_0';
  storage.delete(firstNamespace);
  assert.throws(() => authority.read(firstNamespace), {
    code: 'anchor_reference_witness_rewind',
  });
});

test('purpose, storage context, and storage identity are authenticated and not reusable', () => {
  const { authority, storage } = setup();
  authority.prepare(transition());

  for (const overrides of [
    { purpose: 'owner_catalog_witness' },
    { storageContext: 'other-catalog-reference' },
    { storageIdentity: OTHER_STORAGE_IDENTITY },
  ]) {
    const conflicting = createReferenceMonotonicAnchorAuthority(
      authorityOptions(storage, overrides),
    );
    assert.throws(() => conflicting.read(transition().namespace), {
      code: 'anchor_state_binding_invalid',
    });
    assert.throws(() => conflicting.read('catalog:other_customer:deployment_one'), {
      code: 'anchor_state_binding_invalid',
    });
  }
});

test('storage witness rejects rollback and divergent histories before state reuse', () => {
  const rollbackStorage = createReferenceMonotonicAnchorStorage();
  const rollbackA = setup(rollbackStorage).authority;
  rollbackA.prepare(transition());
  rollbackA.finalize(transition());
  rollbackStorage.delete(transition().namespace);
  const rollbackB = setup(rollbackStorage).authority;
  assert.throws(() => rollbackB.prepare(transition()), {
    code: 'anchor_reference_witness_rewind',
  });

  const forkStorage = createReferenceMonotonicAnchorStorage();
  const forkA = setup(forkStorage).authority;
  forkA.prepare(transition());
  forkA.finalize(transition());
  forkStorage.delete(transition().namespace);
  const forkB = setup(forkStorage).authority;
  const divergentFirst = transition({ targetDigest: DIGEST_TWO });
  assert.throws(() => forkB.prepare(divergentFirst), {
    code: 'anchor_reference_witness_rewind',
  });

  const validStorage = createReferenceMonotonicAnchorStorage();
  const validA = setup(validStorage).authority;
  validA.prepare(transition());
  validA.finalize(transition());
  const validB = setup(validStorage).authority;
  const validSecond = transition({
    expectedRevision: 1,
    expectedDigest: DIGEST_ONE,
    targetRevision: 2,
    targetDigest: DIGEST_TWO,
  });
  validB.prepare(validSecond);
  validB.finalize(validSecond);
  assert.equal(validA.read(transition().namespace).revision, 2);
});

test('storage witness preserves pending and aborted attempt history', () => {
  const pendingStorage = createReferenceMonotonicAnchorStorage();
  const pendingA = setup(pendingStorage).authority;
  pendingA.prepare(transition());
  pendingStorage.delete(transition().namespace);
  const pendingB = setup(pendingStorage).authority;
  const divergent = transition({ targetDigest: DIGEST_TWO });
  assert.throws(() => pendingB.prepare(divergent), {
    code: 'anchor_reference_witness_rewind',
  });

  const reuseStorage = createReferenceMonotonicAnchorStorage();
  const reuseA = setup(reuseStorage).authority;
  reuseA.prepare(transition());
  reuseA.abort(transition());
  reuseStorage.delete(transition().namespace);
  const reuseB = setup(reuseStorage).authority;
  assert.throws(() => reuseB.prepare(transition()), {
    code: 'anchor_reference_witness_rewind',
  });
});

test('authenticated lineage remains valid when its proof window truncates', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  const { authority } = setup(storage);
  let expectedDigest = ZERO_DIGEST;
  for (let revision = 1; revision <= 66; revision += 1) {
    const request = transition({
      expectedRevision: revision - 1,
      expectedDigest,
      targetRevision: revision,
      targetDigest: sha256Text(`head:${revision}`),
      witnessDigest: sha256Text(`witness:${revision}`),
    });
    authority.prepare(request);
    authority.finalize(request);
    expectedDigest = request.targetDigest;
  }
  const state = setup(storage).authority.read(transition().namespace);
  assert.equal(state.revision, 66);
  assert.equal(state.ancestry.length, 64);
  assert.equal(state.ancestry[0].revision, 3);
  assert.equal(state.ancestry.at(-1).revision, 66);
  assert.equal(state.ancestry.at(-1).lineageDigest, state.lineageDigest);
});

test('shared witness permits multi-authority progress beyond the 64-entry proof window', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  const firstAuthority = setup(storage).authority;
  firstAuthority.prepare(transition());
  firstAuthority.finalize(transition());
  advanceLineage(setup(storage).authority, 2, 66, DIGEST_ONE);
  const state = firstAuthority.read(transition().namespace);
  assert.equal(state.revision, 66);
  assert.equal(state.ancestry.length, 64);
  assert.equal(state.ancestry[0].revision, 3);
});

test('storage witness rejects a restored alternate fork at the compaction edge', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  const authorityA = setup(storage).authority;
  authorityA.prepare(transition());
  authorityA.finalize(transition());
  const revision65Digest = advanceLineage(authorityA, 2, 65, DIGEST_ONE);
  const revision65 = storage.snapshot();
  const legitimate66 = transition({
    expectedRevision: 65,
    expectedDigest: revision65Digest,
    targetRevision: 66,
    targetDigest: sha256Text('compaction-edge:legitimate:66'),
    witnessDigest: sha256Text('compaction-edge:witness:66'),
  });
  const authorityB = setup(storage).authority;
  authorityB.prepare(legitimate66);
  authorityB.finalize(legitimate66);

  storage.restore(revision65);
  const alternate66 = {
    ...legitimate66,
    targetDigest: sha256Text('compaction-edge:alternate:66'),
  };
  assert.throws(() => authorityA.prepare(alternate66), {
    code: 'anchor_reference_witness_rewind',
  });
});

test('an aborted transition cannot be re-prepared and delayed decisions cannot cross attempts', () => {
  const { authority } = setup();
  authority.prepare(transition());
  authority.abort(transition());
  assert.throws(() => authority.prepare(transition()), { code: 'anchor_transition_reused' });

  const secondAttempt = transition({ witnessDigest: OTHER_WITNESS });
  authority.prepare(secondAttempt);
  assert.throws(() => authority.finalize(transition()), { code: 'anchor_finalize_conflict' });
  assert.throws(() => authority.abort(transition()), { code: 'anchor_abort_conflict' });
  assert.equal(authority.finalize(secondAttempt).revision, 1);
});

test('aborted transition history is bounded and fails closed at its attempt cap', () => {
  const { authority } = setup();
  for (let attempt = 0; attempt < 1_024; attempt += 1) {
    const request = transition({ witnessDigest: sha256Text(`aborted:${attempt}`) });
    authority.prepare(request);
    authority.abort(request);
  }
  assert.throws(() => authority.prepare(transition({
    witnessDigest: sha256Text('aborted:overflow'),
  })), { code: 'anchor_attempt_limit' });
});

test('storage cannot mutate a private operation result after callback or readback', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  const { authority } = setup(storage);
  storage.decorateNextReceiptValue();
  const prepared = authority.prepare(transition());
  assert.equal(prepared.schemaVersion, 3);
  assert.deepEqual(prepared.pending, expectedPending());
  assert.equal(prepared.generation, 1);
});

test('post-callback deletion or restore cannot be reported as committed success', () => {
  const deletedStorage = createReferenceMonotonicAnchorStorage();
  const deletedAuthority = setup(deletedStorage).authority;
  deletedStorage.deleteAfterNextCommit(transition().namespace);
  assert.throws(() => deletedAuthority.prepare(transition()), {
    code: 'anchor_postcommit_verification_failed',
  });

  const restoredStorage = createReferenceMonotonicAnchorStorage();
  const restoredAuthority = setup(restoredStorage).authority;
  restoredAuthority.prepare(transition());
  const prior = restoredStorage.snapshot();
  restoredStorage.restoreAfterNextCommit(prior);
  assert.throws(() => restoredAuthority.finalize(transition()), {
    code: 'anchor_postcommit_verification_failed',
  });
});

test('lost response cannot accept a post-commit replacement into the witness', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  const authority = setup(storage).authority;
  authority.prepare(transition());
  const prior = storage.snapshot();
  storage.restoreAfterNextCommit(prior);
  storage.loseNextResponse();
  assert.throws(() => authority.finalize(transition()), {
    code: 'anchor_postcommit_verification_failed',
  });
  assert.equal(authority.finalize(transition()).revision, 1);
});

test('CAS rejects a same-generation alternate authenticated envelope', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  const authority = setup(storage).authority;
  authority.prepare(transition());
  const expected = storage.readRaw(transition().namespace);

  const alternateStorage = createReferenceMonotonicAnchorStorage();
  const alternateAuthority = setup(alternateStorage).authority;
  const alternateTransition = transition({ targetDigest: DIGEST_TWO });
  alternateAuthority.prepare(alternateTransition);
  const alternate = alternateStorage.readRaw(transition().namespace);
  assert.equal(alternate.payload.generation, expected.payload.generation);
  assert.notEqual(alternate.mac, expected.mac);

  storage.substituteBeforeNextCompare(transition().namespace, alternate);
  assert.throws(() => authority.finalize(transition()), { code: 'anchor_cas_conflict' });
  assert.deepEqual(storage.readRaw(transition().namespace), expected);
});

test('legacy anchor state has an explicit migration policy but public import is witness-rejected', () => {
  assert.deepEqual(ANCHOR_STATE_MIGRATION_STATUS, {
    currentSchemaVersion: 3,
    migrationEligibleSchemaVersions: [2],
    unsupportedSchemaVersions: [1],
    policy: 'authenticated_v2_explicit_migration_or_reset_required',
  });
  const authenticatedStorage = createReferenceMonotonicAnchorStorage();
  const payload = legacyV2Payload();
  authenticatedStorage.replace(transition().namespace, {
    schemaVersion: 2,
    keyId: 'rw-anchor-catalog-customer',
    payload,
    mac: testLegacyV2StateMac(payload, 'rw-anchor-catalog-customer', Buffer.alloc(32, 0x6a)),
  });
  // Reference storage has no trusted migration-import capability. Any row
  // planted through its public controls is unwitnessed and fails at that
  // stronger boundary before an envelope-specific migration classification.
  assert.throws(() => setup(authenticatedStorage).authority.read(transition().namespace), {
    code: 'anchor_reference_witness_rewind',
  });

  for (const schemaVersion of [1, 2]) {
    const storage = createReferenceMonotonicAnchorStorage();
    storage.replace(transition().namespace, {
      schemaVersion,
      keyId: 'rw-anchor-catalog-customer',
      payload: {
        schemaVersion,
        namespace: transition().namespace,
        generation: 0,
        revision: 0,
        headDigest: ZERO_DIGEST,
        pending: null,
      },
      mac: '0'.repeat(64),
    });
    assert.throws(() => setup(storage).authority.read(transition().namespace), {
      code: 'anchor_reference_witness_rewind',
    });
  }
});

test('finalize and abort require the exact pending transition or exact last resolution', () => {
  const { authority } = setup();
  assert.throws(() => authority.finalize(transition()), { code: 'anchor_finalize_conflict' });
  assert.throws(() => authority.abort(transition()), { code: 'anchor_abort_conflict' });
  assert.throws(() => authority.prepare(transition({ expectedRevision: -0 })), {
    code: 'anchor_request_invalid',
  });
  const accessorTransition = transition();
  Object.defineProperty(accessorTransition, 'targetDigest', {
    enumerable: true,
    get: () => DIGEST_ONE,
  });
  assert.throws(() => authority.prepare(accessorTransition), {
    code: 'anchor_request_invalid',
  });

  authority.prepare(transition());
  assert.throws(() => authority.finalize(transition({ witnessDigest: OTHER_WITNESS })), {
    code: 'anchor_finalize_conflict',
  });
  const finalized = authority.finalize(transition());
  assert.deepEqual(authority.finalize(transition()), finalized);
  assert.throws(() => authority.finalize(transition({ witnessDigest: OTHER_WITNESS })), {
    code: 'anchor_finalize_conflict',
  });
  assert.throws(() => authority.abort(transition()), { code: 'anchor_abort_conflict' });

  const next = transition({
    expectedRevision: 1,
    expectedDigest: DIGEST_ONE,
    targetRevision: 2,
    targetDigest: DIGEST_TWO,
  });
  authority.prepare(next);
  const aborted = authority.abort(next);
  assert.deepEqual(authority.abort(next), aborted);
  assert.throws(() => authority.abort({ ...next, witnessDigest: OTHER_WITNESS }), {
    code: 'anchor_abort_conflict',
  });
  assert.throws(() => authority.finalize(transition()), { code: 'anchor_finalize_conflict' });
});

test('lost responses return only the exact authenticated resolution after restart', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  let { authority } = setup(storage);
  storage.loseNextResponse();
  assert.throws(() => authority.prepare(transition()), { code: 'anchor_reference_response_lost' });
  authority = setup(storage).authority;
  assert.deepEqual(authority.prepare(transition()).pending, expectedPending());

  storage.loseNextResponse();
  assert.throws(() => authority.finalize(transition()), { code: 'anchor_reference_response_lost' });
  authority = setup(storage).authority;
  const recovered = authority.finalize(transition());
  assert.equal(recovered.revision, 1);
  assert.equal(recovered.lastResolution.outcome, 'finalized');
  assert.deepEqual(recovered.lastResolution.transition, expectedPending());
  assert.throws(() => authority.finalize(transition({ witnessDigest: OTHER_WITNESS })), {
    code: 'anchor_finalize_conflict',
  });
});

test('rollback, truncation, changed identity, and forged state fail closed', () => {
  const { authority, storage } = setup();
  authority.prepare(transition());
  const preparedSnapshot = storage.snapshot();
  authority.finalize(transition());

  storage.restore(preparedSnapshot);
  assert.throws(() => authority.read(transition().namespace), {
    code: 'anchor_reference_witness_rewind',
  });
  const truncatedStorage = createReferenceMonotonicAnchorStorage();
  const truncated = setup(truncatedStorage).authority;
  truncated.prepare(transition());
  truncatedStorage.delete(transition().namespace);
  assert.throws(() => truncated.read(transition().namespace), {
    code: 'anchor_reference_witness_rewind',
  });

  const cleanStorage = createReferenceMonotonicAnchorStorage();
  const first = setup(cleanStorage).authority;
  first.prepare(transition());
  const restarted = setup(cleanStorage).authority;
  assert.deepEqual(restarted.read(transition().namespace).pending, expectedPending());
  const changedIdentity = setup(cleanStorage, { storageIdentity: OTHER_STORAGE_IDENTITY }).authority;
  assert.throws(() => changedIdentity.read(transition().namespace), {
    code: 'anchor_state_binding_invalid',
  });

  const forgedStorage = createReferenceMonotonicAnchorStorage();
  forgedStorage.restore(cleanStorage.snapshot());
  forgedStorage.tamper((rows) => { rows.get(transition().namespace).mac = '0'.repeat(64); });
  assert.throws(() => setup(forgedStorage).authority.read(transition().namespace), {
    code: 'anchor_reference_witness_rewind',
  });
});

test('authenticated state remains exact and the private storage capability cannot be forged', () => {
  const malformedSource = createReferenceMonotonicAnchorStorage();
  setup(malformedSource).authority.prepare(transition());
  const malformedStorage = createReferenceMonotonicAnchorStorage();
  malformedStorage.restore(malformedSource.snapshot());
  malformedStorage.tamper((rows) => {
    const wrapped = rows.get(transition().namespace);
    wrapped.payload.pending.ignoredClock = 1;
    wrapped.mac = testStateMac(wrapped.payload, wrapped.keyId, Buffer.alloc(32, 0x6a));
  });
  const malformed = setup(malformedStorage).authority;
  assert.throws(() => malformed.read(transition().namespace), {
    code: 'anchor_reference_witness_rewind',
  });

  const accessorSource = createReferenceMonotonicAnchorStorage();
  setup(accessorSource).authority.prepare(transition());
  const accessorStorage = createReferenceMonotonicAnchorStorage();
  accessorStorage.restore(accessorSource.snapshot());
  let accessorReads = 0;
  accessorStorage.tamper((rows) => {
    const wrapped = rows.get(transition().namespace);
    const pending = wrapped.payload.pending;
    Object.defineProperty(wrapped.payload, 'pending', {
      enumerable: true,
      get: () => {
        accessorReads += 1;
        return pending;
      },
    });
  });
  const accessorBound = setup(accessorStorage).authority;
  assert.throws(() => accessorBound.read(transition().namespace), {
    code: 'anchor_reference_witness_rewind',
  });
  assert.equal(accessorReads, 0);

  const metadataStorage = createReferenceMonotonicAnchorStorage();
  const metadataBound = setup(metadataStorage).authority;
  assert.throws(() => { metadataStorage.assurance = INDEPENDENT_WITNESS_ASSURANCE; }, TypeError);
  assert.equal(metadataBound.read(transition().namespace).revision, 0);
  const forged = Object.freeze({
    assurance: TEST_WITNESS_ASSURANCE,
    kind: 'memory_reference',
    schemaVersion: 1,
    stateKind: 'monotonic_anchor_reference',
  });
  assert.throws(() => createReferenceMonotonicAnchorAuthority(
    authorityOptions(forged),
  ), { code: 'anchor_authority_invalid' });
});

test('abort is exact and a failed storage commit leaves no published transition', () => {
  const storage = createReferenceMonotonicAnchorStorage();
  const { authority } = setup(storage);
  storage.failNextCommit();
  assert.throws(() => authority.prepare(transition()), { code: 'anchor_reference_commit_failed' });
  assert.equal(authority.read(transition().namespace).revision, 0);
  authority.prepare(transition());
  const aborted = authority.abort(transition());
  assert.equal(aborted.revision, 0);
  assert.equal(aborted.pending, null);
  assert.equal(aborted.lastResolution.outcome, 'aborted');
  assert.deepEqual(authority.abort(transition()), aborted);
  assert.deepEqual(setup(storage).authority.abort(transition()), aborted);
});

function sha256Text(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function setNodeEnvironment(value) {
  if (value === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = value;
}

function advanceLineage(authority, firstRevision, lastRevision, initialDigest) {
  let expectedDigest = initialDigest;
  for (let revision = firstRevision; revision <= lastRevision; revision += 1) {
    const request = transition({
      expectedRevision: revision - 1,
      expectedDigest,
      targetRevision: revision,
      targetDigest: sha256Text(`boundary-head:${revision}`),
      witnessDigest: sha256Text(`boundary-witness:${revision}`),
    });
    authority.prepare(request);
    authority.finalize(request);
    expectedDigest = request.targetDigest;
  }
  return expectedDigest;
}

function legacyV2Payload() {
  return {
    schemaVersion: 2,
    binding: expectedBinding(),
    namespace: transition().namespace,
    generation: 0,
    revision: 0,
    headDigest: ZERO_DIGEST,
    pending: null,
    lastResolution: null,
  };
}

function testLegacyV2StateMac(payload, keyId, secret) {
  const domain = `redactwall.monotonic-anchor.v2\0${keyId}\0${canonicalJson(payload.binding)}\0`;
  return crypto.createHmac('sha256', secret)
    .update(`${domain}${canonicalJson(payload)}`, 'utf8').digest('hex');
}

function testStateMac(payload, keyId, secret) {
  const domain = `redactwall.monotonic-anchor.v3\0${keyId}\0${canonicalJson(payload.binding)}\0`;
  return crypto.createHmac('sha256', secret)
    .update(`${domain}${canonicalJson(payload)}`, 'utf8').digest('hex');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!value || typeof value !== 'object') return JSON.stringify(value);
  return `{${Object.keys(value).sort().map(
    (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
  ).join(',')}}`;
}
