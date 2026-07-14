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
  normalizePublicKeys,
  verifySignedArtifact,
} = require('../server/vendor-signed-artifact');
const {
  createProductionVersionedAuthorityManifest,
  createVersionedAuthorityManifest,
  encodePublicKey,
  signAuthorityManifest,
} = require('../server/vendor-authority-manifest');

const ISSUED = '2026-07-13T12:00:00.000Z';
const ZERO_DIGEST = '0'.repeat(64);

test('production manifest construction fails closed without managed storage and witness adapters', () => {
  assert.throws(() => createProductionVersionedAuthorityManifest({
    storage: { productionReady: true },
    anchorAuthority: { assurance: 'independent_nonrewindable' },
  }), { code: 'authority_manifest_production_adapter_unavailable' });
});

test('genesis verifier registry rejects private PEM, PKCS8 wrappers, and private KeyObjects', () => {
  const pair = crypto.generateKeyPairSync('ed25519');
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateDer = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  for (const publicKey of [
    privatePem,
    { key: privateDer, format: 'der', type: 'pkcs8' },
    pair.privateKey,
  ]) {
    const storage = new MemoryManifestStorage({});
    const anchorAuthority = createReferenceMonotonicAnchorAuthority({
      storage: createReferenceMonotonicAnchorStorage(),
      keyId: 'rw-anchor-private-genesis-test',
      secret: Buffer.alloc(32, 0x71),
      purpose: 'authority_manifest_witness',
    });
    assert.throws(() => createVersionedAuthorityManifest({
      storage,
      anchorAuthority,
      allowTestWitness: true,
      genesisPublicKeys: { 'rw-owner-attestation-private': publicKey },
    }), { code: 'authority_manifest_invalid' });
  }
});

function harness() {
  const referenceCounts = {};
  const storage = new MemoryManifestStorage(referenceCounts);
  const anchorStorage = createReferenceMonotonicAnchorStorage();
  const material = createMaterial();
  const anchorAuthority = createReferenceMonotonicAnchorAuthority({
    storage: anchorStorage,
    keyId: 'rw-anchor-owner-authority-manifest',
    secret: Buffer.alloc(32, 0x61),
    purpose: 'authority_manifest_witness',
  });
  const service = createVersionedAuthorityManifest({
    storage,
    anchorAuthority,
    allowTestWitness: true,
    genesisPublicKeys: {
      [material[KEY_PURPOSES.OWNER_ATTESTATION].a.keyId]:
        material[KEY_PURPOSES.OWNER_ATTESTATION].a.publicKey,
    },
  });
  return { service, storage, anchorStorage, anchorAuthority, material, referenceCounts };
}

test('authenticated 20-purpose manifest rotates A to B to C and retains referenced verify-only keys', () => {
  const run = harness();
  assert.equal(Object.keys(AUTHORITY_DEFINITIONS).length, 20);
  const first = artifactFor(run, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  assert.equal(run.service.install(first).generation, 1);
  const globalA = run.material[KEY_PURPOSES.CATALOG_GLOBAL].a.keyId;
  run.referenceCounts[globalA] = 1;
  const second = artifactFor(run, 2, 'b', 'c', ['a'], digest(first), 'b');
  assert.equal(run.service.install(second).generation, 2);
  assert.deepEqual(run.service.registry().list(KEY_PURPOSES.CATALOG_GLOBAL)
    .map((record) => [record.slot, record.keyId, record.references]), [
    ['current', run.material[KEY_PURPOSES.CATALOG_GLOBAL].b.keyId, 0],
    ['next', run.material[KEY_PURPOSES.CATALOG_GLOBAL].c.keyId, 0],
    ['verifyOnly', globalA, 1],
  ]);
  const registry = run.service.registry();
  assert.deepEqual([...registry.activePublicKeys(KEY_PURPOSES.CATALOG_GLOBAL).keys()], [
    run.material[KEY_PURPOSES.CATALOG_GLOBAL].b.keyId,
    run.material[KEY_PURPOSES.CATALOG_GLOBAL].c.keyId,
  ]);
  assert.deepEqual([...registry.publicKeys(KEY_PURPOSES.CATALOG_GLOBAL).keys()], [
    run.material[KEY_PURPOSES.CATALOG_GLOBAL].b.keyId,
    run.material[KEY_PURPOSES.CATALOG_GLOBAL].c.keyId,
  ]);
  assert.deepEqual([...registry.verificationPublicKey(
    KEY_PURPOSES.CATALOG_GLOBAL, globalA,
  ).keys()], [globalA]);
  assert.throws(() => registry.verificationPublicKey(
    KEY_PURPOSES.CATALOG_GLOBAL, 'rw-catalog-global-unknown',
  ), { code: 'authority_manifest_public_key_required' });
  const archivedArtifact = signedGlobalArtifact(run, 'a');
  assert.throws(() => verifySignedArtifact(
    archivedArtifact,
    registry.activePublicKeys(KEY_PURPOSES.CATALOG_GLOBAL),
    protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    { purpose: KEY_PURPOSES.CATALOG_GLOBAL, strictPurpose: true },
  ), { code: 'unknown_signing_key' });
  assert.equal(verifySignedArtifact(
    archivedArtifact,
    registry.verificationPublicKey(KEY_PURPOSES.CATALOG_GLOBAL, globalA),
    protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    { purpose: KEY_PURPOSES.CATALOG_GLOBAL, strictPurpose: true },
  ).payload.globalVersion, 1);
  assert.throws(() => normalizePublicKeys({
    [globalA]: run.material[KEY_PURPOSES.CATALOG_GLOBAL].a.publicKey,
  }, {
    purpose: KEY_PURPOSES.CATALOG_GLOBAL,
    authorityRegistry: registry,
  }), { code: 'vendor_authority_manifest_mismatch' });
  assert.doesNotThrow(() => registry.assertHistoricalPublicKey(
    KEY_PURPOSES.CATALOG_GLOBAL,
    globalA,
    keyFingerprint(run.material[KEY_PURPOSES.CATALOG_GLOBAL].a.publicKey),
  ));

  const removingReferenced = artifactFor(run, 3, 'c', null, [], digest(second), 'c');
  assert.throws(() => run.service.install(removingReferenced), {
    code: 'authority_manifest_key_still_referenced',
  });
  run.referenceCounts[globalA] = 0;
  const globalB = run.material[KEY_PURPOSES.CATALOG_GLOBAL].b.keyId;
  run.referenceCounts[globalB] = 1;
  const third = artifactFor(run, 3, 'c', null, ['b'], digest(second), 'c');
  assert.equal(run.service.install(third).generation, 3);
  const globalKeys = run.service.registry().list(KEY_PURPOSES.CATALOG_GLOBAL);
  assert.deepEqual(globalKeys.map((record) => record.slot), ['current', 'verifyOnly']);
  assert.equal(globalKeys.some((record) => record.keyId === globalA), false);
  assert.equal(globalKeys.find((record) => record.keyId === globalB).references, 1);
});

test('entitlement current, next, and verify-only records require the exact full fingerprint key ID', () => {
  const run = harness();
  const base = payloadFor(run, 1, 'a', 'b', [], ZERO_DIGEST);
  base.authorities[KEY_PURPOSES.ENTITLEMENT].verifyOnly = [
    publicIdentity(run, KEY_PURPOSES.ENTITLEMENT, 'c'),
  ];
  const selectors = [
    (payload) => payload.authorities[KEY_PURPOSES.ENTITLEMENT].current,
    (payload) => payload.authorities[KEY_PURPOSES.ENTITLEMENT].next,
    (payload) => payload.authorities[KEY_PURPOSES.ENTITLEMENT].verifyOnly[0],
  ];
  for (const select of selectors) {
    const identity = select(base).identity;
    const wrongFingerprint = identity === 'f'.repeat(64) ? 'e'.repeat(64) : 'f'.repeat(64);
    for (const keyId of [
      'rw-entitlement-current',
      `rw-entitlement-${identity.slice(0, 32)}`,
      `rw-entitlement-${wrongFingerprint}`,
    ]) {
      const candidate = clone(base);
      select(candidate).keyId = keyId;
      assert.throws(() => signAuthorityManifest(
        candidate,
        run.material[KEY_PURPOSES.OWNER_ATTESTATION].a.keyId,
        run.material[KEY_PURPOSES.OWNER_ATTESTATION].a.privateKey,
      ), { code: 'authority_manifest_invalid' });
    }
  }
});

test('retired entitlement records retain the exact full fingerprint key ID', () => {
  const run = harness();
  const first = artifactFor(run, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  run.service.install(first);
  const base = payloadFor(run, 2, 'b', 'c', [], digest(first));
  const retired = base.retiredIdentities.find(
    (record) => record.purpose === KEY_PURPOSES.ENTITLEMENT,
  );
  assert.ok(retired);
  const wrongFingerprint = retired.identity === 'f'.repeat(64) ? 'e'.repeat(64) : 'f'.repeat(64);
  for (const keyId of [
    'rw-entitlement-retired',
    `rw-entitlement-${retired.identity.slice(0, 32)}`,
    `rw-entitlement-${wrongFingerprint}`,
  ]) {
    const candidate = clone(base);
    candidate.retiredIdentities.find(
      (record) => record.purpose === KEY_PURPOSES.ENTITLEMENT,
    ).keyId = keyId;
    assert.throws(() => signAuthorityManifest(
      candidate,
      run.material[KEY_PURPOSES.OWNER_ATTESTATION].b.keyId,
      run.material[KEY_PURPOSES.OWNER_ATTESTATION].b.privateKey,
    ), { code: 'authority_manifest_invalid' });
  }
});

test('manifest external anchor rejects a complete valid primary rewind and signature tamper', () => {
  const run = harness();
  const first = artifactFor(run, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  run.service.install(first);
  const oldPrimary = run.storage.snapshot();
  const second = artifactFor(run, 2, 'b', 'c', [], digest(first), 'b');
  run.service.install(second);
  run.storage.restore(oldPrimary);
  assert.throws(() => run.service.read(), { code: 'authority_manifest_anchor_mismatch' });

  const clean = harness();
  const forged = artifactFor(clean, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  forged.signature = flip(forged.signature);
  assert.throws(() => clean.service.install(forged), {
    code: 'authority_manifest_signature_invalid',
  });
});

test('manifest globally rejects cross-type fingerprints and generation skips', () => {
  const run = harness();
  const first = artifactFor(run, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  run.service.install(first);
  const skipped = artifactFor(run, 3, 'b', 'c', [], digest(first), 'b');
  assert.throws(() => run.service.install(skipped), {
    code: 'authority_manifest_generation_invalid',
  });

  const collision = payloadFor(run, 2, 'b', 'c', [], digest(first));
  collision.authorities[KEY_PURPOSES.PLATFORM_AUDIT].current.identity =
    collision.authorities[KEY_PURPOSES.CATALOG_GLOBAL].current.identity;
  assert.throws(() => signAuthorityManifest(
    collision,
    run.material[KEY_PURPOSES.OWNER_ATTESTATION].b.keyId,
    run.material[KEY_PURPOSES.OWNER_ATTESTATION].b.privateKey,
  ), { code: 'authority_manifest_identity_reused' });

  const forgedGenesisHistory = payloadFor(run, 1, 'a', 'b', [], ZERO_DIGEST);
  const definition = AUTHORITY_DEFINITIONS[KEY_PURPOSES.PLATFORM_AUDIT];
  forgedGenesisHistory.retiredIdentities = [{
    purpose: KEY_PURPOSES.PLATFORM_AUDIT,
    identityType: definition.identityType,
    keyId: `${definition.keyPrefix}forged-retired`,
    identity: 'f'.repeat(64),
    retiredAtGeneration: 2,
  }];
  assert.throws(() => signAuthorityManifest(
    forgedGenesisHistory,
    run.material[KEY_PURPOSES.OWNER_ATTESTATION].a.keyId,
    run.material[KEY_PURPOSES.OWNER_ATTESTATION].a.privateKey,
  ), { code: 'authority_manifest_invalid' });
});

test('manifest cannot demote a former current key into next for later re-promotion', () => {
  const run = harness();
  const first = artifactFor(run, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  run.service.install(first);
  const reversed = artifactFor(run, 2, 'b', 'a', [], digest(first), 'b');
  assert.throws(() => run.service.install(reversed), {
    code: 'authority_manifest_rotation_invalid',
  });
});

test('retired identities cannot be dropped then re-added as next across three generations', () => {
  const run = harness();
  const first = artifactFor(run, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  run.service.install(first);
  const second = artifactFor(run, 2, 'b', 'c', [], digest(first), 'b');
  run.service.install(second);
  assert.throws(() => artifactFor(run, 3, 'c', 'a', [], digest(second), 'c'), {
    code: 'authority_manifest_retired_identity_reused',
  });
});

test('manifest identities cannot move between authority purposes before retirement', () => {
  const run = harness();
  const first = artifactFor(run, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  run.service.install(first);
  const moved = payloadFor(run, 2, 'b', 'c', [], digest(first));
  const recoveryA = run.material[KEY_PURPOSES.RECOVERY].a.identity;
  moved.authorities[KEY_PURPOSES.PLATFORM_AUDIT].next.identity = recoveryA;
  moved.retiredIdentities = moved.retiredIdentities.filter(
    (record) => record.identity !== recoveryA,
  );
  const signer = run.material[KEY_PURPOSES.OWNER_ATTESTATION].b;
  const artifact = signAuthorityManifest(moved, signer.keyId, signer.privateKey);
  assert.throws(() => run.service.install(artifact), {
    code: 'authority_manifest_identity_changed',
  });
});

test('manifest retirement shares the serializable storage transaction with live references', () => {
  const run = harness();
  const first = artifactFor(run, 1, 'a', 'b', [], ZERO_DIGEST, 'a');
  run.service.install(first);
  const retiring = artifactFor(run, 2, 'b', 'c', [], digest(first), 'b');
  const retiredKey = run.material[KEY_PURPOSES.CATALOG_GLOBAL].a.keyId;
  run.storage.beforeManifestCas = () => run.storage.setReferenceCount(retiredKey, 1);
  assert.throws(() => run.service.install(retiring), /serialization conflict/);
  const noAbortAuthority = Object.freeze({
    ...run.anchorAuthority,
    abort: (request) => run.anchorAuthority.read(request.namespace),
  });
  const noAbortService = createVersionedAuthorityManifest({
    storage: run.storage,
    anchorAuthority: noAbortAuthority,
    allowTestWitness: true,
    genesisPublicKeys: {
      [run.material[KEY_PURPOSES.OWNER_ATTESTATION].a.keyId]:
        run.material[KEY_PURPOSES.OWNER_ATTESTATION].a.publicKey,
    },
  });
  assert.throws(() => noAbortService.reconcile(), {
    code: 'authority_manifest_anchor_abort_failed',
  });
  assert.deepEqual(run.service.reconcile(), { action: 'rolled_back' });
  assert.throws(() => run.service.install(retiring), {
    code: 'authority_manifest_key_still_referenced',
  });
  assert.equal(run.service.read().generation, 1);
});

function artifactFor(run, generation, currentLabel, nextLabel, verifyLabels,
  previousManifestDigest, signerLabel) {
  const payload = payloadFor(
    run, generation, currentLabel, nextLabel, verifyLabels, previousManifestDigest,
  );
  const signer = run.material[KEY_PURPOSES.OWNER_ATTESTATION][signerLabel];
  return clone(signAuthorityManifest(payload, signer.keyId, signer.privateKey));
}

function payloadFor(run, generation, currentLabel, nextLabel, verifyLabels,
  previousManifestDigest) {
  const authorities = Object.fromEntries(Object.entries(AUTHORITY_DEFINITIONS).map(
    ([purpose, definition]) => [purpose, {
      purpose,
      identityType: definition.identityType,
      current: publicIdentity(run, purpose, currentLabel),
      next: nextLabel === null ? null : publicIdentity(run, purpose, nextLabel),
      verifyOnly: verifyLabels.map((label) => publicIdentity(run, purpose, label))
        .filter((record) => record.references > 0)
        .sort((left, right) => left.keyId.localeCompare(right.keyId)),
    }],
  ));
  return {
    schemaVersion: 1,
    generation,
    previousManifestDigest,
    issuedAt: ISSUED,
    authorities,
    retiredIdentities: retiredIdentitiesFor(run, generation, authorities),
  };
}

function retiredIdentitiesFor(run, generation, authorities) {
  if (generation === 1) return [];
  const previous = run.service.read().payload;
  const active = new Set(Object.values(authorities).flatMap((entry) => [
    entry.current, ...(entry.next ? [entry.next] : []), ...entry.verifyOnly,
  ]).flatMap((record) => [`key:${record.keyId}`, `identity:${record.identity}`]));
  const retired = previous.retiredIdentities.map(clone);
  const known = new Set(retired.flatMap((record) => [
    `key:${record.keyId}`, `identity:${record.identity}`,
  ]));
  for (const [purpose, entry] of Object.entries(previous.authorities)) {
    for (const record of [entry.current, ...(entry.next ? [entry.next] : []), ...entry.verifyOnly]) {
      if (active.has(`key:${record.keyId}`) || active.has(`identity:${record.identity}`)
          || known.has(`key:${record.keyId}`) || known.has(`identity:${record.identity}`)) continue;
      retired.push({
        purpose, identityType: entry.identityType, keyId: record.keyId,
        identity: record.identity, retiredAtGeneration: generation,
      });
      known.add(`key:${record.keyId}`);
      known.add(`identity:${record.identity}`);
    }
  }
  return retired.sort((left, right) => left.keyId.localeCompare(right.keyId)
    || left.identity.localeCompare(right.identity) || left.purpose.localeCompare(right.purpose));
}

function publicIdentity(run, purpose, label) {
  const value = run.material[purpose][label];
  const record = {
    keyId: value.keyId,
    identity: value.identity,
    references: run.referenceCounts[value.keyId] || 0,
  };
  if (value.publicKey) record.publicKeySpki = encodePublicKey(value.publicKey);
  return record;
}

function createMaterial() {
  return Object.fromEntries(Object.entries(AUTHORITY_DEFINITIONS).map(([purpose, definition]) => {
    const values = {};
    for (const label of ['a', 'b', 'c']) {
      if (definition.identityType === 'ed25519_public') {
        const keys = crypto.generateKeyPairSync('ed25519');
        const identity = keyFingerprint(keys.publicKey);
        const keyId = purpose === KEY_PURPOSES.ENTITLEMENT
          ? `${definition.keyPrefix}${identity}` : `${definition.keyPrefix}${label}`;
        values[label] = { keyId, ...keys, identity };
      } else {
        const keyId = `${definition.keyPrefix}${label}`;
        const material = crypto.createHash('sha256').update(`${purpose}:${label}`).digest();
        values[label] = {
          keyId,
          identity: crypto.createHash('sha256').update(material).digest('hex'),
        };
      }
    }
    return [purpose, values];
  }));
}

function signedGlobalArtifact(run, label) {
  const records = [{
    catalogId: 'historical-ai', registrableDomain: 'historical.ai', aliases: [],
    classification: 'generative_ai', riskTier: 'high', analystState: 'approved',
    evidenceClass: 'public_documentation', confidenceBps: 9500,
  }];
  const payload = {
    schemaVersion: 1,
    messageId: '2bb7ed2b-0df3-45f4-a16a-2dd4a789b760',
    kind: protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
    globalReleaseId: 'a27c8e12-cff7-4d12-b751-eaf75af909a7',
    globalVersion: 1,
    previousGlobalVersion: 0,
    rollbackOfGlobalVersion: null,
    issuedAt: ISSUED,
    recordsDigest: protocol.catalogRecordsDigest(records),
    records,
  };
  const signer = run.material[KEY_PURPOSES.CATALOG_GLOBAL][label];
  return {
    keyId: signer.keyId,
    payload,
    signature: crypto.sign(null, protocol.signingInput(payload, signer.keyId),
      signer.privateKey).toString('base64'),
  };
}

class MemoryManifestStorage {
  constructor(referenceCounts) {
    this.value = null;
    this.version = 0;
    this.referenceCounts = referenceCounts;
    this.beforeManifestCas = null;
  }

  transaction(callback) {
    const base = this.version;
    let working = clone(this.value);
    const references = clone(this.referenceCounts);
    const result = callback({
      readAuthorityManifest: () => clone(working),
      readAuthorityReferenceCounts: () => clone(references),
      compareAndSetAuthorityManifest: (expected, value) => {
        if ((working?.payload?.generation || 0) !== expected) return false;
        const hook = this.beforeManifestCas;
        this.beforeManifestCas = null;
        if (hook) hook();
        working = clone(value);
        return true;
      },
    });
    if (base !== this.version) throw new Error('serialization conflict');
    this.value = working;
    this.version += 1;
    return result;
  }

  snapshot() { return clone(this.value); }
  restore(value) { this.value = clone(value); this.version += 1; }
  setReferenceCount(keyId, count) {
    this.referenceCounts[keyId] = count;
    this.version += 1;
  }
}

function digest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function flip(value) {
  return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`;
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}
