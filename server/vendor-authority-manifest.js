'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const {
  INDEPENDENT_WITNESS_ASSURANCE,
  TEST_WITNESS_ASSURANCE,
} = require('./monotonic-anchor-authority');
const {
  AUTHORITY_DEFINITIONS,
  KEY_PURPOSES,
  keyFingerprint,
  parsePublicOnlyEd25519Key,
  validPurposeKeyBinding,
} = require('./vendor-signed-artifact');

const MANIFEST_VERSION = 1;
const MANIFEST_NAMESPACE = 'owner-authority-manifest';
const MANIFEST_WITNESS_PURPOSE = 'authority_manifest_witness';
const MANIFEST_SIGNATURE_DOMAIN = 'redactwall.owner-authority-manifest.v1';
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_VERIFY_ONLY_PER_PURPOSE = 16;
const MAX_RETIRED_IDENTITIES = 4096;
const ZERO_DIGEST = '0'.repeat(64);
const SHA256_RE = /^[a-f0-9]{64}$/;
const KEY_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,95}$/;
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function createVersionedAuthorityManifest(options = {}) {
  const config = checkedOptions(options);
  return Object.freeze({
    install: (artifact) => install(config, artifact),
    read: () => readInstalled(config),
    registry: () => registryFromPayload(readInstalled(config).payload),
    reconcile: () => reconcile(config),
  });
}

function createProductionVersionedAuthorityManifest() {
  // Managed storage and an independently retained witness are both required.
  throw manifestError('authority_manifest_production_adapter_unavailable');
}

function checkedOptions(options) {
  if (!plainObject(options) || !options.storage
      || typeof options.storage.transaction !== 'function') throw manifestError('storage_invalid');
  const anchor = options.anchorAuthority;
  const anchorDescriptor = checkedAnchor(
    anchor, MANIFEST_WITNESS_PURPOSE, options.allowTestWitness === true,
  );
  const genesisPublicKeys = publicKeyMap(options.genesisPublicKeys, true);
  return Object.freeze({
    storage: options.storage,
    anchor,
    anchorDescriptor,
    genesisPublicKeys,
    namespace: options.namespace || MANIFEST_NAMESPACE,
  });
}

function install(config, rawArtifact) {
  const outcome = runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    const previousRaw = tx.readAuthorityManifest();
    const previous = previousRaw ? checkedStoredArtifact(previousRaw, config) : null;
    const anchor = config.anchor.read(config.namespace);
    if (anchor.pending) throw manifestError('authority_manifest_reconciliation_required');
    const previousGeneration = previous?.payload.generation || 0;
    const previousDigest = previous ? artifactDigest(previous.artifact) : ZERO_DIGEST;
    if (anchor.revision !== previousGeneration || anchor.headDigest !== previousDigest) {
      throw manifestError('authority_manifest_anchor_mismatch');
    }
    const trusted = previous
      ? registryFromPayload(previous.payload).activePublicKeys(KEY_PURPOSES.OWNER_ATTESTATION)
      : config.genesisPublicKeys;
    const candidate = checkedArtifact(rawArtifact, trusted);
    assertWitnessDistinct(candidate.payload, config.anchorDescriptor);
    if (candidate.payload.generation !== previousGeneration + 1
        || candidate.payload.previousManifestDigest !== previousDigest) {
      throw manifestError('authority_manifest_generation_invalid');
    }
    const counts = checkedReferenceCounts(tx.readAuthorityReferenceCounts());
    validateReferences(candidate.payload, previous?.payload || null, counts);
    validateTransition(previous?.payload || null, candidate.payload);
    const targetDigest = artifactDigest(candidate.artifact);
    if (tx.compareAndSetAuthorityManifest(previousGeneration, clone(candidate.artifact)) !== true) {
      throw manifestError('authority_manifest_conflict');
    }
    const readback = tx.readAuthorityManifest();
    if (artifactDigest(readback) !== targetDigest) {
      throw manifestError('authority_manifest_readback_failed');
    }
    const transition = {
      namespace: config.namespace,
      expectedRevision: previousGeneration,
      expectedDigest: previousDigest,
      targetRevision: candidate.payload.generation,
      targetDigest,
      witnessDigest: targetDigest,
    };
    assertPrepared(config.anchor.prepare(transition), transition);
    return { transition, artifact: candidate.artifact, digest: targetDigest };
  });
  assertFinalized(config.anchor.finalize(outcome.transition), outcome.transition);
  return Object.freeze({
    generation: outcome.transition.targetRevision,
    manifestDigest: outcome.digest,
    artifact: clone(outcome.artifact),
  });
}

function readInstalled(config) {
  const primary = runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    const raw = tx.readAuthorityManifest();
    return raw ? checkedStoredArtifact(raw, config) : null;
  });
  const anchor = config.anchor.read(config.namespace);
  if (anchor.pending) throw manifestError('authority_manifest_reconciliation_required');
  if (!primary) {
    if (anchor.revision !== 0 || anchor.headDigest !== ZERO_DIGEST) {
      throw manifestError('authority_manifest_anchor_mismatch');
    }
    throw manifestError('authority_manifest_required');
  }
  const digest = artifactDigest(primary.artifact);
  if (anchor.revision !== primary.payload.generation || anchor.headDigest !== digest) {
    throw manifestError('authority_manifest_anchor_mismatch');
  }
  return Object.freeze({
    generation: primary.payload.generation,
    manifestDigest: digest,
    payload: clone(primary.payload),
    artifact: clone(primary.artifact),
  });
}

function reconcile(config) {
  const primary = runTransaction(config.storage, (tx) => {
    requireTransaction(tx);
    const raw = tx.readAuthorityManifest();
    if (!raw) return { generation: 0, digest: ZERO_DIGEST };
    const checked = checkedStoredArtifact(raw, config);
    return { generation: checked.payload.generation, digest: artifactDigest(checked.artifact) };
  });
  const anchor = config.anchor.read(config.namespace);
  if (!anchor.pending) {
    if (anchor.revision !== primary.generation || anchor.headDigest !== primary.digest) {
      throw manifestError('authority_manifest_anchor_mismatch');
    }
    return { action: 'none' };
  }
  const transition = transitionFromAnchor(config.namespace, anchor);
  const committed = primary.generation === transition.targetRevision
    && primary.digest === transition.targetDigest;
  const rolledBack = primary.generation === transition.expectedRevision
    && primary.digest === transition.expectedDigest;
  if (!committed && !rolledBack) {
    throw manifestError('authority_manifest_reconciliation_required');
  }
  if (committed) assertFinalized(config.anchor.finalize(transition), transition);
  else assertAborted(config.anchor.abort(transition), transition);
  return { action: committed ? 'finalized' : 'rolled_back' };
}

function checkedStoredArtifact(raw, config) {
  const snapshot = boundedSnapshot(raw);
  const payload = checkedPayload(snapshot.payload);
  const ownKeys = registryFromPayload(payload).verificationPublicKey(
    KEY_PURPOSES.OWNER_ATTESTATION, snapshot.keyId,
  );
  const trusted = payload.generation === 1 ? mergePublicKeys(config.genesisPublicKeys, ownKeys) : ownKeys;
  const checked = checkedArtifact(snapshot, trusted);
  assertWitnessDistinct(checked.payload, config.anchorDescriptor);
  return checked;
}

function checkedArtifact(raw, trustedKeys) {
  const artifact = boundedSnapshot(raw);
  if (!exactKeys(artifact, ['keyId', 'payload', 'signature'])
      || !KEY_ID_RE.test(String(artifact.keyId || ''))
      || !canonicalSignature(artifact.signature)) throw manifestError('authority_manifest_invalid');
  const payload = checkedPayload(artifact.payload);
  const key = trustedKeys.get(artifact.keyId);
  if (!key || !crypto.verify(null, signingInput(payload, artifact.keyId), key,
    Buffer.from(artifact.signature, 'base64'))) {
    throw manifestError('authority_manifest_signature_invalid');
  }
  const ownerRecords = recordsFor(payload, KEY_PURPOSES.OWNER_ATTESTATION);
  if (!ownerRecords.some((record) => record.keyId === artifact.keyId)) {
    throw manifestError('authority_manifest_signer_not_retained');
  }
  return { artifact, payload };
}

function checkedPayload(raw) {
  const payload = boundedSnapshot(raw);
  if (!exactKeys(payload, [
    'authorities', 'generation', 'issuedAt', 'previousManifestDigest',
    'retiredIdentities', 'schemaVersion',
  ]) || payload.schemaVersion !== MANIFEST_VERSION
      || !Number.isSafeInteger(payload.generation) || payload.generation < 1
      || !SHA256_RE.test(String(payload.previousManifestDigest || ''))
      || !canonicalTime(payload.issuedAt) || !plainObject(payload.authorities)
      || !Array.isArray(payload.retiredIdentities)
      || payload.retiredIdentities.length > MAX_RETIRED_IDENTITIES
      || Object.keys(payload.authorities).sort().join(',')
        !== Object.keys(AUTHORITY_DEFINITIONS).sort().join(',')) {
    throw manifestError('authority_manifest_invalid');
  }
  const identities = new Set();
  const keyIds = new Set();
  payload.retiredIdentities = payload.retiredIdentities.map(checkedRetiredIdentity);
  if (!sortedRetiredIdentities(payload.retiredIdentities)) {
    throw manifestError('authority_manifest_invalid');
  }
  if ((payload.generation === 1 && payload.retiredIdentities.length !== 0)
      || payload.retiredIdentities.some(
        (record) => record.retiredAtGeneration > payload.generation,
      )) {
    throw manifestError('authority_manifest_invalid');
  }
  const retiredIdentities = new Set(payload.retiredIdentities.map((item) => item.identity));
  const retiredKeyIds = new Set(payload.retiredIdentities.map((item) => item.keyId));
  if (retiredIdentities.size !== payload.retiredIdentities.length
      || retiredKeyIds.size !== payload.retiredIdentities.length) {
    throw manifestError('authority_manifest_invalid');
  }
  for (const [purpose, definition] of Object.entries(AUTHORITY_DEFINITIONS)) {
    const entry = payload.authorities[purpose];
    if (!plainObject(entry) || !exactKeys(entry, [
      'current', 'identityType', 'next', 'purpose', 'verifyOnly',
    ]) || entry.purpose !== purpose || entry.identityType !== definition.identityType
        || !Array.isArray(entry.verifyOnly)
        || entry.verifyOnly.length > MAX_VERIFY_ONLY_PER_PURPOSE) {
      throw manifestError('authority_manifest_invalid');
    }
    entry.current = checkedIdentity(entry.current, purpose, definition);
    entry.next = entry.next === null ? null : checkedIdentity(entry.next, purpose, definition);
    entry.verifyOnly = entry.verifyOnly.map((value) => checkedIdentity(value, purpose, definition));
    if (!sortedByKeyId(entry.verifyOnly)) throw manifestError('authority_manifest_invalid');
    for (const identity of [entry.current, ...(entry.next ? [entry.next] : []), ...entry.verifyOnly]) {
      if (retiredIdentities.has(identity.identity) || retiredKeyIds.has(identity.keyId)) {
        throw manifestError('authority_manifest_retired_identity_reused');
      }
      if (identities.has(identity.identity) || keyIds.has(identity.keyId)) {
        throw manifestError('authority_manifest_identity_reused');
      }
      identities.add(identity.identity);
      keyIds.add(identity.keyId);
    }
  }
  return payload;
}

function checkedRetiredIdentity(value) {
  const keys = ['identity', 'identityType', 'keyId', 'purpose', 'retiredAtGeneration'];
  if (!plainObject(value) || !exactKeys(value, keys)
      || !Object.hasOwn(AUTHORITY_DEFINITIONS, value.purpose)
      || value.identityType !== AUTHORITY_DEFINITIONS[value.purpose].identityType
      || !validPurposeKeyBinding(value.keyId, value.purpose, value.identity)
      || !SHA256_RE.test(String(value.identity || ''))
      || !Number.isSafeInteger(value.retiredAtGeneration)
      || value.retiredAtGeneration < 2) {
    throw manifestError('authority_manifest_invalid');
  }
  return value;
}

function checkedIdentity(value, purpose, definition) {
  const publicIdentity = definition.identityType === 'ed25519_public';
  const keys = publicIdentity
    ? ['identity', 'keyId', 'publicKeySpki', 'references']
    : ['identity', 'keyId', 'references'];
  if (!plainObject(value) || !exactKeys(value, keys)
      || !validPurposeKeyBinding(value.keyId, purpose, value.identity)
      || !SHA256_RE.test(String(value.identity || ''))
      || !Number.isSafeInteger(value.references) || value.references < 0) {
    throw manifestError('authority_manifest_invalid');
  }
  if (publicIdentity) {
    const key = publicEd25519(value.publicKeySpki);
    if (keyFingerprint(key) !== value.identity) throw manifestError('authority_manifest_invalid');
  }
  return value;
}

function validateReferences(candidate, previous, counts) {
  const candidateRecords = allRecords(candidate);
  const candidateIds = new Set(candidateRecords.map((record) => record.keyId));
  for (const record of candidateRecords) {
    if ((counts.get(record.keyId) || 0) !== record.references) {
      throw manifestError('authority_manifest_reference_count_mismatch');
    }
  }
  if (previous) {
    for (const record of allRecords(previous)) {
      if (!candidateIds.has(record.keyId) && (counts.get(record.keyId) || 0) !== 0) {
        throw manifestError('authority_manifest_key_still_referenced');
      }
    }
  }
  for (const [keyId, count] of counts) {
    if (count > 0 && !candidateIds.has(keyId)) {
      throw manifestError('authority_manifest_key_still_referenced');
    }
  }
}

function validateTransition(previous, candidate) {
  if (!previous) return;
  validateLifetimeIdentityBindings(previous, candidate);
  validateRetiredIdentities(previous, candidate);
  for (const purpose of Object.keys(AUTHORITY_DEFINITIONS)) {
    const before = entrySlots(previous.authorities[purpose]);
    const after = entrySlots(candidate.authorities[purpose]);
    const allowedCurrent = new Set([
      before.current.keyId,
      ...(before.next ? [before.next.keyId] : []),
    ]);
    if (!allowedCurrent.has(after.current.keyId)) {
      throw manifestError('authority_manifest_rotation_invalid');
    }
    const beforeById = new Map(allEntryRecords(before).map((record) => [record.keyId, record]));
    for (const [slot, record] of slotRecords(after)) {
      const known = beforeById.get(record.keyId);
      if (known && canonicalIdentity(known) !== canonicalIdentity(record)) {
        throw manifestError('authority_manifest_identity_changed');
      }
      if (!known && slot !== 'next') throw manifestError('authority_manifest_rotation_invalid');
      if (known && before.current.keyId === record.keyId
          && !['current', 'verifyOnly'].includes(slot)) {
        throw manifestError('authority_manifest_rotation_invalid');
      }
      if (known && before.verifyOnly.some((item) => item.keyId === record.keyId)
          && slot !== 'verifyOnly') throw manifestError('authority_manifest_rotation_invalid');
    }
  }
}

function validateLifetimeIdentityBindings(previous, candidate) {
  const priorByKeyId = new Map();
  const priorByIdentity = new Map();
  for (const purpose of Object.keys(AUTHORITY_DEFINITIONS)) {
    for (const record of recordsFor(previous, purpose)) {
      const binding = { purpose, keyId: record.keyId, identity: record.identity };
      priorByKeyId.set(record.keyId, binding);
      priorByIdentity.set(record.identity, binding);
    }
  }
  for (const purpose of Object.keys(AUTHORITY_DEFINITIONS)) {
    for (const record of recordsFor(candidate, purpose)) {
      const priorKey = priorByKeyId.get(record.keyId);
      const priorIdentity = priorByIdentity.get(record.identity);
      if ((priorKey && (priorKey.purpose !== purpose || priorKey.identity !== record.identity))
          || (priorIdentity
            && (priorIdentity.purpose !== purpose || priorIdentity.keyId !== record.keyId))) {
        throw manifestError('authority_manifest_identity_changed');
      }
    }
  }
}

function validateRetiredIdentities(previous, candidate) {
  const active = new Set(allRecords(candidate).flatMap((record) => [
    `key:${record.keyId}`, `identity:${record.identity}`,
  ]));
  const expected = previous.retiredIdentities.map(clone);
  const known = new Set(expected.flatMap((record) => [
    `key:${record.keyId}`, `identity:${record.identity}`,
  ]));
  for (const purpose of Object.keys(AUTHORITY_DEFINITIONS)) {
    for (const record of recordsFor(previous, purpose)) {
      if (active.has(`key:${record.keyId}`) || active.has(`identity:${record.identity}`)) continue;
      if (known.has(`key:${record.keyId}`) || known.has(`identity:${record.identity}`)) continue;
      expected.push({
        purpose,
        identityType: AUTHORITY_DEFINITIONS[purpose].identityType,
        keyId: record.keyId,
        identity: record.identity,
        retiredAtGeneration: candidate.generation,
      });
      known.add(`key:${record.keyId}`);
      known.add(`identity:${record.identity}`);
    }
  }
  expected.sort(compareRetiredIdentities);
  if (expected.length > MAX_RETIRED_IDENTITIES) {
    throw manifestError('authority_manifest_retired_identity_capacity');
  }
  if (protocol.canonicalJson(candidate.retiredIdentities) !== protocol.canonicalJson(expected)) {
    throw manifestError('authority_manifest_retired_identity_history_invalid');
  }
}

function registryFromPayload(payloadValue) {
  const payload = checkedPayload(payloadValue);
  return Object.freeze({
    generation: payload.generation,
    get(purpose) {
      return publicRecord(entryFor(payload, purpose).current, purpose, 'current');
    },
    list(purpose) {
      const entry = entryFor(payload, purpose);
      return [
        publicRecord(entry.current, purpose, 'current'),
        ...(entry.next ? [publicRecord(entry.next, purpose, 'next')] : []),
        ...entry.verifyOnly.map((record) => publicRecord(record, purpose, 'verifyOnly')),
      ];
    },
    activePublicKeys(purpose) {
      const output = new Map();
      for (const record of this.list(purpose).filter(
        (candidate) => candidate.slot === 'current' || candidate.slot === 'next',
      )) {
        if (!record.publicKeySpki) throw manifestError('authority_manifest_public_key_required');
        output.set(record.keyId, publicEd25519(record.publicKeySpki));
      }
      return output;
    },
    publicKeys(purpose) {
      return this.activePublicKeys(purpose);
    },
    verificationPublicKey(purpose, keyId) {
      const record = this.list(purpose).find((candidate) => candidate.keyId === keyId);
      if (!record || !record.publicKeySpki) {
        throw manifestError('authority_manifest_public_key_required');
      }
      return new Map([[record.keyId, publicEd25519(record.publicKeySpki)]]);
    },
    assertPublicKey(purpose, keyId, fingerprint) {
      const match = this.list(purpose).find((record) => record.keyId === keyId
        && ['current', 'next'].includes(record.slot)
        && record.identity === fingerprint && record.publicKeySpki);
      if (!match) throw manifestError('vendor_authority_manifest_mismatch');
    },
    assertHistoricalPublicKey(purpose, keyId, fingerprint) {
      const match = this.list(purpose).find((record) => record.keyId === keyId
        && record.identity === fingerprint && record.publicKeySpki);
      if (!match) throw manifestError('vendor_authority_manifest_mismatch');
    },
    retiredIdentities() {
      return clone(payload.retiredIdentities);
    },
  });
}

function entryFor(payload, purpose) {
  if (!Object.hasOwn(AUTHORITY_DEFINITIONS, purpose)) {
    throw manifestError('authority_manifest_purpose_invalid');
  }
  return payload.authorities[purpose];
}

function recordsFor(payload, purpose) {
  const entry = entryFor(payload, purpose);
  return [entry.current, ...(entry.next ? [entry.next] : []), ...entry.verifyOnly];
}

function allRecords(payload) {
  return Object.keys(AUTHORITY_DEFINITIONS).flatMap((purpose) => recordsFor(payload, purpose));
}

function entrySlots(entry) {
  return { current: entry.current, next: entry.next, verifyOnly: entry.verifyOnly };
}

function allEntryRecords(entry) {
  return [entry.current, ...(entry.next ? [entry.next] : []), ...entry.verifyOnly];
}

function slotRecords(entry) {
  return [
    ['current', entry.current],
    ...(entry.next ? [['next', entry.next]] : []),
    ...entry.verifyOnly.map((record) => ['verifyOnly', record]),
  ];
}

function publicRecord(record, purpose, slot) {
  return clone({ ...record, purpose, slot, identityType: AUTHORITY_DEFINITIONS[purpose].identityType });
}

function canonicalIdentity(record) {
  const value = { keyId: record.keyId, identity: record.identity };
  if (record.publicKeySpki) value.publicKeySpki = record.publicKeySpki;
  return protocol.canonicalJson(value);
}

function checkedReferenceCounts(value) {
  if (!plainObject(value)) throw manifestError('reference_count_provider_invalid');
  const output = new Map();
  for (const [keyId, count] of Object.entries(value)) {
    if (!KEY_ID_RE.test(keyId) || !Number.isSafeInteger(count) || count < 0) {
      throw manifestError('reference_count_provider_invalid');
    }
    output.set(keyId, count);
  }
  return output;
}

function checkedAnchor(value, expectedPurpose, allowTestWitness) {
  if (!value || ['abort', 'finalize', 'prepare', 'read', 'describe'].some(
    (method) => typeof value[method] !== 'function',
  )) throw manifestError('anchor_authority_invalid');
  const descriptor = value.describe();
  if (!plainObject(descriptor)
      || !exactKeys(descriptor, ['assurance', 'identity', 'keyId', 'purpose'])
      || descriptor.purpose !== expectedPurpose
      || ![INDEPENDENT_WITNESS_ASSURANCE, TEST_WITNESS_ASSURANCE].includes(
        descriptor.assurance,
      )
      || (descriptor.assurance === TEST_WITNESS_ASSURANCE && !allowTestWitness)
      || !KEY_ID_RE.test(String(descriptor.keyId || ''))
      || !descriptor.keyId.startsWith('rw-anchor-')
      || !SHA256_RE.test(String(descriptor.identity || ''))) {
    throw manifestError('anchor_authority_invalid');
  }
  return Object.freeze(clone(descriptor));
}

function assertWitnessDistinct(payload, descriptor) {
  if (allRecords(payload).some((record) => record.keyId === descriptor.keyId
      || record.identity === descriptor.identity)) {
    throw manifestError('authority_manifest_identity_reused');
  }
}

function publicKeyMap(value, requireOwnerPrefix) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw manifestError('genesis_public_keys_invalid');
  }
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  if (!entries.length || entries.length > 2) throw manifestError('genesis_public_keys_invalid');
  const output = new Map();
  const fingerprints = new Set();
  for (const [keyId, raw] of entries) {
    if (!KEY_ID_RE.test(keyId) || (requireOwnerPrefix && !keyId.startsWith('rw-owner-attestation-'))) {
      throw manifestError('genesis_public_keys_invalid');
    }
    const key = publicEd25519(raw);
    const fingerprint = keyFingerprint(key);
    if (fingerprints.has(fingerprint)) throw manifestError('authority_manifest_identity_reused');
    fingerprints.add(fingerprint);
    output.set(keyId, key);
  }
  return output;
}

function mergePublicKeys(left, right) {
  const output = new Map(left);
  for (const [keyId, key] of right) {
    const existing = output.get(keyId);
    if (existing && keyFingerprint(existing) !== keyFingerprint(key)) {
      throw manifestError('authority_manifest_identity_changed');
    }
    output.set(keyId, key);
  }
  return output;
}

function publicEd25519(value) {
  try {
    let input = value;
    if (typeof value === 'string') {
      const der = Buffer.from(value, 'base64');
      if (der.toString('base64') !== value) throw new Error('noncanonical');
      input = { key: der, format: 'der', type: 'spki' };
    }
    return parsePublicOnlyEd25519Key(input);
  } catch { throw manifestError('authority_manifest_invalid'); }
}

function encodePublicKey(key) {
  return publicEd25519(key).export({ type: 'spki', format: 'der' }).toString('base64');
}

function signingInput(payload, keyId) {
  return Buffer.from(`${MANIFEST_SIGNATURE_DOMAIN}\0${keyId}\0${protocol.canonicalJson(payload)}`, 'utf8');
}

function signAuthorityManifest(payloadValue, keyId, privateKeyValue) {
  const payload = checkedPayload(payloadValue);
  let privateKey;
  try { privateKey = privateKeyValue instanceof crypto.KeyObject
    ? privateKeyValue : crypto.createPrivateKey(privateKeyValue); }
  catch { throw manifestError('authority_manifest_signing_key_invalid'); }
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw manifestError('authority_manifest_signing_key_invalid');
  }
  return Object.freeze({
    keyId,
    payload: clone(payload),
    signature: crypto.sign(null, signingInput(payload, keyId), privateKey).toString('base64'),
  });
}

function transitionFromAnchor(namespace, anchor) {
  return {
    namespace,
    expectedRevision: anchor.pending.expectedRevision,
    expectedDigest: anchor.pending.expectedDigest,
    targetRevision: anchor.pending.targetRevision,
    targetDigest: anchor.pending.targetDigest,
    witnessDigest: anchor.pending.witnessDigest,
  };
}

function assertPrepared(value, transition) {
  if (!value?.pending || value.revision !== transition.expectedRevision
      || value.headDigest !== transition.expectedDigest
      || protocol.canonicalJson(transitionFromAnchor(transition.namespace, value))
        !== protocol.canonicalJson(transition)) {
    throw manifestError('authority_manifest_anchor_prepare_failed');
  }
}

function assertFinalized(value, transition) {
  if (!value || value.pending || value.revision !== transition.targetRevision
      || value.headDigest !== transition.targetDigest) {
    throw manifestError('authority_manifest_anchor_finalize_failed');
  }
}

function assertAborted(value, transition) {
  if (!value || value.pending || value.revision !== transition.expectedRevision
      || value.headDigest !== transition.expectedDigest) {
    throw manifestError('authority_manifest_anchor_abort_failed');
  }
}

function requireTransaction(tx) {
  if (!tx || typeof tx.readAuthorityManifest !== 'function'
      || typeof tx.compareAndSetAuthorityManifest !== 'function'
      || typeof tx.readAuthorityReferenceCounts !== 'function') {
    throw manifestError('storage_invalid');
  }
}

function runTransaction(storage, callback) {
  let calls = 0;
  let returned;
  const result = storage.transaction((tx) => {
    calls += 1;
    if (calls !== 1) throw manifestError('storage_invalid');
    returned = callback(tx);
    return returned;
  });
  if (calls !== 1 || result !== returned || (result && typeof result.then === 'function')) {
    throw manifestError('storage_invalid');
  }
  return result;
}

function boundedSnapshot(value) {
  try {
    const encoded = JSON.stringify(value);
    if (!encoded || Buffer.byteLength(encoded, 'utf8') > MAX_MANIFEST_BYTES) throw new Error('size');
    return JSON.parse(encoded);
  } catch { throw manifestError('authority_manifest_invalid'); }
}

function artifactDigest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function canonicalSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === 64 && decoded.toString('base64') === value;
}

function canonicalTime(value) {
  return typeof value === 'string' && ISO_MS_RE.test(value)
    && new Date(Date.parse(value)).toISOString() === value;
}

function exactKeys(value, keys) {
  return plainObject(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function sortedByKeyId(values) {
  return values.every((value, index) => index === 0
    || values[index - 1].keyId.localeCompare(value.keyId) < 0);
}

function compareRetiredIdentities(left, right) {
  return left.keyId.localeCompare(right.keyId)
    || left.identity.localeCompare(right.identity)
    || left.purpose.localeCompare(right.purpose);
}

function sortedRetiredIdentities(values) {
  return values.every((value, index) => index === 0
    || compareRetiredIdentities(values[index - 1], value) < 0);
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }

function manifestError(code) {
  const error = new Error('vendor authority manifest rejected');
  error.code = code;
  return error;
}

module.exports = {
  MANIFEST_NAMESPACE,
  MANIFEST_SIGNATURE_DOMAIN,
  MANIFEST_VERSION,
  MANIFEST_WITNESS_PURPOSE,
  MAX_VERIFY_ONLY_PER_PURPOSE,
  MAX_RETIRED_IDENTITIES,
  createVersionedAuthorityManifest,
  createReferenceVersionedAuthorityManifest: createVersionedAuthorityManifest,
  createProductionVersionedAuthorityManifest,
  encodePublicKey,
  signAuthorityManifest,
};
