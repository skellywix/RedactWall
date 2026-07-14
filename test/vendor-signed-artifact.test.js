'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../server/vendor-control-protocol');
const {
  AUTHORITY_DEFINITIONS,
  KEY_PURPOSES,
  createAuthorityRegistry,
  keyFingerprint,
  normalizePublicKeys,
  verifySignedArtifact,
} = require('../server/vendor-signed-artifact');

const IDS = Object.freeze({
  schemaVersion: 1,
  messageId: '12e5ad65-7d8f-42c2-b7af-5e89b2836e19',
  customerId: 'cu-signature-1',
  deploymentId: 'dep_dddddddddddddddddddddddddddddddd',
});

function catalogRecord() {
  return {
    catalogId: 'example-ai', registrableDomain: 'example.ai', aliases: [],
    classification: 'generative_ai', riskTier: 'high', analystState: 'approved',
    evidenceClass: 'public_documentation', confidenceBps: 9500,
  };
}

function payloads() {
  const records = [catalogRecord()];
  return [
    {
      ...IDS,
      kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
      status: 'active', plan: 'standard', seats: 10, features: ['policy'],
      entitlementVersion: 1, previousVersion: 0,
      issuedAt: '2026-07-12T12:00:00.000Z', expiresAt: '2026-07-12T12:05:00.000Z',
      fallbackUntil: '2026-07-15T12:00:00.000Z', reasonCode: 'billing_active',
    },
    {
      schemaVersion: 1,
      messageId: 'fbc6de4f-7490-4b36-990c-ee995072c779',
      kind: protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
      authorityManifestGeneration: 1,
      authorityManifestKeySlot: 'current',
      globalReleaseId: 'fe7b3266-2b99-429f-9ef2-e9d3175dbd1c',
      globalVersion: 57, previousGlobalVersion: 56, rollbackOfGlobalVersion: null,
      issuedAt: '2026-07-12T12:00:00.000Z',
      recordsDigest: protocol.catalogRecordsDigest(records), records,
    },
    {
      ...IDS,
      kind: protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION,
      authorityManifestGeneration: 1,
      authorityManifestKeySlot: 'current',
      distributionSequence: 1, previousDistributionSequence: 0,
      globalReleaseId: 'fe7b3266-2b99-429f-9ef2-e9d3175dbd1c',
      globalVersion: 57, globalArtifactDigest: 'a'.repeat(64),
      recordsDigest: protocol.catalogRecordsDigest(records),
      rollout: { mode: 'required', cohortBps: 10_000 },
      issuedAt: '2026-07-12T12:00:00.000Z',
    },
    {
      ...IDS,
      kind: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
      policyVersion: 1, previousVersion: 0, rollbackOfVersion: null,
      bundleDigest: 'a'.repeat(64), mandatoryControlsDigest: 'b'.repeat(64),
      issuedAt: '2026-07-12T12:00:00.000Z', expiresAt: '2026-07-13T12:00:00.000Z',
      rollout: 'required',
    },
    {
      ...IDS,
      kind: protocol.CHANNEL_KINDS.AUDIT_REQUEST,
      requestId: '989b520d-23a3-48ea-af30-c601e809e5de', requestVersion: 1,
      requestType: 'integrity_status', purposeCode: 'customer_support',
      notBefore: '2026-07-12T12:00:00.000Z', expiresAt: '2026-07-12T13:00:00.000Z',
      maxRecords: 1, fields: ['integrity_status'],
    },
  ];
}

const PURPOSE_BY_KIND = Object.freeze({
  [protocol.CHANNEL_KINDS.ENTITLEMENT]: KEY_PURPOSES.ENTITLEMENT,
  [protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE]: KEY_PURPOSES.CATALOG_GLOBAL,
  [protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION]: KEY_PURPOSES.CATALOG_DISTRIBUTION,
  [protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE]: KEY_PURPOSES.POLICY,
  [protocol.CHANNEL_KINDS.AUDIT_REQUEST]: KEY_PURPOSES.AUDIT_REQUEST,
});

const KEY_ID_BY_KIND = Object.freeze({
  [protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE]: 'rw-catalog-global-current',
  [protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION]: 'rw-catalog-distribution-current',
  [protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE]: 'rw-policy-current',
  [protocol.CHANNEL_KINDS.AUDIT_REQUEST]: 'rw-audit-request-current',
});

function artifact(payload, keyId, privateKey, signingInput = protocol.signingInput(payload, keyId)) {
  return {
    keyId,
    payload,
    signature: crypto.sign(null, signingInput, privateKey).toString('base64'),
  };
}

test('each signed channel accepts only its exact purpose prefix and signature domain', () => {
  for (const payload of payloads()) {
    const keys = crypto.generateKeyPairSync('ed25519');
    const keyId = payload.kind === protocol.CHANNEL_KINDS.ENTITLEMENT
      ? `rw-entitlement-${keyFingerprint(keys.publicKey)}`
      : KEY_ID_BY_KIND[payload.kind];
    const signed = artifact(payload, keyId, keys.privateKey);
    const verified = verifySignedArtifact(signed, { [keyId]: keys.publicKey }, payload.kind, {
      purpose: PURPOSE_BY_KIND[payload.kind], strictPurpose: true,
    });
    assert.equal(verified.payloadDigest, protocol.payloadDigest(payload, payload.kind));
    assert.equal(verified.artifactDigest, crypto.createHash('sha256')
      .update(protocol.canonicalJson(signed), 'utf8').digest('hex'));
    const wrongKey = crypto.generateKeyPairSync('ed25519');
    const wrongSignature = artifact(payload, keyId, wrongKey.privateKey);
    assert.throws(
      () => verifySignedArtifact(wrongSignature, { [keyId]: keys.publicKey }, payload.kind, {
        purpose: PURPOSE_BY_KIND[payload.kind], strictPurpose: true,
      }),
      (error) => error.code === 'invalid_signature',
    );
    const badId = `rw-offline-license-${keyId.split('-').at(-1)}`;
    assert.throws(
      () => verifySignedArtifact({ ...signed, keyId: badId }, { [badId]: keys.publicKey },
        payload.kind, { purpose: PURPOSE_BY_KIND[payload.kind], strictPurpose: true }),
      (error) => error.code === 'vendor_key_purpose_mismatch',
    );
  }
});

test('artifact digest snapshots the exact verified envelope and rejects unstable inputs', () => {
  const payload = payloads()[0];
  const keys = crypto.generateKeyPairSync('ed25519');
  const keyId = `rw-entitlement-${keyFingerprint(keys.publicKey)}`;
  const signed = artifact(payload, keyId, keys.privateKey);
  const options = { purpose: KEY_PURPOSES.ENTITLEMENT, strictPurpose: true };
  const expectedDigest = crypto.createHash('sha256')
    .update(protocol.canonicalJson(signed), 'utf8').digest('hex');
  assert.equal(verifySignedArtifact(
    signed, { [keyId]: keys.publicKey }, payload.kind, options,
  ).artifactDigest, expectedDigest);

  let getterCalls = 0;
  const accessorEnvelope = { keyId, payload };
  Object.defineProperty(accessorEnvelope, 'signature', {
    enumerable: true,
    get() { getterCalls += 1; return signed.signature; },
  });
  assert.throws(() => verifySignedArtifact(
    accessorEnvelope, { [keyId]: keys.publicKey }, payload.kind, options,
  ), { code: 'invalid_schema' });
  assert.equal(getterCalls, 0);

  let proxyTraps = 0;
  const proxied = new Proxy(signed, {
    getOwnPropertyDescriptor(target, property) {
      proxyTraps += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  assert.throws(() => verifySignedArtifact(
    proxied, { [keyId]: keys.publicKey }, payload.kind, options,
  ), { code: 'invalid_schema' });
  assert.equal(proxyTraps, 0);
});

test('global release and deployment envelope cannot share a signing identity', () => {
  const keys = crypto.generateKeyPairSync('ed25519');
  const fingerprint = keyFingerprint(keys.publicKey);
  const manifest = completeManifest({
    [KEY_PURPOSES.CATALOG_GLOBAL]: {
      keyId: 'rw-catalog-global-current', identity: fingerprint,
    },
    [KEY_PURPOSES.CATALOG_DISTRIBUTION]: {
      keyId: 'rw-catalog-distribution-current', identity: fingerprint,
    },
  });
  assert.throws(() => createAuthorityRegistry(manifest), {
    code: 'vendor_key_identity_reused',
  });
});

test('complete authority registry covers exact purpose prefixes and typed identities', () => {
  assert.deepEqual(Object.keys(AUTHORITY_DEFINITIONS).sort(), Object.values(KEY_PURPOSES).sort());
  const manifest = completeManifest();
  const registry = createAuthorityRegistry(manifest);
  assert.equal(registry.get(KEY_PURPOSES.RECOVERY).identityType, 'hmac_secret');
  assert.equal(registry.get(KEY_PURPOSES.CATALOG_GLOBAL).identityType, 'ed25519_public');

  // Identity text and key IDs are globally unique even across cryptographic types.
  const sharedHex = 'f'.repeat(64);
  const typed = completeManifest({
    [KEY_PURPOSES.PLATFORM_AUDIT]: {
      keyId: 'rw-platform-audit-current', identity: sharedHex,
    },
    [KEY_PURPOSES.CATALOG_GLOBAL]: {
      keyId: 'rw-catalog-global-current', identity: sharedHex,
    },
  });
  assert.throws(() => createAuthorityRegistry(typed), {
    code: 'vendor_key_identity_reused',
  });
  const duplicateKeyId = completeManifest({
    [KEY_PURPOSES.PLATFORM_AUDIT]: {
      keyId: 'rw-platform-audit-current', identity: 'd'.repeat(64),
    },
    [KEY_PURPOSES.RECOVERY]: {
      keyId: 'rw-platform-audit-current', identity: 'e'.repeat(64),
    },
  });
  assert.throws(() => createAuthorityRegistry(duplicateKeyId), {
    code: 'vendor_authority_manifest_invalid',
  });
  const missing = { ...manifest };
  delete missing[KEY_PURPOSES.RECOVERY];
  assert.throws(() => createAuthorityRegistry(missing), {
    code: 'vendor_authority_manifest_invalid',
  });
});

test('authority registry binds a public key to the registered purpose and key ID', () => {
  const keys = crypto.generateKeyPairSync('ed25519');
  const manifest = completeManifest({
    [KEY_PURPOSES.CATALOG_GLOBAL]: {
      keyId: 'rw-catalog-global-current', identity: keyFingerprint(keys.publicKey),
    },
  });
  const registry = createAuthorityRegistry(manifest);
  assert.equal(normalizePublicKeys({ 'rw-catalog-global-current': keys.publicKey }, {
    purpose: KEY_PURPOSES.CATALOG_GLOBAL,
    authorityRegistry: registry,
  }).size, 1);
  assert.throws(() => normalizePublicKeys({ 'rw-catalog-global-next': keys.publicKey }, {
    purpose: KEY_PURPOSES.CATALOG_GLOBAL,
    authorityRegistry: registry,
  }), { code: 'vendor_authority_manifest_mismatch' });
});

test('entitlement authority registry requires the full public-key fingerprint as its key ID', () => {
  const keys = crypto.generateKeyPairSync('ed25519');
  const identity = keyFingerprint(keys.publicKey);
  const exact = completeManifest({
    [KEY_PURPOSES.ENTITLEMENT]: {
      keyId: `rw-entitlement-${identity}`,
      identity,
    },
  });
  assert.doesNotThrow(() => createAuthorityRegistry(exact));
  for (const keyId of [
    'rw-entitlement-current',
    `rw-entitlement-${identity.slice(0, 32)}`,
    `rw-entitlement-${'f'.repeat(64)}`,
  ]) {
    assert.throws(() => createAuthorityRegistry({
      ...exact,
      [KEY_PURPOSES.ENTITLEMENT]: { keyId, identity },
    }), { code: 'vendor_authority_manifest_invalid' });
  }
});

test('key identifiers, current/next bounds, and forbidden public roots are enforced', () => {
  const first = crypto.generateKeyPairSync('ed25519').publicKey;
  const second = crypto.generateKeyPairSync('ed25519').publicKey;
  const third = crypto.generateKeyPairSync('ed25519').publicKey;
  assert.equal(normalizePublicKeys({
    'rw-catalog-global-current': first,
    'rw-catalog-global-next': second,
  }, { purpose: KEY_PURPOSES.CATALOG_GLOBAL, strictPurpose: true }).size, 2);
  assert.throws(() => normalizePublicKeys({ 'rw-catalog-global-current': first }, {
    purpose: KEY_PURPOSES.CATALOG_GLOBAL,
    strictPurpose: true,
    forbiddenPublicKeyFingerprints: [keyFingerprint(first)],
  }), { code: 'vendor_key_identity_reused' });
  assert.throws(() => normalizePublicKeys({ first, second, third }), {
    code: 'vendor_keys_invalid',
  });
  assert.throws(() => normalizePublicKeys({ first, second: first }), {
    code: 'vendor_key_identity_reused',
  });
  const privateKeys = crypto.generateKeyPairSync('ed25519');
  const privatePem = privateKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => normalizePublicKeys({
    'rw-catalog-global-current': privatePem,
  }, {
    purpose: KEY_PURPOSES.CATALOG_GLOBAL,
    strictPurpose: true,
  }), { code: 'vendor_key_invalid' });
  assert.throws(() => normalizePublicKeys({
    'rw-catalog-global-current': { key: privateKeys.privateKey },
  }, {
    purpose: KEY_PURPOSES.CATALOG_GLOBAL,
    strictPurpose: true,
  }), { code: 'vendor_key_invalid' });
  assert.throws(() => keyFingerprint(privatePem), { code: 'vendor_key_invalid' });
  assert.throws(() => keyFingerprint(privateKeys.privateKey), {
    code: 'vendor_key_invalid',
  });
  assert.throws(() => keyFingerprint(crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  }).publicKey), { code: 'vendor_key_invalid' });
});

test('public-only key parsing snapshots stable forms and rejects dynamic private wrappers', async () => {
  const pair = crypto.generateKeyPairSync('ed25519');
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const publicDer = pair.publicKey.export({ type: 'spki', format: 'der' });
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateDer = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  const keyId = 'rw-catalog-global-current';
  const normalize = (value) => normalizePublicKeys({ [keyId]: value }, {
    purpose: KEY_PURPOSES.CATALOG_GLOBAL,
    strictPurpose: true,
  });
  assert.equal(normalize({ key: publicDer, format: 'der', type: 'spki' }).size, 1);
  for (const value of [
    privatePem,
    { key: privateDer, format: 'der', type: 'pkcs8' },
    pair.privateKey,
    { key: pair.privateKey },
  ]) assert.throws(() => normalize(value), { code: 'vendor_key_invalid' });

  let accessorReads = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'key', {
    enumerable: true,
    get() { accessorReads += 1; return privatePem; },
  });
  assert.throws(() => normalize(accessor), { code: 'vendor_key_invalid' });
  assert.equal(accessorReads, 0);

  let proxyReads = 0;
  const alternating = new Proxy({ key: publicPem }, {
    get(target, property, receiver) {
      if (property === 'key') {
        proxyReads += 1;
        return proxyReads === 1 ? publicPem : privatePem;
      }
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(() => normalize(alternating), { code: 'vendor_key_invalid' });
  assert.equal(proxyReads, 0);

  const disguisedPrivateKey = new Proxy(pair.privateKey, {
    get(target, property) {
      if (property === 'type') return 'public';
      if (property === 'asymmetricKeyType') return 'ed25519';
      if (property === 'export') return pair.publicKey.export.bind(pair.publicKey);
      return Reflect.get(target, property, target);
    },
  });
  assert.throws(() => normalize(disguisedPrivateKey), { code: 'vendor_key_invalid' });

  const cycle = {};
  cycle.key = cycle;
  assert.throws(() => normalize(cycle), { code: 'vendor_key_invalid' });

  const webKeys = await crypto.webcrypto.subtle.generateKey(
    { name: 'Ed25519' }, true, ['sign', 'verify'],
  );
  assert.throws(() => normalize(webKeys.privateKey), { code: 'vendor_key_invalid' });
  assert.throws(() => normalize({ key: webKeys.privateKey }), { code: 'vendor_key_invalid' });
});

function completeManifest(overrides = {}) {
  const output = {};
  let index = 1;
  for (const [purpose, definition] of Object.entries(AUTHORITY_DEFINITIONS)) {
    const identity = crypto.createHash('sha256').update(`${purpose}:${index}`).digest('hex');
    output[purpose] = {
      keyId: purpose === KEY_PURPOSES.ENTITLEMENT
        ? `${definition.keyPrefix}${identity}` : `${definition.keyPrefix}current`,
      identity,
    };
    index += 1;
  }
  return { ...output, ...overrides };
}
