'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  AUTHORITY_DEFINITIONS,
} = require('../server/vendor-signed-artifact');
const {
  CHANNEL_CREDENTIAL_PURPOSES,
  DIAGNOSTIC_KEY_ENVIRONMENT,
  PURPOSES,
  RESERVED_PURPOSES,
  createVendorDiagnosticKeyFactory,
} = require('../server/vendor-diagnostic-key-factory');
const {
  POSTGRES_ADAPTER_CONTRACT,
  createVendorDiagnosticPostgresStorage,
  createVendorDiagnosticRuntime,
} = require('../server/vendor-diagnostic-runtime');
const {
  createVendorDiagnosticSqliteStorage,
} = require('../server/vendor-diagnostic-sqlite');
const {
  ReferenceDiagnosticWitness,
} = require('./support/vendor-diagnostic-reference-adapter');
const {
  PRODUCTION_WITNESS_PROVIDER_CONTRACT,
  createProductionVendorDiagnosticWitnessFactory,
  isProductionVendorDiagnosticWitnessAuthority,
} = require('../server/vendor-diagnostic-witness-factory');

const NOW = Date.parse('2026-07-13T12:00:00.000Z');

function material(label) {
  return crypto.createHash('sha256').update(`vendor diagnostic test:${label}`).digest();
}

function encoded(label) { return material(label).toString('base64'); }
function fingerprint(label) { return crypto.createHash('sha256').update(material(label)).digest('hex'); }

test('production witness authority requires a compiled module-private provider', () => {
  const raw = {
    assurance: 'independent_monotonic_exact_cas_v1',
    read: () => null,
    compareAndSwap: () => null,
  };
  assert.equal(isProductionVendorDiagnosticWitnessAuthority(raw), false);
  assert.equal(PRODUCTION_WITNESS_PROVIDER_CONTRACT, 'vendor-diagnostic-witness-provider-v1');
  assert.throws(
    () => createProductionVendorDiagnosticWitnessFactory('test-independent-provider'),
    (error) => error.code === 'vendor_diagnostic_production_witness_not_implemented',
  );
});

function configuration(overrides = {}) {
  const keys = Object.fromEntries(PURPOSES.map((purpose) => [purpose, {
    current: {
      keyId: purpose === 'integrity'
        ? `rw-diagnostic-integrity-${fingerprint('integrity.current')}`
        : `${purpose.toLowerCase()}.current`,
      key: encoded(`${purpose}.current`),
    },
    verifyOnly: [],
  }]));
  const ownerAuthorityManifest = Object.fromEntries(RESERVED_PURPOSES.map((purpose) => [
    purpose, ownerRecord(purpose),
  ]));
  ownerAuthorityManifest.diagnostic_integrity = {
    keyId: keys.integrity.current.keyId,
    identity: fingerprint('integrity.current'),
  };
  return {
    keys,
    ownerAuthorityManifest,
    requiredVerifyHorizonMs: 60_000,
    now: () => NOW,
    ...overrides,
  };
}

function ownerRecord(purpose) {
  const identity = fingerprint(`owner.${purpose}`);
  const prefix = AUTHORITY_DEFINITIONS[purpose].keyPrefix;
  return {
    keyId: ['entitlement', 'online_verdict'].includes(purpose)
      ? `${prefix}${identity}` : `${prefix}test-current`,
    identity,
  };
}

test('key factory binds key IDs into MACs and exposes only actual material fingerprints', () => {
  const options = configuration();
  const factory = createVendorDiagnosticKeyFactory(options);
  const authority = factory.authority('audit');
  const domain = 'redactwall.vendor-diagnostic-test.v1';
  const message = 'checkpoint';
  const proof = authority.sign(domain, message);
  const expected = crypto.createHmac('sha256', material('audit.current'))
    .update(domain, 'utf8').update('\0')
    .update('audit.current', 'utf8').update('\0')
    .update(message, 'utf8').digest('base64');
  assert.equal(proof.mac, expected);
  assert.equal(authority.verify(domain, message, proof), true);
  assert.equal(authority.verify(domain, message, { ...proof, keyId: 'other.key' }), false);
  assert.equal(factory.fingerprints().audit, fingerprint('audit.current'));

  const serialized = JSON.stringify(factory.manifest());
  assert.doesNotMatch(serialized, new RegExp(encoded('audit.current').replace(/[+/=]/g, '\\$&')));
  assert.equal(factory.manifestDigest.length, 64);
  assert.equal(factory.manifest().ownerAuthorityManifest.recovery.identity.length, 64);
  assert.equal(factory.manifest().ownerAuthorityManifest.online_verdict.identity.length, 64);
  assert.equal(
    factory.manifest().ownerAuthorityManifest.license_registry_integrity.identity.length, 64,
  );
  assert.deepEqual(
    Object.keys(factory.manifest().channelCredentialFingerprints).sort(),
    [...CHANNEL_CREDENTIAL_PURPOSES].sort(),
  );
  assert.equal(
    factory.manifest().channelCredentialFingerprints.diagnostic_credential,
    factory.manifest().ownerAuthorityManifest.diagnostic_credential.identity,
  );
  assert.equal(
    factory.authority('integrity').keyId,
    factory.manifest().ownerAuthorityManifest.diagnostic_integrity.keyId,
  );
  assert.equal(factory.authority('integrity').keyId.length, 88);
  assert.equal(
    factory.authority('integrity').fingerprint,
    factory.manifest().ownerAuthorityManifest.diagnostic_integrity.identity,
  );
  assert.equal(DIAGNOSTIC_KEY_ENVIRONMENT.integrity, 'OWNER_DIAGNOSTIC_INTEGRITY_KEY');
  assert.equal(DIAGNOSTIC_KEY_ENVIRONMENT.diagnosticWitness, 'OWNER_DIAGNOSTIC_WITNESS_KEY');
  assert.equal(Object.keys(factory.manifest().ownerAuthorityManifest).length, 20);
});

test('factory requires the runtime integrity key to match the Owner diagnostic purpose exactly', () => {
  for (const field of ['keyId', 'identity']) {
    const mismatch = configuration();
    mismatch.ownerAuthorityManifest.diagnostic_integrity[field] = field === 'keyId'
      ? 'rw-diagnostic-integrity-mismatch' : fingerprint('diagnostic-integrity-mismatch');
    assert.throws(
      () => createVendorDiagnosticKeyFactory(mismatch),
      (error) => error.code === 'diagnostic_integrity_manifest_mismatch',
    );
  }

  const reusedByAnotherPurpose = configuration();
  reusedByAnotherPurpose.ownerAuthorityManifest.platform_audit.identity =
    reusedByAnotherPurpose.ownerAuthorityManifest.diagnostic_integrity.identity;
  assert.throws(
    () => createVendorDiagnosticKeyFactory(reusedByAnotherPurpose),
    (error) => error.code === 'key_cross_purpose_conflict',
  );
});

test('Owner manifest accepts canonical long key IDs and rejects aliases and overlong IDs', () => {
  const canonical = configuration();
  for (const purpose of ['entitlement', 'online_verdict']) {
    const record = canonical.ownerAuthorityManifest[purpose];
    record.keyId = `${AUTHORITY_DEFINITIONS[purpose].keyPrefix}${record.identity}`;
  }
  assert.equal(canonical.ownerAuthorityManifest.entitlement.keyId.length, 79);
  assert.equal(canonical.ownerAuthorityManifest.online_verdict.keyId.length, 82);
  assert.doesNotThrow(() => createVendorDiagnosticKeyFactory(canonical));

  for (const purpose of ['entitlement', 'online_verdict']) {
    const alias = configuration();
    alias.ownerAuthorityManifest[purpose].keyId =
      `${AUTHORITY_DEFINITIONS[purpose].keyPrefix}alias`;
    assert.throws(
      () => createVendorDiagnosticKeyFactory(alias),
      (error) => error.code === 'key_manifest_invalid',
    );

    const overlong = configuration();
    overlong.ownerAuthorityManifest[purpose].keyId = `r${'w'.repeat(95)}x`;
    assert.equal(overlong.ownerAuthorityManifest[purpose].keyId.length, 97);
    assert.throws(
      () => createVendorDiagnosticKeyFactory(overlong),
      (error) => error.code === 'key_manifest_invalid',
    );
  }
});

test('audit verification keys are retained for the full epoch and cannot use timed retirement', () => {
  let nowMs = NOW;
  const options = configuration({ now: () => nowMs });
  const oldKey = material('audit.old');
  options.keys.audit.verifyOnly.push({
    keyId: 'audit.old',
    key: oldKey.toString('base64'),
    verifyUntil: null,
  });
  const factory = createVendorDiagnosticKeyFactory(options);
  const domain = 'redactwall.vendor-diagnostic-audit.v1';
  const message = 'historic audit epoch';
  const proof = {
    keyId: 'audit.old',
    mac: crypto.createHmac('sha256', oldKey)
      .update(domain, 'utf8').update('\0')
      .update('audit.old', 'utf8').update('\0')
      .update(message, 'utf8').digest('base64'),
  };
  nowMs += 400 * 24 * 60 * 60 * 1000;
  assert.equal(factory.authority('audit').verify(domain, message, proof), true);
  const timed = configuration();
  timed.keys.audit.verifyOnly.push({
    keyId: 'audit.timed',
    key: encoded('audit.timed'),
    verifyUntil: new Date(NOW + 120_000).toISOString(),
  });
  assert.throws(
    () => createVendorDiagnosticKeyFactory(timed),
    (error) => error.code === 'audit_key_retirement_requires_epoch',
  );
});

test('verify-only keys survive the required horizon and then stop verifying', () => {
  let nowMs = NOW;
  const options = configuration({ now: () => nowMs });
  const oldKey = material('access.old');
  options.keys.access.verifyOnly.push({
    keyId: 'access.old',
    key: oldKey.toString('base64'),
    verifyUntil: new Date(NOW + 120_000).toISOString(),
  });
  const factory = createVendorDiagnosticKeyFactory(options);
  const domain = 'redactwall.vendor-diagnostic-capability.v1';
  const message = 'rotated capability';
  const proof = {
    keyId: 'access.old',
    mac: crypto.createHmac('sha256', oldKey)
      .update(domain, 'utf8').update('\0')
      .update('access.old', 'utf8').update('\0')
      .update(message, 'utf8').digest('base64'),
  };
  assert.equal(factory.authority('access').verify(domain, message, proof), true);
  nowMs = NOW + 120_001;
  assert.equal(factory.authority('access').verify(domain, message, proof), false);
});

test('factory rejects short rotation windows and every cross-purpose material collision', () => {
  const short = configuration();
  short.keys.cursor.verifyOnly.push({
    keyId: 'cursor.old',
    key: encoded('cursor.old'),
    verifyUntil: new Date(NOW + 59_999).toISOString(),
  });
  assert.throws(
    () => createVendorDiagnosticKeyFactory(short),
    (error) => error.code === 'key_retention_too_short',
  );

  const duplicate = configuration();
  duplicate.keys.audit.current.key = duplicate.keys.access.current.key;
  assert.throws(
    () => createVendorDiagnosticKeyFactory(duplicate),
    (error) => error.code === 'key_cross_purpose_conflict',
  );

  const reserved = configuration();
  reserved.ownerAuthorityManifest.platform_audit.identity = fingerprint('integrity.current');
  assert.throws(
    () => createVendorDiagnosticKeyFactory(reserved),
    (error) => error.code === 'key_cross_purpose_conflict',
  );
});

test('runtime rejects an undersized verification horizon and keeps Postgres fail-closed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vendor-diagnostic-runtime-'));
  const directory = path.join(root, 'private');
  try {
    const factory = createVendorDiagnosticKeyFactory(configuration());
    assert.throws(
      () => createVendorDiagnosticRuntime({
        directory,
        deletionIntentKeyRegistry: { verify: () => false },
        keyFactory: factory,
        witnessAuthority: new ReferenceDiagnosticWitness({
          assurance: 'independent_monotonic_exact_cas_v1',
        }),
        currentPrincipal: () => ({
          principalId: crypto.randomUUID(),
          principalType: 'vendor',
          sessionId: crypto.randomUUID(),
        }),
      }),
      (error) => error.code === 'VENDOR_DIAGNOSTIC_KEY_HORIZON_TOO_SHORT',
    );
    assert.equal(POSTGRES_ADAPTER_CONTRACT.contractVersion, 'vendor-diagnostic-serializable-v2');
    assert.equal(POSTGRES_ADAPTER_CONTRACT.requirements.length >= 10, true);
    assert.equal(fs.existsSync(directory), false);
    assert.throws(
      () => createVendorDiagnosticPostgresStorage(),
      (error) => error.code === 'VENDOR_DIAGNOSTIC_POSTGRES_NOT_IMPLEMENTED',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runtime constructs from the exact 20-purpose Owner manifest and refuses witness self-attestation', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vendor-diagnostic-runtime-happy-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory(configuration({
    requiredVerifyHorizonMs: 120 * 24 * 60 * 60 * 1000,
  }));
  const runtimeDependencies = {
    deletionIntentKeyRegistry: {
      manifestDigest: 'a'.repeat(64),
      verify: () => false,
    },
    keyFactory: factory,
    currentPrincipal: () => ({
      principalId: crypto.randomUUID(),
      principalType: 'vendor',
      sessionId: crypto.randomUUID(),
    }),
  };
  assert.throws(
    () => createVendorDiagnosticRuntime({
      ...runtimeDependencies,
      directory: path.join(root, 'test-witness-rejected'),
      witnessAuthority: new ReferenceDiagnosticWitness(),
    }),
    (error) => error.code === 'diagnostic_sqlite_witness_authority_invalid',
  );
  assert.throws(
    () => createVendorDiagnosticRuntime({
      ...runtimeDependencies,
      directory: path.join(root, 'spoofed-production-witness'),
      witnessAuthority: new ReferenceDiagnosticWitness({
        assurance: 'independent_monotonic_exact_cas_v1',
      }),
    }),
    (error) => error.code === 'diagnostic_sqlite_witness_authority_invalid',
  );
  const runtime = createVendorDiagnosticRuntime({
    ...runtimeDependencies,
    allowTestWitness: true,
    directory: path.join(root, 'private'),
    witnessAuthority: new ReferenceDiagnosticWitness(),
  });
  assert.equal(Object.keys(factory.manifest().ownerAuthorityManifest).length, 20);
  assert.equal(Object.keys(runtime.authorityFingerprints).length, 27);
  assert.deepEqual(
    Object.keys(runtime.authorityFingerprints).filter((key) => key.endsWith('_credential')).sort(),
    [
      'acknowledgement_credential', 'diagnostic_credential',
      'heartbeat_credential', 'shadow_candidate_credential',
    ],
  );
  assert.equal(Object.hasOwn(runtime.authorityFingerprints, 'sharedChannelCredentials'), false);
  assert.deepEqual(runtime.health(), {
    ready: true,
    productionReady: false,
    degradedCode: null,
  });
  runtime.storage.productionReady = true;
  const tamperHealth = runtime.health();
  assert.equal(tamperHealth.productionReady, false);
  assert.equal(Object.isFrozen(tamperHealth), true);
  await runtime.close();
});

test('runtime independently rejects a key factory whose mapped integrity identity drifts', () => {
  const factory = createVendorDiagnosticKeyFactory(configuration({
    requiredVerifyHorizonMs: 120 * 24 * 60 * 60 * 1000,
  }));
  const manifest = factory.manifest();
  const forgedFactory = {
    authority: factory.authority,
    fingerprints: factory.fingerprints,
    manifest: () => ({
      ...manifest,
      ownerAuthorityManifest: {
        ...manifest.ownerAuthorityManifest,
        diagnostic_integrity: {
          ...manifest.ownerAuthorityManifest.diagnostic_integrity,
          keyId: 'rw-diagnostic-integrity-drift',
        },
      },
    }),
    manifestDigest: factory.manifestDigest,
  };
  assert.throws(
    () => createVendorDiagnosticRuntime({
      directory: path.join(os.tmpdir(), `diagnostic-runtime-drift-${crypto.randomUUID()}`),
      deletionIntentKeyRegistry: { verify: () => false },
      keyFactory: forgedFactory,
      witnessAuthority: new ReferenceDiagnosticWitness(),
      currentPrincipal: () => ({
        principalId: crypto.randomUUID(),
        principalType: 'vendor',
        sessionId: crypto.randomUUID(),
      }),
    }),
    (error) => error.code === 'VENDOR_DIAGNOSTIC_INTEGRITY_MANIFEST_MISMATCH',
  );
});

test('reference diagnostic runtime and SQLite store refuse actual production despite spoofed inputs', () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    assert.throws(
      () => createVendorDiagnosticRuntime({ env: { NODE_ENV: 'test' } }),
      (error) => error.code === 'vendor_diagnostic_reference_runtime_forbidden',
    );
    assert.throws(
      () => createVendorDiagnosticSqliteStorage({
        env: { NODE_ENV: 'test' },
        directory: path.join(os.tmpdir(), `diagnostic-sqlite-production-${crypto.randomUUID()}`),
        witnessAuthority: {
          assurance: 'independent_monotonic_exact_cas_v1',
          read: () => null,
          compareAndSwap: () => null,
        },
      }),
      (error) => error.code === 'vendor_diagnostic_reference_runtime_forbidden',
    );
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});
