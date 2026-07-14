'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const assert = require('node:assert/strict');

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
process.env.NODE_ENV = 'test';
test.after(() => {
  if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
});

const Database = require('better-sqlite3');
const protocol = require('../server/vendor-control-protocol');
const {
  INDEPENDENT_WITNESS_ASSURANCE,
  createProductionMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorStorage,
} = require('../server/monotonic-anchor-authority');
const {
  CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY,
  createShadowAiCatalogState,
  createProductionShadowAiCatalogState,
} = require('../server/shadow-ai-catalog-state');
const {
  createProductionVendorShadowAiIntelligence,
  createVendorShadowAiIntelligence,
} = require('../server/vendor-shadow-ai-intelligence');
const { keyFingerprint } = require('../server/vendor-signed-artifact');
const {
  assertProductionCustomerShadowAiStorage,
  openCustomerShadowAiSqliteStorage,
  openShadowAiAnchorSqliteStorage,
} = require('../server/customer-shadow-ai-storage');
const {
  openProductionVendorShadowAiStorage,
  openVendorShadowAiSqliteStorage,
} = require('../server/vendor-shadow-ai-sqlite');
const { openShadowAiStorage } = require('../server/shadow-ai-sqlite');

const NOW = Date.parse('2026-07-13T15:00:00.000Z');
const SCOPE = Object.freeze({
  customerId: 'customer_sqlite',
  deploymentId: 'dep_dddddddddddddddddddddddddddddddd',
});

function withProcessNodeEnv(value, callback) {
  const previous = process.env.NODE_ENV;
  if (value === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = value;
  try { return callback(); }
  finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
}

test('SQLite vendor and customer stores survive restart with retained reference witnesses through applied Shadow AI ACK', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-shadow-sqlite-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const paths = {
    vendor: path.join(root, 'vendor.sqlite'),
    customer: path.join(root, 'customer.sqlite'),
  };
  const anchorStorages = {
    vendor: createReferenceMonotonicAnchorStorage(),
    customer: createReferenceMonotonicAnchorStorage(),
  };
  const material = createMaterial();
  const authority = createAuthorityResolver();
  let runtime = openRuntime(paths, material, authority, anchorStorages);

  const global = await runtime.vendor.publishGlobalCatalog(
    publishCommand(authority, null),
  );
  const distribution = await runtime.vendor.createDistribution(
    distributionCommand(authority, global),
  );
  const delivered = await runtime.vendor.markDelivered(
    deliveryCommand(authority, distribution, 1),
  );
  assert.equal(delivered.stage, 'delivered');

  const applied = runtime.customer.applySignedRelease({
    globalArtifact: distribution.globalArtifact,
    distributionArtifact: distribution.distributionArtifact,
  });
  assert.equal(applied.action, 'apply');
  const firstAcknowledgementBytes = Buffer.from(
    protocol.canonicalJson(applied.acknowledgement), 'utf8',
  );
  assert.equal(applied.acknowledgement.targetDigest, distribution.payloadDigest);
  assert.notEqual(applied.acknowledgement.targetDigest, distribution.artifactDigest);
  const adopted = await runtime.vendor.recordCustomerAcknowledgement(
    acknowledgementCommand(authority, distribution, 2, applied.acknowledgement),
  );
  assert.equal(adopted.stage, 'applied');
  assert.equal(adopted.revision, 3);
  assert.deepEqual(runtime.customer.readiness(), { ready: true, reason: 'ready' });
  assert.deepEqual(await runtime.vendor.readiness(), {
    ready: true, reason: 'ready', productionReady: false,
  });
  closeRuntime(runtime);

  runtime = openRuntime(paths, material, authority, anchorStorages);
  assert.deepEqual(runtime.customer.readiness(), { ready: true, reason: 'ready' });
  assert.deepEqual(await runtime.vendor.readiness(), {
    ready: true, reason: 'ready', productionReady: false,
  });
  const status = await runtime.vendor.distributionStatus(
    statusCommand(authority, distribution),
  );
  assert.equal(status.adoption.stage, 'applied');
  assert.equal(status.adoption.acknowledgementCount, 1);
  const replayedAcknowledgement = runtime.customer.createAcknowledgement(
    expectation(applied.state),
  );
  assert.deepEqual(Buffer.from(protocol.canonicalJson(replayedAcknowledgement), 'utf8'),
    firstAcknowledgementBytes);
  closeRuntime(runtime);
});

test('SQLite storage detects state tamper and Postgres selection fails closed', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-shadow-tamper-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const databasePath = path.join(root, 'customer.sqlite');
  const storage = openCustomerShadowAiSqliteStorage({
    path: databasePath,
    ...SCOPE,
    storageIntegrityAuthority: storageKey('customer', 0x41),
  });
  storage.transaction((tx) => tx.writeLocalObservation({
    registrableDomain: 'sqlite.ai', revision: 1,
  }));
  storage.database.prepare(`
    UPDATE shadow_ai_json_state SET state_json = ? WHERE store_id = ?
  `).run('{}', `customer:${SCOPE.customerId}:${SCOPE.deploymentId}`);
  assert.deepEqual(storage.readiness(), {
    ready: false, reason: 'shadow_ai_sqlite_state_invalid', postgresSupported: false,
  });
  storage.close();

  for (const kind of ['customer', 'vendor', 'anchor']) {
    assert.throws(() => openShadowAiStorage({ driver: 'postgres', kind }), {
      code: 'shadow_ai_postgres_adapter_not_implemented',
    });
  }
});

test('customer SQLite handles are scope-bound and sibling deployments remain isolated', (t) => {
  const database = new Database(':memory:');
  const siblingScope = Object.freeze({
    customerId: SCOPE.customerId,
    deploymentId: 'dep_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  });
  const storageA = openCustomerShadowAiSqliteStorage({
    database,
    testOnlyExternalDatabase: true,
    ...SCOPE,
    storageIntegrityAuthority: storageKey('scope-customer', 0x71),
  });
  const storageB = openCustomerShadowAiSqliteStorage({
    database,
    testOnlyExternalDatabase: true,
    ...siblingScope,
    storageIntegrityAuthority: storageKey('scope-customer', 0x71),
  });
  const anchorStorage = createReferenceMonotonicAnchorStorage();
  t.after(() => {
    try { storageA.close(); } catch {}
    try { storageB.close(); } catch {}
    try { database.close(); } catch {}
  });
  const material = createMaterial();
  const anchorAuthority = createReferenceMonotonicAnchorAuthority({
    storage: anchorStorage,
    keyId: 'rw-anchor-scope-bound-customer',
    secret: Buffer.alloc(32, 0x73),
    purpose: 'customer_catalog_witness',
  });
  const optionsFor = (scope, storage) => ({
    ...customerCatalogOptions(material),
    ...scope,
    storage,
    anchorAuthority,
    allowTestWitness: true,
  });
  const catalogA = createShadowAiCatalogState(optionsFor(SCOPE, storageA));
  const catalogB = createShadowAiCatalogState(optionsFor(siblingScope, storageB));
  const observation = {
    registrableDomain: 'silo-a-only.ai',
    revision: 1,
    firstSeenDay: '2026-07-13',
    lastSeenDay: '2026-07-13',
    observationCountBucket: '1',
    sourceTypes: ['browser_destination'],
    localClassification: 'unknown',
    localOutcome: 'observed',
    updatedAt: '2026-07-13T15:00:00.000Z',
  };
  catalogA.putLocalObservation(observation);
  assert.deepEqual(catalogA.readLocalObservations(), [observation]);
  assert.deepEqual(catalogB.readLocalObservations(), []);
  assert.throws(() => createShadowAiCatalogState(optionsFor(siblingScope, storageA)), {
    code: 'shadow_ai_customer_storage_scope_mismatch',
  });
});

test('test-only external customer databases are never production-eligible stores', (t) => {
  const database = new Database(':memory:');
  const storage = openCustomerShadowAiSqliteStorage({
    database,
    testOnlyExternalDatabase: true,
    ...SCOPE,
    storageIntegrityAuthority: storageKey('external-customer', 0x74),
  });
  t.after(() => {
    try { storage.close(); } catch {}
    try { database.close(); } catch {}
  });
  assert.throws(() => assertProductionCustomerShadowAiStorage(storage), {
    code: 'shadow_ai_production_customer_storage_required',
  });
});

test('reference storage and witness are rejected at production boundaries', (t) => {
  const originalNodeEnv = process.env.NODE_ENV;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-shadow-boundary-'));
  let vendorStorage;
  let customerStorage;
  let anchorStorage;
  t.after(() => {
    try { vendorStorage?.close(); } catch {}
    try { customerStorage?.close(); } catch {}
    try { anchorStorage?.close(); } catch {}
    fs.rmSync(root, { recursive: true, force: true });
  });
  const material = createMaterial();
  vendorStorage = openVendorShadowAiSqliteStorage({
    path: path.join(root, 'vendor.sqlite'),
    storageIntegrityAuthority: storageKey('boundary-vendor', 0x61),
    authorityResolver: emptyAuthorityResolver(),
  });
  assert.equal(vendorStorage.assurance, 'test_reference_blob');
  assert.equal(vendorStorage.productionReady, false);
  assert.equal(vendorStorage.readiness().productionReady, false);
  assert.throws(() => openVendorShadowAiSqliteStorage({
    path: path.join(root, 'production-vendor.sqlite'),
    env: { NODE_ENV: 'production' },
    storageIntegrityAuthority: storageKey('boundary-vendor', 0x61),
    authorityResolver: emptyAuthorityResolver(),
  }), { code: 'shadow_ai_vendor_sqlite_reference_only' });
  assert.throws(() => createVendorShadowAiIntelligence({
    storage: vendorStorage, production: true,
  }), { code: 'production_constructor_required' });
  assert.throws(() => createVendorShadowAiIntelligence({
    storage: vendorStorage, env: { NODE_ENV: 'production' },
  }), { code: 'production_constructor_required' });

  const hostileDatabase = new Database(':memory:');
  t.after(() => {
    try { hostileDatabase.close(); } catch {}
  });
  withProcessNodeEnv('production', () => {
    assert.throws(() => openVendorShadowAiSqliteStorage({
      path: path.join(root, 'actual-production-vendor.sqlite'),
      storageIntegrityAuthority: storageKey('actual-production-vendor', 0x66),
      authorityResolver: emptyAuthorityResolver(),
    }), { code: 'shadow_ai_vendor_sqlite_reference_only' });
    assert.throws(() => openVendorShadowAiSqliteStorage({
      database: hostileDatabase,
      testOnlyExternalDatabase: true,
      env: { NODE_ENV: 'development' },
      production: false,
      storageIntegrityAuthority: storageKey('hostile-preopened-vendor', 0x65),
      authorityResolver: emptyAuthorityResolver(),
    }), { code: 'shadow_ai_vendor_sqlite_reference_only' });
    assert.throws(() => createVendorShadowAiIntelligence({
      storage: {
        ...vendorStorage,
        assurance: 'managed_postgres',
        productionReady: true,
      },
      anchorAuthority: {
        assurance: INDEPENDENT_WITNESS_ASSURANCE,
        productionReady: true,
      },
      env: { NODE_ENV: 'development' },
      production: false,
    }), { code: 'production_constructor_required' });
    assert.throws(() => createVendorShadowAiIntelligence({
      storage: vendorStorage,
    }), { code: 'production_constructor_required' });
  });
  assert.equal(hostileDatabase.prepare('SELECT 1 AS value').get().value, 1);
  assert.equal(vendorStorage.readiness().productionReady, false);
  assert.equal(process.env.NODE_ENV, originalNodeEnv);
  assert.throws(() => createProductionVendorShadowAiIntelligence({
    storage: { ...vendorStorage, productionReady: true, assurance: 'managed_postgres' },
  }), { code: 'shadow_ai_production_adapter_required' });
  assert.throws(() => openProductionVendorShadowAiStorage(), {
    code: 'shadow_ai_managed_postgres_adapter_unavailable',
  });
  assert.throws(() => createProductionMonotonicAnchorAuthority(), {
    code: 'production_anchor_adapter_unavailable',
  });

  customerStorage = openCustomerShadowAiSqliteStorage({
    path: path.join(root, 'customer.sqlite'), ...SCOPE,
    storageIntegrityAuthority: storageKey('boundary-customer', 0x62),
  });
  assert.strictEqual(assertProductionCustomerShadowAiStorage(customerStorage), customerStorage);
  anchorStorage = openShadowAiAnchorSqliteStorage({
    path: path.join(root, 'anchor.sqlite'),
    purpose: 'customer_catalog_witness',
    storageIntegrityAuthority: storageKey('boundary-anchor', 0x63),
  });
  assert.equal(anchorStorage.assurance, 'test_reference');
  assert.throws(() => createReferenceMonotonicAnchorAuthority({
    storage: anchorStorage,
    keyId: 'rw-anchor-boundary-witness', secret: Buffer.alloc(32, 0x64),
    purpose: 'customer_catalog_witness',
  }), { code: 'anchor_authority_invalid' });
  const referenceAnchor = createReferenceMonotonicAnchorAuthority({
    storage: createReferenceMonotonicAnchorStorage(),
    keyId: 'rw-anchor-boundary-witness', secret: Buffer.alloc(32, 0x64),
    purpose: 'customer_catalog_witness',
  });
  assert.throws(() => createShadowAiCatalogState({
    storage: customerStorage,
    anchorAuthority: referenceAnchor,
    ...customerCatalogOptions(material),
  }), { code: 'anchor_authority_invalid' });
  assert.throws(() => createProductionShadowAiCatalogState({
    storage: { ...customerStorage, productionReady: true },
    anchorAuthority: { ...referenceAnchor, assurance: INDEPENDENT_WITNESS_ASSURANCE },
    ...customerCatalogOptions(material),
  }), { code: 'shadow_ai_production_adapter_required' });
  assert.throws(() => createProductionShadowAiCatalogState({
    storage: customerStorage,
    anchorAuthority: referenceAnchor,
    ...customerCatalogOptions(material),
  }), { code: 'shadow_ai_production_adapter_required' });
});

test('customer Shadow AI package entry point exports no vendor authority', () => {
  const customerEntry = require('../server/customer-shadow-ai-sqlite');
  assert.deepEqual(Object.keys(customerEntry).sort(), [
    'CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY',
    'openCustomerShadowAiSqliteStorage',
    'openShadowAiAnchorSqliteStorage',
  ]);
  assert.strictEqual(customerEntry.CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY,
    CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY);
  for (const excluded of [
    'vendor-shadow-ai-intelligence', 'vendor-authority-manifest',
    'vendor signing private keys', 'vendor ledgers', 'vendor compaction authority',
  ]) {
    assert.equal(CUSTOMER_SHADOW_AI_PACKAGE_BOUNDARY.excludes.includes(excluded), true);
  }
  assert.equal('openVendorShadowAiSqliteStorage' in customerEntry, false);
  assert.equal('openShadowAiStorage' in customerEntry, false);
});

test('customer Shadow AI dependency closure contains no vendor persistence or signing authority', () => {
  const entryPath = path.resolve(__dirname, '../server/customer-shadow-ai-sqlite.js');
  const closure = localModuleClosure(entryPath);
  const basenames = new Set([...closure].map((file) => path.basename(file)));

  for (const required of [
    'customer-shadow-ai-sqlite.js',
    'customer-shadow-ai-storage.js',
    'shadow-ai-catalog-state.js',
    'shadow-ai-sqlite-core.js',
    'monotonic-anchor-authority.js',
  ]) {
    assert.equal(basenames.has(required), true, `missing customer dependency ${required}`);
  }
  for (const forbidden of [
    'shadow-ai-sqlite.js',
    'vendor-shadow-ai-sqlite.js',
    'vendor-shadow-ai-intelligence.js',
    'vendor-authority-manifest.js',
  ]) {
    assert.equal(basenames.has(forbidden), false, `vendor dependency leaked: ${forbidden}`);
  }

  for (const file of closure) {
    const source = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(source, /\bcrypto\.sign\s*\(/,
      `private signing call leaked through ${path.basename(file)}`);
    assert.doesNotMatch(source, /\b(?:createSign|generateKeyPairSync)\s*\(/,
      `signing authority leaked through ${path.basename(file)}`);
    assert.doesNotMatch(source,
      /\b(?:openVendorShadowAi|createVendorShadowAi|publishGlobalCatalog|reviewCandidate|createDistribution|insertObservation|insertReview|compareAndSetGlobalRelease)\b/,
      `vendor persistence or governance leaked through ${path.basename(file)}`);
  }
});

test('independent processes serialize customer and vendor CAS and recover an abandoned transaction', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-shadow-process-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const modulePath = path.resolve(__dirname, '../server/shadow-ai-sqlite.js');
  const customerPath = path.join(root, 'customer.sqlite');
  const vendorPath = path.join(root, 'vendor.sqlite');
  const customerResults = await runWorkers(modulePath, 'customer', customerPath, 4);
  assert.equal(customerResults.filter((value) => value.won).length, 1);
  const vendorResults = await runWorkers(modulePath, 'vendor', vendorPath, 4);
  assert.equal(vendorResults.filter((value) => value.won).length, 1);

  const customer = openCustomerShadowAiSqliteStorage({
    path: customerPath, ...SCOPE,
    storageIntegrityAuthority: storageKey('process-customer', 0x51),
  });
  const customerWinner = customer.transaction((tx) => tx.readCurrentCatalog());
  assert.equal(customerResults.find((value) => value.won).worker, customerWinner.worker);
  assert.deepEqual(customer.readiness(), {
    ready: true, reason: 'ready', postgresSupported: false,
  });
  customer.close();

  const vendor = openVendorShadowAiSqliteStorage({
    path: vendorPath,
    storageIntegrityAuthority: storageKey('process-vendor', 0x52),
    authorityResolver: emptyAuthorityResolver(),
  });
  const vendorWinner = await vendor.transaction((tx) => tx.readCurrentGlobalRelease());
  assert.equal(vendorResults.find((value) => value.won).worker, vendorWinner.worker);
  assert.deepEqual(vendor.readiness(), {
    ready: true, reason: 'ready', postgresSupported: false, productionReady: false,
  });
  vendor.close();

  const crashPath = path.join(root, 'crash.sqlite');
  const crashed = await runWorker(modulePath, 'crash', crashPath, 'crash-writer');
  assert.equal(crashed.code, 17);
  const recovered = openCustomerShadowAiSqliteStorage({
    path: crashPath, ...SCOPE,
    storageIntegrityAuthority: storageKey('process-customer', 0x51),
  });
  assert.equal(recovered.transaction((tx) => tx.readCurrentCatalog()), null);
  assert.deepEqual(recovered.readiness(), {
    ready: true, reason: 'ready', postgresSupported: false,
  });
  recovered.close();
});

function openRuntime(paths, material, authority, anchorStorages) {
  const vendorStorage = openVendorShadowAiSqliteStorage({
    path: paths.vendor,
    storageIntegrityAuthority: storageKey('vendor', 0x31),
    authorityResolver: authority,
  });
  const vendorAnchorStorage = anchorStorages.vendor;
  const vendorAnchor = createReferenceMonotonicAnchorAuthority({
    storage: vendorAnchorStorage,
    keyId: 'rw-anchor-owner-catalog-witness',
    secret: Buffer.alloc(32, 0x33),
    purpose: 'owner_catalog_witness',
  });
  const vendor = createVendorShadowAiIntelligence({
    storage: vendorStorage,
    anchorAuthority: vendorAnchor,
    allowTestWitness: true,
    clock: () => NOW,
    randomUUID: crypto.randomUUID,
    catalogIntegrityAuthority: { keyId: 'rw-catalog-integrity-sqlite',
      secret: Buffer.alloc(32, 0x34) },
    platformAuditAuthority: { keyId: 'rw-platform-audit-sqlite',
      secret: Buffer.alloc(32, 0x35) },
    commandIdempotencyAuthority: { keyId: 'rw-command-idempotency-sqlite',
      secret: Buffer.alloc(32, 0x36) },
    paginationCursorAuthority: { keyId: 'rw-pagination-cursor-sqlite',
      secret: Buffer.alloc(32, 0x37) },
    catalogKeyAuthority: () => ({
      global: {
        current: { keyId: 'rw-catalog-global-current', privateKey: material.global.privateKey },
        next: null,
        archivedPublicKeys: new Map([
          ['rw-catalog-global-current', material.global.publicKey],
        ]),
      },
      distribution: {
        current: { keyId: 'rw-catalog-distribution-current',
          privateKey: material.distribution.privateKey },
        next: null,
        archivedPublicKeys: new Map([
          ['rw-catalog-distribution-current', material.distribution.publicKey],
        ]),
      },
      forbiddenPublicKeyFingerprints: material.forbidden,
    }),
  });

  const customerStorage = openCustomerShadowAiSqliteStorage({
    path: paths.customer,
    ...SCOPE,
    storageIntegrityAuthority: storageKey('customer', 0x41),
  });
  const customerAnchorStorage = anchorStorages.customer;
  const customerAnchor = createReferenceMonotonicAnchorAuthority({
    storage: customerAnchorStorage,
    keyId: 'rw-anchor-customer-catalog-witness',
    secret: Buffer.alloc(32, 0x43),
    purpose: 'customer_catalog_witness',
  });
  const customer = createShadowAiCatalogState({
    storage: customerStorage,
    anchorAuthority: customerAnchor,
    allowTestWitness: true,
    ...SCOPE,
    globalPublicKeys: { 'rw-catalog-global-current': material.global.publicKey },
    distributionPublicKeys: {
      'rw-catalog-distribution-current': material.distribution.publicKey,
    },
    forbiddenPublicKeyFingerprints: Object.values(material.forbidden),
    stateIntegrityAuthority: {
      keyId: 'rw-catalog-state-integrity-sqlite', secret: Buffer.alloc(32, 0x44),
    },
    clock: () => NOW,
    randomUUID: crypto.randomUUID,
  });
  return { vendor, vendorStorage, vendorAnchorStorage, customer, customerStorage,
    customerAnchorStorage };
}

function closeRuntime(runtime) {
  runtime.vendorStorage.close();
  runtime.customerStorage.close();
}

function createMaterial() {
  const global = crypto.generateKeyPairSync('ed25519');
  const distribution = crypto.generateKeyPairSync('ed25519');
  const forbiddenKeys = Array.from({ length: 5 }, () => crypto.generateKeyPairSync('ed25519'));
  return {
    global,
    distribution,
    forbidden: {
      audit_request: keyFingerprint(forbiddenKeys[0].publicKey),
      entitlement: keyFingerprint(forbiddenKeys[1].publicKey),
      offline_license: keyFingerprint(forbiddenKeys[2].publicKey),
      online_verdict: keyFingerprint(forbiddenKeys[3].publicKey),
      policy: keyFingerprint(forbiddenKeys[4].publicKey),
    },
  };
}

function customerCatalogOptions(material) {
  return {
    ...SCOPE,
    globalPublicKeys: { 'rw-catalog-global-current': material.global.publicKey },
    distributionPublicKeys: {
      'rw-catalog-distribution-current': material.distribution.publicKey,
    },
    forbiddenPublicKeyFingerprints: Object.values(material.forbidden),
    stateIntegrityAuthority: {
      keyId: 'rw-catalog-state-integrity-boundary', secret: Buffer.alloc(32, 0x65),
    },
    clock: () => NOW,
    randomUUID: crypto.randomUUID,
  };
}

function createAuthorityResolver() {
  const authorizations = new Map();
  const confirmations = new Map();
  return {
    authorizations,
    confirmations,
    resolveAuthorization: (id) => authorizations.get(id),
    resolveConfirmation: (id) => confirmations.get(id),
    resolveConsent: () => null,
    resolveScopeConsent: () => null,
  };
}

function emptyAuthorityResolver() {
  return {
    resolveAuthorization: () => null,
    resolveConfirmation: () => null,
    resolveConsent: () => null,
    resolveScopeConsent: () => null,
  };
}

function localModuleClosure(entryPath) {
  const root = path.resolve(__dirname, '../server');
  const pending = [entryPath];
  const visited = new Set();
  while (pending.length > 0) {
    const file = path.resolve(pending.pop());
    if (visited.has(file)) continue;
    assert.equal(file.startsWith(root + path.sep), true, `dependency escaped server root: ${file}`);
    visited.add(file);
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(/require\(['"](\.[^'"]+)['"]\)/g)) {
      const candidate = path.resolve(path.dirname(file), match[1]);
      const resolved = fs.existsSync(candidate) ? candidate : `${candidate}.js`;
      assert.equal(fs.existsSync(resolved), true, `unresolved local dependency: ${match[1]}`);
      pending.push(resolved);
    }
  }
  return visited;
}

async function runWorkers(modulePath, kind, databasePath, count) {
  const results = await Promise.all(Array.from({ length: count }, (_, index) =>
    runWorker(modulePath, kind, databasePath, `worker-${index + 1}`)));
  for (const result of results) {
    assert.equal(result.code, 0, result.stderr);
  }
  return results.map((result) => JSON.parse(result.stdout.trim()));
}

function runWorker(modulePath, kind, databasePath, worker) {
  const source = String.raw`
    const api = require(process.argv[1]);
    const kind = process.argv[2];
    const databasePath = process.argv[3];
    const worker = process.argv[4];
    const scope = { customerId: 'customer_sqlite',
      deploymentId: ${JSON.stringify(SCOPE.deploymentId)} };
    const storageKey = (label, byte) => ({
      keyId: 'rw-shadow-storage-' + label,
      secret: Buffer.alloc(32, byte),
    });
    const emptyAuthority = {
      resolveAuthorization: () => null,
      resolveConfirmation: () => null,
      resolveConsent: () => null,
      resolveScopeConsent: () => null,
    };
    (async () => {
      if (kind === 'customer' || kind === 'crash') {
        const store = api.openCustomerShadowAiSqliteStorage({
          path: databasePath,
          ...scope,
          storageIntegrityAuthority: storageKey('process-customer', 0x51),
        });
        const won = store.transaction((tx) => {
          const accepted = tx.compareAndSetCurrentCatalog(0, { distributionSequence: 1, worker });
          if (kind === 'crash') process.exit(17);
          return accepted;
        });
        store.close();
        process.stdout.write(JSON.stringify({ won, worker }));
        return;
      }
      const store = api.openVendorShadowAiSqliteStorage({
        path: databasePath,
        storageIntegrityAuthority: storageKey('process-vendor', 0x52),
        authorityResolver: emptyAuthority,
      });
      const won = await store.transaction((tx) => tx.compareAndSetGlobalRelease(
        0, '00000000-0000-4000-8000-' + worker.padEnd(12, '0').slice(0, 12), 1,
        { payload: { globalVersion: 1 }, worker },
      ));
      store.close();
      process.stdout.write(JSON.stringify({ won, worker }));
    })().catch((error) => {
      process.stderr.write(String(error && (error.stack || error)));
      process.exitCode = 1;
    });
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', source, modulePath, kind, databasePath, worker], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function authorize(authority, purpose, role, scope = null) {
  const authEventId = crypto.randomUUID();
  authority.authorizations.set(authEventId, {
    schemaVersion: 1,
    authEventId,
    actorRole: role,
    customerId: scope?.customerId || null,
    deploymentId: scope?.deploymentId || null,
    authenticatedAt: new Date(NOW - 60_000).toISOString(),
    stepUpAt: ['global_publish', 'distribution_create', 'distribution_deliver'].includes(purpose)
      ? new Date(NOW - 30_000).toISOString() : null,
    expiresAt: new Date(NOW + 60 * 60_000).toISOString(),
    purposes: [purpose],
  });
  return authEventId;
}

function confirm(authority, authEventId, purpose, operationDigest) {
  const confirmationId = crypto.randomUUID();
  authority.confirmations.set(confirmationId, {
    schemaVersion: 1, confirmationId, authEventId, purpose, operationDigest,
    confirmedAt: new Date(NOW - 10_000).toISOString(),
    expiresAt: new Date(NOW + 290_000).toISOString(),
  });
  return confirmationId;
}

function publishCommand(authority, current) {
  const authEventId = authorize(authority, 'global_publish', 'vendor_owner');
  const partial = {
    expectedGlobalVersion: current?.globalVersion || 0,
    expectedGlobalReleaseId: current?.globalReleaseId || null,
    expectedGlobalArtifactDigest: current?.artifactDigest || null,
    expectedGlobalRecordsDigest: current?.recordsDigest || null,
    idempotencyKey: crypto.randomUUID(),
    keySlot: 'current',
  };
  return { authEventId, confirmationId: confirm(authority, authEventId,
    'global_publish', digest({ ...partial, operation: 'publish' })), ...partial };
}

function distributionCommand(authority, global) {
  const authEventId = authorize(authority, 'distribution_create', 'catalog_publisher');
  const partial = {
    ...SCOPE,
    expectedDistributionSequence: 0,
    globalReleaseId: global.globalReleaseId,
    globalVersion: global.globalVersion,
    globalArtifactDigest: global.artifactDigest,
    recordsDigest: global.recordsDigest,
    idempotencyKey: crypto.randomUUID(),
    keySlot: 'current',
    rollout: { mode: 'required', cohortBps: 10_000 },
  };
  return { authEventId, confirmationId: confirm(authority, authEventId,
    'distribution_create', digest(partial)), ...partial };
}

function deliveryCommand(authority, distribution, expectedRevision) {
  const authEventId = authorize(authority, 'distribution_deliver', 'catalog_publisher');
  const partial = adoptionIdentity(distribution, expectedRevision);
  return { authEventId, confirmationId: confirm(authority, authEventId,
    'distribution_deliver', digest({ ...partial, operation: 'mark_delivered' })), ...partial };
}

function acknowledgementCommand(authority, distribution, expectedRevision, acknowledgement) {
  return {
    authEventId: authorize(authority, 'customer_ack', 'customer_connector', SCOPE),
    ...adoptionIdentity(distribution, expectedRevision),
    acknowledgement,
  };
}

function statusCommand(authority, distribution) {
  const value = adoptionIdentity(distribution, 0);
  delete value.expectedRevision;
  return {
    authEventId: authorize(authority, 'distribution_status', 'vendor_owner'),
    ...value,
  };
}

function adoptionIdentity(distribution, expectedRevision) {
  return {
    ...SCOPE,
    distributionSequence: distribution.distributionSequence,
    expectedRevision,
    globalReleaseId: distribution.globalReleaseId,
    globalVersion: distribution.globalVersion,
    globalArtifactDigest: distribution.globalArtifactDigest,
    recordsDigest: distribution.recordsDigest,
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

function storageKey(label, byte) {
  return { keyId: `rw-shadow-storage-${label}`, secret: Buffer.alloc(32, byte) };
}

function digest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}
