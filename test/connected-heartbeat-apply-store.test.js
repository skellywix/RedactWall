'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const { Worker } = require('node:worker_threads');
const Database = require('better-sqlite3');
const { MIGRATIONS } = require('../server/storage/migrations');
const {
  installAuditTransactionProtocol,
  isAuditImmediateTransactionRunner,
} = require('../server/storage');
const protocol = require('../server/vendor-control-protocol');
const registryState = require('../server/connected-online-registry-state');
const onlineVerdict = require('../server/connected-online-verdict');
const { keyFingerprint } = require('../server/vendor-signed-artifact');
const {
  ACK_BACKLOG_BLOCK_THRESHOLD,
  ACK_ORDINARY_PENDING_LIMIT,
  ACK_PENDING_HARD_LIMIT,
  createConnectedEntitlementStore,
} = require('../server/connected-entitlement-store');
const { createConnectedOnlineRegistryStore } = require('../server/connected-online-registry-store');
const {
  createConnectedAcknowledgedAuthorityStore,
  MAX_DELETION_HISTORY_ROWS,
} = require('../server/connected-acknowledged-authority-store');
const {
  createConnectedHeartbeatApplyStore,
  createConnectedHeartbeatTransactionCoordinator,
  isConnectedHeartbeatTransactionCoordinator,
} = require('../server/connected-heartbeat-apply-store');
const { createConnectedLicenseRuntime } = require('../server/connected-license-runtime');
const { systemBootClock } = require('../server/system-boot-clock');

const CUSTOMER_ID = 'customer_composite';
const DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
const NOW = Date.parse('2026-07-12T12:01:00.000Z');
const REFERENCE_KEY = Buffer.alloc(32, 41);
const AUDIT_KEY = Buffer.alloc(32, 42);
const entitlementKeys = crypto.generateKeyPairSync('ed25519');
const verdictKeys = crypto.generateKeyPairSync('ed25519');
const offlineKeys = crypto.generateKeyPairSync('ed25519');
const ENTITLEMENT_KEY_ID = `rw-entitlement-${keyFingerprint(entitlementKeys.publicKey)}`;
const VERDICT_KEY_ID = onlineVerdict.keyIdForPublicKey(verdictKeys.publicKey);

function entitlement(overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: 'f9ff3f99-460b-4a95-b79e-b1e1b300cfb3',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status: 'active',
    plan: 'enterprise',
    seats: 25,
    features: ['policy'],
    entitlementVersion: 1,
    previousVersion: 0,
    issuedAt: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-12T12:05:00.000Z',
    fallbackUntil: '2026-07-15T12:00:00.000Z',
    reasonCode: 'billing_active',
    ...overrides,
  };
}

function signedEntitlement(value = entitlement(), key = entitlementKeys.privateKey) {
  return {
    keyId: ENTITLEMENT_KEY_ID,
    payload: value,
    signature: crypto.sign(
      null, protocol.signingInput(value, ENTITLEMENT_KEY_ID), key,
    ).toString('base64'),
  };
}

function signedOfflineFallback(overrides = {}) {
  const payload = {
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    status: 'active',
    plan: 'enterprise',
    seats: 500,
    features: ['policy', 'shadow_ai'],
    expires: '2026-07-20T00:00:00.000Z',
    graceDays: 0,
    ...overrides,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return `${encoded}.${crypto.sign(null, Buffer.from(encoded), offlineKeys.privateKey).toString('base64')}`;
}

function verdict(overrides = {}) {
  const value = {
    kind: registryState.VERDICT_DOMAIN,
    keyId: VERDICT_KEY_ID,
    status: 'active',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    issuedAt: '2026-07-12T12:01:00.000Z',
    registryGeneration: 9,
    registryStateDigest: '9'.repeat(64),
    ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
  const signature = crypto.sign(
    null,
    Buffer.from(`${registryState.VERDICT_DOMAIN}\0${payload}`, 'utf8'),
    verdictKeys.privateKey,
  ).toString('base64');
  return `${payload}.${signature}`;
}

function opaqueReference(prefix, value) {
  return `${prefix}${crypto.createHmac('sha256', REFERENCE_KEY)
    .update(value, 'utf8').digest('base64url').slice(0, 32)}`;
}

function auditMac(value) {
  return crypto.createHmac('sha256', AUDIT_KEY)
    .update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function harness(compositeReceivers = null, databasePath = ':memory:') {
  const db = new Database(databasePath);
  db.pragma('foreign_keys = ON');
  const initialized = Boolean(db.prepare(`SELECT 1 AS present FROM main.sqlite_schema
    WHERE type = 'table' AND name = 'audit'`).get());
  if (!initialized) {
    db.exec('CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, entry TEXT NOT NULL)');
    for (const version of [11, 12, 13, 14, 15]) {
      db.exec(MIGRATIONS.find((migration) => migration.version === version).sqlite);
    }
  }
  let auditFailure = null;
  const appendAudit = (event) => {
    if (auditFailure?.action === event.action) throw new Error(auditFailure.message);
    const body = {
      action: event.action,
      actor: event.actor,
      detail: event.detail,
      ...(event.connectedAuthorityRef
        ? { connectedAuthorityRef: event.connectedAuthorityRef } : {}),
      ...(event.connectedAckRef ? { connectedAckRef: event.connectedAckRef } : {}),
    };
    const entry = { ...body, mac: auditMac(body) };
    db.prepare('INSERT INTO audit (action, entry) VALUES (?, ?)')
      .run(event.action, JSON.stringify(entry));
    return entry;
  };
  const verifyAuditEntry = (entry) => {
    if (!entry || typeof entry !== 'object') return false;
    const { mac, ...body } = entry;
    return mac === auditMac(body);
  };
  let auditHealthy = true;
  const verifyAuditState = () => ({ ok: auditHealthy });
  const createStore = () => {
    const coordinator = createConnectedHeartbeatTransactionCoordinator();
    const entitlementStore = createConnectedEntitlementStore({
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      driver: db,
      appendAudit,
      authorityReference: (customerId, deploymentId) => opaqueReference(
        'connected_', `${customerId}\0${deploymentId}`,
      ),
      ackReference: (id) => opaqueReference('connected_ack_', id),
      verifyAuditState,
      verifyAuditEntry,
      verificationKeys: () => ({
        publicKeys: { [ENTITLEMENT_KEY_ID]: entitlementKeys.publicKey },
        offlineKeyFingerprint: keyFingerprint(offlineKeys.publicKey),
        forbiddenPublicKeyFingerprints: [onlineVerdict.keyFingerprint(verdictKeys.publicKey)],
      }),
      offlinePublicKey: () => offlineKeys.publicKey,
      compositeCoordinator: coordinator,
    });
    const registryStore = createConnectedOnlineRegistryStore({
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      driver: db,
      appendAudit,
      registryReference: (customerId, deploymentId) => opaqueReference(
        'connected_registry_', `${customerId}\0${deploymentId}`,
      ),
      verifyAuditState,
      verifyAuditEntry,
      verifyVerdict: (value) => onlineVerdict.verifySignedOnlineVerdict(
        value,
        new Map([[VERDICT_KEY_ID, verdictKeys.publicKey]]),
        { forbiddenPublicKeyFingerprints: [keyFingerprint(entitlementKeys.publicKey)] },
      ),
      compositeCoordinator: coordinator,
    });
    const acknowledgedAuthorityStore = createConnectedAcknowledgedAuthorityStore({
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      driver: db,
      entitlementStore,
      appendAudit,
      authorityReference: (customerId, deploymentId) => opaqueReference(
        'connected_ack_authority_', `${customerId}\0${deploymentId}`,
      ),
      ackReference: (id) => opaqueReference('connected_ack_', id),
      verifyAuditState,
      verifyAuditEntry,
      compositeCoordinator: coordinator,
    });
    return createConnectedHeartbeatApplyStore({
      driver: db,
      entitlementStore,
      registryStore,
      acknowledgedAuthorityStore,
      verifyAuditState: compositeReceivers
        ? function observedCompositeAudit() {
          compositeReceivers.push(this);
          return verifyAuditState();
        }
        : verifyAuditState,
      coordinator,
    });
  };
  return {
    db,
    createStore,
    store: createStore(),
    failAudit(action, message) { auditFailure = { action, message }; },
    restoreAudit() { auditFailure = null; },
    setAuditHealthy(value) { auditHealthy = value; },
  };
}

function apply(store, overrides = {}) {
  return store.applyHeartbeatResponse({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedOnlineRegistryVerdict: verdict(),
    signedEntitlementArtifact: signedEntitlement(),
    nowMs: NOW,
    randomUUID: () => entitlement().messageId,
    clock: { bootId: '1'.repeat(32), nowMs: 5000 },
    ...overrides,
  });
}

function ackInput(row, nowMs = NOW + 1) {
  return {
    id: row.id,
    customerId: row.customerId,
    deploymentId: row.deploymentId,
    payloadDigest: row.payloadDigest,
    accepted: true,
    nowMs,
  };
}

function applyVersion(store, version, options = {}) {
  const messageId = versionMessageId(version);
  const nowMs = NOW + version * 1000;
  const issuedAt = new Date(nowMs).toISOString();
  const payload = entitlement({
    messageId,
    entitlementVersion: version,
    previousVersion: version - 1,
    issuedAt,
    expiresAt: new Date(nowMs + 4 * 60 * 1000).toISOString(),
    fallbackUntil: new Date(nowMs + 72 * 60 * 60 * 1000).toISOString(),
    plan: options.plan ?? 'enterprise',
    seats: options.seats ?? 25,
    features: options.features ?? ['policy'],
    status: options.status ?? 'active',
    reasonCode: options.reasonCode ?? 'billing_active',
    ...(options.status && options.status !== 'active' ? { fallbackUntil: null } : {}),
  });
  const registryGeneration = options.registryGeneration ?? version + 8;
  const registryStatus = options.registryStatus ?? 'active';
  return store.applyHeartbeatResponse({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedOnlineRegistryVerdict: verdict({
      issuedAt,
      registryGeneration,
      registryStateDigest: generationDigest(registryGeneration, registryStatus),
      status: registryStatus,
    }),
    signedEntitlementArtifact: signedEntitlement(payload),
    nowMs,
    randomUUID: () => messageId,
    clock: { bootId: '1'.repeat(32), nowMs: 5000 + version * 1000 },
  });
}

function applyRegistryOnly(store, generation, status = 'active', options = {}) {
  const nowMs = options.nowMs ?? NOW + (generation - 8) * 1000;
  const issuedAt = new Date(nowMs).toISOString();
  return store.applyHeartbeatResponse({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedOnlineRegistryVerdict: verdict({
      issuedAt,
      registryGeneration: generation,
      registryStateDigest: options.registryStateDigest
        ?? generationDigest(generation, status),
      status,
    }),
    signedEntitlementArtifact: signedEntitlement(options.entitlement ?? entitlement()),
    nowMs,
    randomUUID: () => entitlement().messageId,
    clock: { bootId: '1'.repeat(32), nowMs: 5000 + (generation - 8) * 1000 },
  });
}

function acknowledgePair(store, result, nowMs) {
  store.recordAckResult(ackInput(result.entitlement.outboxes.delivered, nowMs));
  return store.recordAckResult(ackInput(result.entitlement.outboxes.applied, nowMs + 1));
}

function realRuntime(store, now = NOW + 10_000) {
  return createConnectedLicenseRuntime({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    store,
    connector: {
      start() {},
      stop: async () => ({ ok: true }),
      synchronize: async () => ({ ok: true }),
      readiness: () => ({ ok: true, connected: true, mode: 'connected' }),
      sendDiagnostic: async () => ({ ok: true }),
      sendShadowCandidate: async () => ({ ok: true }),
    },
    now: () => now,
    offlineLicenseText: () => null,
    seatsUsed: () => 3,
    packageVersion: '1.0.0',
    policyVersion: () => 0,
    catalogVersion: () => 0,
  });
}

function versionMessageId(version) {
  return `00000000-0000-4000-8000-${version.toString(16).padStart(12, '0')}`;
}

function generationDigest(generation, status = 'active') {
  return crypto.createHash('sha256')
    .update(`${generation}\0${status}`, 'utf8').digest('hex');
}

function assertIntegrityFailure(callback, label) {
  assert.throws(callback, (error) => /integrity|anchored|audit/i.test(
    `${error?.code || ''} ${error?.message || ''}`,
  ), label);
}

function methodSet(overrides = {}) {
  const methods = [
    'applyEntitlement', 'assertExactReplay', 'recordFailure', 'getState', 'disposition',
    'listPendingAcknowledgements', 'acknowledgementHealth', 'recordAckResult',
    'assertAcknowledgementLineages',
    'applyVerdict', 'registryGeneration',
    'stagePair', 'recordAcknowledgementResult', 'constrainDisposition',
  ];
  return Object.fromEntries(methods.map((name) => [name, overrides[name] || (() => null)]));
}

async function concurrentCombinedRead(method) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-combined-read-'));
  const databasePath = path.join(directory, 'state.db');
  const db = new Database(databasePath);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  db.exec(`
    CREATE TABLE entitlement_probe (status TEXT NOT NULL);
    CREATE TABLE registry_probe (status TEXT NOT NULL);
    INSERT INTO entitlement_probe VALUES ('active');
    INSERT INTO registry_probe VALUES ('revoked');
  `);
  installAuditTransactionProtocol(db, {
    prepareTransactionCommit() {},
    transactionCommitted() {},
    transactionCommitUncertain() {},
  });
  assert.equal(isAuditImmediateTransactionRunner(db.transaction(() => null)), true);

  const signal = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
  const state = new Int32Array(signal);
  let writer = null;
  let committedDuringRead = null;
  const startWriter = () => {
    if (writer) return;
    writer = new Worker(`
      'use strict';
      const { workerData } = require('node:worker_threads');
      const Database = require('better-sqlite3');
      const state = new Int32Array(workerData.signal);
      const db = new Database(workerData.databasePath);
      db.pragma('busy_timeout = 5000');
      Atomics.store(state, 0, 1);
      Atomics.notify(state, 0);
      try {
        db.transaction(() => {
          db.prepare("UPDATE entitlement_probe SET status = 'paused'").run();
          db.prepare("UPDATE registry_probe SET status = 'active'").run();
        }).immediate();
        Atomics.store(state, 0, 2);
      } catch {
        Atomics.store(state, 0, 3);
      } finally {
        Atomics.notify(state, 0);
        db.close();
      }
    `, { eval: true, workerData: { databasePath, signal } });
    const started = Atomics.wait(state, 0, 0, 2000);
    assert.notEqual(started, 'timed-out', 'independent writer did not start');
    if (Atomics.load(state, 0) === 1) Atomics.wait(state, 0, 1, 300);
  };
  const entitlementStore = methodSet({
    getState() {
      const status = db.prepare('SELECT status FROM entitlement_probe').get().status;
      startWriter();
      return { status };
    },
    disposition() {
      const status = db.prepare('SELECT status FROM entitlement_probe').get().status;
      startWriter();
      return { protectedEgress: status === 'active' ? 'allow' : 'block', status };
    },
  });
  const registryStore = methodSet({
    getState() {
      committedDuringRead = Atomics.load(state, 0) === 2;
      return { status: db.prepare('SELECT status FROM registry_probe').get().status };
    },
    disposition(_customerId, _deploymentId, entitlementDisposition) {
      committedDuringRead = Atomics.load(state, 0) === 2;
      const status = db.prepare('SELECT status FROM registry_probe').get().status;
      return status === 'active'
        ? { ...entitlementDisposition, registryStatus: status }
        : { ...entitlementDisposition, protectedEgress: 'block', registryStatus: status };
    },
  });
  const store = createConnectedHeartbeatApplyStore({
    driver: db,
    entitlementStore,
    registryStore,
    acknowledgedAuthorityStore: methodSet({
      getState: () => null,
      constrainDisposition: (input) => input.currentDisposition,
    }),
    verifyAuditState: () => ({ ok: true }),
    coordinator: createConnectedHeartbeatTransactionCoordinator(),
  });

  try {
    const result = method === 'getState'
      ? store.getState(CUSTOMER_ID, DEPLOYMENT_ID)
      : store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW });
    assert.equal(committedDuringRead, false);
    if (method === 'getState') {
      assert.deepEqual(result, {
        entitlement: { status: 'active' }, registry: { status: 'revoked' },
        acknowledgedAuthority: null,
      });
    } else {
      assert.deepEqual(result, {
        protectedEgress: 'block', status: 'active', registryStatus: 'revoked',
      });
    }
    await new Promise((resolve, reject) => {
      writer.once('error', reject);
      writer.once('exit', (code) => (code === 0 ? resolve() : reject(new Error(`writer exited ${code}`))));
    });
    assert.equal(Atomics.load(state, 0), 2);
    assert.deepEqual({
      entitlement: db.prepare('SELECT status FROM entitlement_probe').get().status,
      registry: db.prepare('SELECT status FROM registry_probe').get().status,
    }, { entitlement: 'paused', registry: 'active' });
  } finally {
    if (writer) await writer.terminate();
    db.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('only the module-issued coordinator can suppress nested audit revalidation', () => {
  const fake = Object.freeze({
    isAuditVerified: () => true,
    runVerified: (_verify, callback) => callback(),
  });
  assert.equal(isConnectedHeartbeatTransactionCoordinator(fake), false);
  assert.equal(
    isConnectedHeartbeatTransactionCoordinator(
      createConnectedHeartbeatTransactionCoordinator(),
    ),
    true,
  );
  const methods = (names) => Object.fromEntries(names.map((name) => [name, () => null]));
  assert.throws(() => createConnectedHeartbeatApplyStore({
    driver: { transaction: (callback) => callback },
    entitlementStore: methods([
      'applyEntitlement', 'assertExactReplay', 'recordFailure', 'getState', 'disposition',
      'listPendingAcknowledgements', 'acknowledgementHealth', 'recordAckResult',
      'assertAcknowledgementLineages',
    ]),
    registryStore: methods([
      'applyVerdict', 'getState', 'registryGeneration', 'disposition',
    ]),
    acknowledgedAuthorityStore: methods([
      'stagePair', 'recordAcknowledgementResult', 'getState', 'constrainDisposition',
    ]),
    verifyAuditState: () => ({ ok: true }),
    coordinator: fake,
  }), /transaction coordinator is required/);
});

test('plain non-Postgres transactions cannot claim combined-read coordination', () => {
  const stores = methodSet();
  assert.throws(() => createConnectedHeartbeatApplyStore({
    driver: { transaction: (callback) => callback },
    entitlementStore: stores,
    registryStore: stores,
    acknowledgedAuthorityStore: stores,
    verifyAuditState: () => ({ ok: true }),
    coordinator: createConnectedHeartbeatTransactionCoordinator(),
  }), /writer-coordinated read transaction is required/);
});

test('composite audit verifier never receives the composite context as receiver', () => {
  const receivers = [];
  const env = harness(receivers);
  apply(env.store);
  assert.deepEqual(receivers, [undefined]);
});

test('combined reads verify under one transaction and invoke store callbacks receiverless', () => {
  let transactionDepth = 0;
  let auditLockHeld = false;
  let verificationCount = 0;
  const coordinator = createConnectedHeartbeatTransactionCoordinator();
  const driver = {
    transaction(callback) {
      return (...args) => {
        transactionDepth += 1;
        auditLockHeld = false;
        try { return callback(...args); }
        finally {
          auditLockHeld = false;
          transactionDepth -= 1;
        }
      };
    },
    lockAuditAppend() {
      assert.equal(transactionDepth, 1);
      auditLockHeld = true;
    },
  };
  const observed = [];
  const entitlementStore = methodSet({
    getState() {
      observed.push(['entitlement-state', this, transactionDepth, auditLockHeld,
        coordinator.isAuditVerified()]);
      return { entitlementVersion: 1 };
    },
    disposition() {
      observed.push(['entitlement-disposition', this, transactionDepth, auditLockHeld,
        coordinator.isAuditVerified()]);
      return { protectedEgress: 'allow' };
    },
  });
  const registryStore = methodSet({
    getState() {
      observed.push(['registry-state', this, transactionDepth, auditLockHeld,
        coordinator.isAuditVerified()]);
      return { registryGeneration: 9 };
    },
    disposition(_customerId, _deploymentId, value) {
      observed.push(['registry-disposition', this, transactionDepth, auditLockHeld,
        coordinator.isAuditVerified()]);
      return value;
    },
  });
  const acknowledgedAuthorityStore = methodSet({
    getState() {
      observed.push(['acknowledged-state', this, transactionDepth, auditLockHeld,
        coordinator.isAuditVerified()]);
      return { acknowledgedPairDigest: null };
    },
    constrainDisposition(input) {
      observed.push(['acknowledged-disposition', this, transactionDepth, auditLockHeld,
        coordinator.isAuditVerified()]);
      return input.currentDisposition;
    },
  });
  const store = createConnectedHeartbeatApplyStore({
    driver,
    entitlementStore,
    registryStore,
    acknowledgedAuthorityStore,
    verifyAuditState() {
      assert.equal(this, undefined);
      assert.equal(transactionDepth, 1);
      assert.equal(auditLockHeld, true);
      verificationCount += 1;
      return { ok: true };
    },
    coordinator,
  });

  assert.deepEqual(store.getState(CUSTOMER_ID, DEPLOYMENT_ID), {
    entitlement: { entitlementVersion: 1 }, registry: { registryGeneration: 9 },
    acknowledgedAuthority: { acknowledgedPairDigest: null },
  });
  assert.deepEqual(store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW }), {
    protectedEgress: 'allow',
  });
  assert.equal(verificationCount, 2);
  assert.deepEqual(observed.map((entry) => entry.slice(0, 2)), [
    ['entitlement-state', undefined], ['registry-state', undefined], ['acknowledged-state', undefined],
    ['entitlement-state', undefined], ['registry-state', undefined],
    ['entitlement-disposition', undefined], ['registry-disposition', undefined],
    ['acknowledged-disposition', undefined],
  ]);
  for (const [, , depth, lockHeld, auditVerified] of observed) {
    assert.equal(depth, 1);
    assert.equal(lockHeld, true);
    assert.equal(auditVerified, true);
  }
});

test('getState excludes an independent SQLite writer across both authority reads', async () => {
  await concurrentCombinedRead('getState');
});

test('disposition excludes an independent SQLite writer across both authority reads', async () => {
  await concurrentCombinedRead('disposition');
});

test('one transaction applies independently signed registry and entitlement high-waters', () => {
  const env = harness();
  const result = apply(env.store);
  assert.equal(result.registry.state.registryGeneration, 9);
  assert.equal(result.entitlement.state.entitlementVersion, 1);
  const appliedState = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.deepEqual(appliedState.entitlement, result.entitlement.state);
  assert.deepEqual(appliedState.registry, result.registry.state);
  assert.deepEqual({
    ...appliedState.acknowledgedAuthority,
    current: undefined,
    acknowledged: undefined,
  }, {
    ...result.acknowledgedAuthority.state,
    current: undefined,
    acknowledged: undefined,
  });
  assert.equal(
    appliedState.acknowledgedAuthority.current.pairDigest,
    result.acknowledgedAuthority.pair.pairDigest,
  );
  assert.equal(appliedState.acknowledgedAuthority.acknowledged, null);
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 9);
  assert.equal(env.store.entitlementVersion(CUSTOMER_ID, DEPLOYMENT_ID), 1);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 2);
  const beforeAcknowledgement = env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 1,
    clock: { bootId: '1'.repeat(32), nowMs: 5001 },
  });
  assert.equal(beforeAcknowledgement.protectedEgress, 'block');
  assert.equal(beforeAcknowledgement.reason, 'connected_initial_acknowledgement_pending');
  env.store.recordAckResult(ackInput(result.entitlement.outboxes.delivered, NOW + 2));
  assert.equal(env.createStore().disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 3,
    clock: { bootId: '1'.repeat(32), nowMs: 5003 },
  }).reason, 'connected_initial_acknowledgement_pending');
  env.store.recordAckResult(ackInput(result.entitlement.outboxes.applied, NOW + 4));
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 5,
    clock: { bootId: '1'.repeat(32), nowMs: 5005 },
  }).protectedEgress, 'allow');
  assert.equal(env.createStore().disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 6,
    clock: { bootId: '1'.repeat(32), nowMs: 5006 },
  }).protectedEgress, 'allow');
});

test('real runtime blocks every release surface until the exact delivered and applied ACKs persist', () => {
  const env = harness();
  const result = apply(env.store, { clock: systemBootClock() });
  const runtime = realRuntime(env.store);
  assert.equal(runtime.protectedEgressAllowed(), false);
  assert.deepEqual(runtime.readiness(), {
    ok: false,
    connected: true,
    mode: 'blocked',
    reason: 'connected_initial_acknowledgement_pending',
  });
  assert.equal(runtime.serviceReadiness().serviceReady, false);
  assert.deepEqual(runtime.publicStatus(), {
    state: 'restricted',
    connected: true,
    managedExternally: true,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    plan: null,
    seats: null,
    features: [],
    entitlementVersion: 0,
    registryGeneration: 0,
    appliedEntitlementVersion: 1,
    appliedRegistryGeneration: 9,
    effectivePairDigest: null,
    lastContactAt: '2026-07-12T12:01:00.000Z',
    fallbackUntil: null,
    reason: 'connected_initial_acknowledgement_pending',
  });
  const responses = [];
  let nextCalls = 0;
  const response = {
    status(code) { responses.push(['status', code]); return this; },
    json(body) { responses.push(['json', body]); return this; },
  };
  runtime.requireProtectedEgress({}, response, () => { nextCalls += 1; });
  assert.equal(nextCalls, 0);
  assert.deepEqual(responses, [
    ['status', 403],
    ['json', {
      error: 'license_restricted', reason: 'connected_initial_acknowledgement_pending',
    }],
  ]);

  env.store.recordAckResult(ackInput(result.entitlement.outboxes.delivered, NOW + 2));
  assert.equal(realRuntime(env.createStore()).protectedEgressAllowed(), false);
  env.store.recordAckResult({
    ...ackInput(result.entitlement.outboxes.applied, NOW + 3),
    accepted: false,
    failureClass: 'transport_unavailable',
  });
  assert.equal(realRuntime(env.createStore()).serviceReadiness().serviceReady, false);

  env.store.recordAckResult(ackInput(result.entitlement.outboxes.applied, NOW + 10_000));
  const restarted = realRuntime(env.createStore());
  assert.equal(restarted.protectedEgressAllowed(), true);
  assert.equal(restarted.readiness().ok, true);
  assert.equal(restarted.serviceReadiness().serviceReady, true);
  const state = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).acknowledgedAuthority;
  assert.deepEqual(restarted.publicStatus(), {
    state: 'active',
    connected: true,
    managedExternally: true,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    plan: 'enterprise',
    seats: 25,
    features: ['policy'],
    entitlementVersion: 1,
    registryGeneration: 9,
    appliedEntitlementVersion: 1,
    appliedRegistryGeneration: 9,
    effectivePairDigest: state.acknowledgedPairDigest,
    lastContactAt: '2026-07-12T12:01:00.000Z',
    fallbackUntil: '2026-07-15T12:00:00.000Z',
    reason: null,
  });
});

test('higher registry-only active and revoke generations preserve one exact entitlement ACK lineage', () => {
  const env = harness();
  const baseline = apply(env.store);
  acknowledgePair(env.store, baseline, NOW + 10);
  const originalOutboxRows = env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_outbox',
  ).get().n;
  const originalAckRows = env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive WHERE target_version = 1',
  ).get().n;

  const active = applyRegistryOnly(env.store, 10);
  assert.equal(active.entitlement.idempotent, true);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_outbox',
  ).get().n, originalOutboxRows, 'registry-only apply cannot synthesize a new entitlement ACK');
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive WHERE target_version = 1',
  ).get().n, originalAckRows, 'registry-only apply reuses only the exact durable artifact lineage');
  let projection = env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority;
  assert.equal(projection.current.registryGeneration, 10);
  assert.equal(projection.acknowledged.registryGeneration, 10);
  assert.equal(projection.acknowledged.entitlementVersion, 1);
  assert.equal(env.db.prepare(`SELECT transition_kind FROM connected_authority_pair_lineage
    WHERE pair_digest = ?`).get(projection.acknowledgedPairDigest).transition_kind, 'registry_only');
  assert.equal(env.createStore().disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 3000,
    clock: { bootId: '1'.repeat(32), nowMs: 8000 },
  }).protectedEgress, 'allow');

  const beforeReplay = {
    audit: env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n,
    pairs: env.db.prepare('SELECT COUNT(*) AS n FROM connected_authority_pair_lineage').get().n,
  };
  const replay = applyRegistryOnly(env.store, 10);
  assert.equal(replay.contactAdvanced, false);
  assert.deepEqual({
    audit: env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n,
    pairs: env.db.prepare('SELECT COUNT(*) AS n FROM connected_authority_pair_lineage').get().n,
  }, beforeReplay);
  assert.throws(() => applyRegistryOnly(env.store, 10, 'active', {
    registryStateDigest: 'f'.repeat(64),
  }), (error) => /conflict/.test(String(error?.code || error?.message || '')));

  applyRegistryOnly(env.store, 11, 'revoked');
  projection = env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority;
  assert.equal(projection.current.registryGeneration, 11);
  assert.equal(projection.acknowledged.registryGeneration, 11);
  assert.equal(projection.acknowledged.registryStatus, 'revoked');
  const revoked = env.createStore().disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 4000,
    clock: { bootId: '1'.repeat(32), nowMs: 9000 },
  });
  assert.equal(revoked.protectedEgress, 'block');
  assert.equal(revoked.reason, 'vendor_registry_revoked');
});

test('registry-only active and revoke generations survive restart without duplicating ACKs', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-registry-only-restart-'));
  const databasePath = path.join(directory, 'connected.db');
  let env = harness(null, databasePath);
  t.after(() => {
    try { env.db.close(); } catch {}
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const baseline = apply(env.store);
  acknowledgePair(env.store, baseline, NOW + 10);
  env.db.close();

  env = harness(null, databasePath);
  applyRegistryOnly(env.store, 10);
  env.db.close();

  env = harness(null, databasePath);
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 10);
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 3000,
    clock: { bootId: '1'.repeat(32), nowMs: 8000 },
  }).protectedEgress, 'allow');
  const auditCount = env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n;
  applyRegistryOnly(env.store, 10);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, auditCount);
  applyRegistryOnly(env.store, 11, 'revoked');
  env.db.close();

  env = harness(null, databasePath);
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 11);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_outbox',
  ).get().n, 2);
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 4000,
    clock: { bootId: '1'.repeat(32), nowMs: 9000 },
  }).reason, 'vendor_registry_revoked');
});

test('registry-only projection failure rolls registry generation and authority back atomically', () => {
  const env = harness();
  const baseline = apply(env.store);
  acknowledgePair(env.store, baseline, NOW + 10);
  const pairDigest = env.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.acknowledgedPairDigest;
  env.failAudit(
    'CONNECTED_ACKNOWLEDGED_AUTHORITY_ADVANCED',
    'forced registry-only projection failure',
  );
  assert.throws(() => applyRegistryOnly(env.store, 10), /forced registry-only projection failure/);
  env.restoreAudit();
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 9);
  assert.equal(env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.acknowledgedPairDigest, pairDigest);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_authority_pair_lineage',
  ).get().n, 1);
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 3000,
    clock: { bootId: '1'.repeat(32), nowMs: 8000 },
  }).protectedEgress, 'allow');
});

test('first restrictive pairs enforce immediately but grant nothing and keep service unready', () => {
  const cases = [
    {
      name: 'entitlement paused',
      entitlement: entitlement({ status: 'paused', fallbackUntil: null, reasonCode: 'manual_pause' }),
      reason: 'vendor_paused',
    },
    {
      name: 'entitlement revoked',
      entitlement: entitlement({ status: 'revoked', fallbackUntil: null, reasonCode: 'manual_revoke' }),
      reason: 'vendor_revoked',
    },
    {
      name: 'registry revoked',
      verdict: verdict({ status: 'revoked', registryStateDigest: generationDigest(9, 'revoked') }),
      reason: 'vendor_registry_revoked',
    },
  ];
  for (const scenario of cases) {
    const env = harness();
    const result = apply(env.store, {
      ...(scenario.entitlement
        ? { signedEntitlementArtifact: signedEntitlement(scenario.entitlement) } : {}),
      ...(scenario.verdict ? { signedOnlineRegistryVerdict: scenario.verdict } : {}),
    });
    const runtime = realRuntime(env.createStore());
    assert.equal(runtime.disposition().reason, scenario.reason, scenario.name);
    assert.equal(runtime.protectedEgressAllowed(), false, scenario.name);
    assert.equal(runtime.featureEnabled('policy'), false, scenario.name);
    assert.deepEqual(runtime.seatAuthority(), {
      configured: true, seatLimit: 0, source: 'connected_entitlement',
    }, scenario.name);
    assert.deepEqual(runtime.publicStatus().features, [], scenario.name);
    assert.equal(runtime.publicStatus().plan, null, scenario.name);
    assert.equal(runtime.publicStatus().seats, null, scenario.name);
    assert.equal(runtime.readiness().ok, false, scenario.name);
    assert.equal(
      runtime.readiness().reason,
      'connected_initial_acknowledgement_pending',
      scenario.name,
    );
    assert.equal(runtime.readiness().enforcementReason, scenario.reason, scenario.name);
    assert.equal(runtime.serviceReadiness().serviceReady, false, scenario.name);

    env.store.recordAckResult(ackInput(result.entitlement.outboxes.delivered, NOW + 2));
    assert.equal(realRuntime(env.createStore()).serviceReadiness().serviceReady, false, scenario.name);
    env.store.recordAckResult(ackInput(result.entitlement.outboxes.applied, NOW + 3));
    const acknowledged = realRuntime(env.createStore());
    assert.equal(acknowledged.disposition().reason, scenario.reason, scenario.name);
    assert.equal(acknowledged.readiness().ok, false, scenario.name);
    assert.equal(acknowledged.serviceReadiness().serviceReady, true, scenario.name);
  }
});

test('pending authority clamps expansions and applies every later contraction immediately', () => {
  const env = harness();
  const v1 = apply(env.store);
  acknowledgePair(env.store, v1, NOW + 10);
  const disposition = (store = env.store, offset = 0) => store.disposition(
    CUSTOMER_ID,
    DEPLOYMENT_ID,
    { nowMs: NOW + 20_000 + offset, clock: { bootId: '1'.repeat(32), nowMs: 25_000 + offset } },
  );

  const v2 = applyVersion(env.store, 2, {
    plan: 'standard', seats: 50, features: ['policy', 'shadow_ai'],
  });
  assert.deepEqual(disposition().authority, {
    plan: 'standard', seats: 25, features: ['policy'],
  }, 'plan uses the lower tier, seats use the minimum, and features use the intersection');
  acknowledgePair(env.store, v2, NOW + 30_000);
  assert.deepEqual(disposition(env.createStore(), 1).authority, {
    plan: 'standard', seats: 50, features: ['policy', 'shadow_ai'],
  });

  applyVersion(env.store, 3, { plan: 'enterprise', seats: 4, features: [] });
  assert.deepEqual(disposition(env.createStore(), 2).authority, {
    plan: 'standard', seats: 4, features: [],
  }, 'an unacknowledged active contraction is effective immediately');
  applyVersion(env.store, 4, { status: 'paused', reasonCode: 'manual_pause' });
  const paused = disposition(env.createStore(), 3);
  assert.equal(paused.protectedEgress, 'block');
  assert.equal(paused.mode, 'paused');
  assert.equal(paused.reason, 'vendor_paused');

  const revoked = harness();
  const allowed = apply(revoked.store);
  acknowledgePair(revoked.store, allowed, NOW + 10);
  applyVersion(revoked.store, 2, { status: 'revoked', reasonCode: 'manual_revoke' });
  assert.equal(revoked.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 20_000,
    clock: { bootId: '1'.repeat(32), nowMs: 25_000 },
  }).reason, 'vendor_revoked');

  const registryRevoked = harness();
  const registryAllowed = apply(registryRevoked.store);
  acknowledgePair(registryRevoked.store, registryAllowed, NOW + 10);
  applyVersion(registryRevoked.store, 2, { registryStatus: 'revoked' });
  assert.equal(registryRevoked.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 20_000,
    clock: { bootId: '1'.repeat(32), nowMs: 25_000 },
  }).reason, 'vendor_registry_revoked');
});

test('unacknowledged pause and revoke clamp every grant to the acknowledged baseline', (t) => {
  for (const status of ['paused', 'revoked']) {
    const directory = fs.mkdtempSync(path.join(
      os.tmpdir(), `rw-connected-${status}-expansion-`,
    ));
    const databasePath = path.join(directory, 'connected.db');
    let env = harness(null, databasePath);
    t.after(() => {
      try { env.db.close(); } catch {}
      fs.rmSync(directory, { recursive: true, force: true });
    });
    const baseline = applyVersion(env.store, 1, {
      plan: 'standard', seats: 25, features: ['policy'],
    });
    acknowledgePair(env.store, baseline, NOW + 10_000);
    applyVersion(env.store, 2, {
      plan: 'enterprise',
      seats: 100,
      features: ['policy', 'shadow_ai'],
      status,
      reasonCode: status === 'paused' ? 'manual_pause' : 'manual_revoke',
    });
    env.db.close();
    env = harness(null, databasePath);
    const runtime = realRuntime(env.createStore(), NOW + 20_000);
    const disposition = runtime.disposition();
    assert.equal(disposition.protectedEgress, 'block', status);
    assert.equal(disposition.reason, status === 'paused' ? 'vendor_paused' : 'vendor_revoked');
    assert.deepEqual(disposition.authority, {
      plan: 'standard', seats: 25, features: ['policy'],
    }, status);
    assert.equal(runtime.featureEnabled('policy'), true, status);
    assert.equal(runtime.featureEnabled('shadow_ai'), false, status);
    assert.deepEqual(runtime.seatAuthority(), {
      configured: true, seatLimit: 25, source: 'connected_entitlement',
    }, status);
    const publicStatus = runtime.publicStatus();
    assert.equal(publicStatus.plan, 'standard', status);
    assert.equal(publicStatus.seats, 25, status);
    assert.deepEqual(publicStatus.features, ['policy'], status);
    assert.equal(runtime.serviceReadiness().serviceReady, true, status);
  }
});

test('retained connected pause survives restart and an active fallback reinstall cannot clear it', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-connected-authority-restart-'));
  const databasePath = path.join(directory, 'connected.db');
  let env = harness(null, databasePath);
  t.after(() => {
    try { env.db.close(); } catch {}
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const v1 = apply(env.store);
  acknowledgePair(env.store, v1, NOW + 10);
  applyVersion(env.store, 2, { status: 'paused', reasonCode: 'manual_pause' });
  env.db.close();

  env = harness(null, databasePath);
  const restartedState = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.equal(restartedState.entitlement.entitlement.status, 'paused');
  assert.equal(restartedState.acknowledgedAuthority.acknowledged.entitlementVersion, 1);
  env.store.recordFailure({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    failureClass: 'transport_unavailable',
    nowMs: NOW + 20_000,
  });
  const afterFallbackReinstall = env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 21_000,
    offlineLicenseText: signedOfflineFallback({ seats: 1000 }),
  });
  assert.equal(afterFallbackReinstall.protectedEgress, 'block');
  assert.equal(afterFallbackReinstall.mode, 'paused');
  assert.equal(afterFallbackReinstall.reason, 'vendor_paused');
});

test('v2 and v3 retain immutable pair lineage and each applied ACK advances only its exact pair', () => {
  const env = harness();
  const v1 = apply(env.store);
  acknowledgePair(env.store, v1, NOW + 10);
  const v2 = applyVersion(env.store, 2, { seats: 50, features: ['policy', 'shadow_ai'] });
  const v3 = applyVersion(env.store, 3, {
    seats: 75,
    features: ['diagnostics', 'policy', 'shadow_ai'],
  });
  const disposition = (store = env.store, offset = 3500) => store.disposition(
    CUSTOMER_ID,
    DEPLOYMENT_ID,
    { nowMs: NOW + offset, clock: { bootId: '1'.repeat(32), nowMs: 5000 + offset } },
  );

  assert.deepEqual(disposition().authority, {
    plan: 'enterprise', seats: 25, features: ['policy'],
  });
  acknowledgePair(env.store, v2, NOW + 4000);
  assert.deepEqual(disposition(env.createStore(), 4500).authority, {
    plan: 'enterprise', seats: 50, features: ['policy', 'shadow_ai'],
  });
  let projection = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).acknowledgedAuthority;
  let acknowledged = env.db.prepare(`SELECT registry_generation, entitlement_version,
    artifact_digest FROM connected_authority_pair_lineage
    WHERE pair_digest = ?`).get(projection.acknowledgedPairDigest);
  assert.deepEqual({
    registryGeneration: Number(acknowledged.registry_generation),
    entitlementVersion: Number(acknowledged.entitlement_version),
    artifactDigest: acknowledged.artifact_digest,
  }, {
    registryGeneration: 10,
    entitlementVersion: 2,
    artifactDigest: v2.entitlement.artifactDigest,
  });

  acknowledgePair(env.store, v3, NOW + 5000);
  assert.deepEqual(disposition(env.createStore(), 5500).authority, {
    plan: 'enterprise', seats: 75, features: ['diagnostics', 'policy', 'shadow_ai'],
  });
  projection = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).acknowledgedAuthority;
  acknowledged = env.db.prepare(`SELECT registry_generation, entitlement_version,
    artifact_digest FROM connected_authority_pair_lineage
    WHERE pair_digest = ?`).get(projection.acknowledgedPairDigest);
  assert.equal(Number(acknowledged.registry_generation), 11);
  assert.equal(Number(acknowledged.entitlement_version), 3);
  assert.equal(acknowledged.artifact_digest, v3.entitlement.artifactDigest);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_authority_pair_lineage',
  ).get().n, 1, 'only the current acknowledged lineage remains live');
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_authority_pair_deletions',
  ).get().n, 2, 'superseded lineage is retained as authenticated deletion history');
  assert.ok(env.db.prepare(`SELECT length(state_json) AS bytes
    FROM connected_acknowledged_authority_state`).get().bytes < 2048,
  'the hot acknowledged projection stays compact instead of embedding ACK history');
  assert.throws(() => env.db.exec(`UPDATE connected_authority_pair_lineage
    SET authority_json = authority_json`), /immutable/);
  assert.throws(() => env.db.exec(`UPDATE connected_authority_pair_deletions
    SET pair_digest = pair_digest`), /append-only/);
  assert.throws(() => env.db.exec('DELETE FROM connected_authority_pair_deletions'), /append-only/);

  env.store.recordAckResult(ackInput(v2.entitlement.outboxes.applied, NOW + 6000));
  assert.equal(env.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.acknowledgedPairDigest, projection.acknowledgedPairDigest);
});

test('authenticated deletion history rejects stable-summary payload tamper in warm and fresh stores', () => {
  const env = harness();
  const v1 = apply(env.store);
  acknowledgePair(env.store, v1, NOW + 10);
  const v2 = applyVersion(env.store, 2, { seats: 50 });
  acknowledgePair(env.store, v2, NOW + 20);
  const v3 = applyVersion(env.store, 3, { seats: 75 });
  acknowledgePair(env.store, v3, NOW + 30);
  const summary = env.db.prepare(`SELECT COUNT(*) AS count,
    MAX(event_seq) AS high_water, MAX(scope_seq) AS scope_high_water
    FROM connected_authority_pair_deletions`).get();
  assert.deepEqual(summary, { count: 2, high_water: 2, scope_high_water: 2 });
  const deletionGuardSql = env.db.prepare(`SELECT sql FROM main.sqlite_schema
    WHERE type = 'trigger' AND name = 'connected_authority_pair_deletions_no_update'`)
    .get().sql;
  env.db.exec('DROP TRIGGER connected_authority_pair_deletions_no_update');
  env.db.prepare(`UPDATE connected_authority_pair_deletions SET
    pair_digest = ?, registry_generation = registry_generation + 1000,
    entitlement_version = entitlement_version + 1000,
    applied_ack_id = ?, deleted_at = ?
    WHERE event_seq = (SELECT MIN(event_seq) FROM connected_authority_pair_deletions)`)
    .run('a'.repeat(64), 'tampered-applied-ack', '2099-01-01T00:00:00.000Z');
  env.db.exec(deletionGuardSql);
  assert.deepEqual(env.db.prepare(`SELECT COUNT(*) AS count,
    MAX(event_seq) AS high_water, MAX(scope_seq) AS scope_high_water
    FROM connected_authority_pair_deletions`).get(), summary,
  'the adversary preserves every summary value previously authenticated');

  assertIntegrityFailure(
    () => env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 40 }),
    'a warmed store must not authorize after deletion payload tamper',
  );
  assertIntegrityFailure(
    () => env.createStore().disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 41 }),
    'a fresh store must not authorize after deletion payload tamper',
  );
});

test('v15 catalog trigger or index removal fails authorization in warm and fresh stores', () => {
  for (const statement of [
    'DROP TRIGGER connected_authority_pair_deletions_no_update',
    'DROP INDEX idx_connected_authority_pair_deletion_scope',
  ]) {
    const env = harness();
    const first = apply(env.store);
    acknowledgePair(env.store, first, NOW + 10);
    env.db.exec(statement);
    assertIntegrityFailure(
      () => env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 20 }),
      `a warmed store must reject v15 catalog mutation: ${statement}`,
    );
    assertIntegrityFailure(
      () => env.createStore().disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 21 }),
      `a fresh store must reject v15 catalog mutation: ${statement}`,
    );
    env.db.close();
  }
});

test('v15 catalog rejects extra, replaced, constraint, and TEMP authority objects', () => {
  const mutations = [
    ['extra index', (env) => env.db.exec(`CREATE INDEX unexpected_authority_index
      ON connected_authority_pair_lineage(customer_id)`)],
    ['replaced trigger', (env) => env.db.exec(`
      DROP TRIGGER connected_authority_pair_deletions_no_update;
      CREATE TRIGGER connected_authority_pair_deletions_no_update
        BEFORE UPDATE ON connected_authority_pair_deletions BEGIN SELECT 1; END;
    `)],
    ['rewritten constraint', (env) => {
      const tableSql = env.db.prepare(`SELECT sql FROM main.sqlite_schema
        WHERE type = 'table' AND name = 'connected_authority_pair_deletions'`).get().sql;
      const dependentSql = env.db.prepare(`SELECT sql FROM main.sqlite_schema
        WHERE type IN ('index', 'trigger') AND sql IS NOT NULL
          AND (tbl_name = 'connected_authority_pair_deletions'
            OR name = 'connected_authority_pair_record_delete') ORDER BY type, name`)
        .all().map((row) => row.sql);
      env.db.exec(`
        DROP TRIGGER connected_authority_pair_record_delete;
        DROP TRIGGER connected_authority_pair_deletions_no_update;
        DROP TRIGGER connected_authority_pair_deletions_no_delete;
        DROP INDEX idx_connected_authority_pair_deletion_scope;
        ALTER TABLE connected_authority_pair_deletions RENAME TO authority_deletions_old;
        ${tableSql.replace(
    'CHECK (registry_generation >= 1)', 'CHECK (registry_generation >= 0)',
  )};
        DROP TABLE authority_deletions_old;
        ${dependentSql.join(';\n')};
      `);
    }],
    ['TEMP table shadow', (env) => env.db.exec(`CREATE TEMP TABLE
      connected_acknowledged_authority_state (customer_id TEXT)`)],
    ['TEMP trigger collision', (env) => env.db.exec(`CREATE TEMP TRIGGER
      unexpected_authority_temp_trigger BEFORE UPDATE
      ON main.connected_authority_pair_lineage BEGIN SELECT 1; END`)],
  ];
  for (const [label, mutate] of mutations) {
    const env = harness();
    const first = apply(env.store);
    acknowledgePair(env.store, first, NOW + 10);
    mutate(env);
    assertIntegrityFailure(
      () => env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 20 }),
      `a warmed store must reject ${label}`,
    );
    assertIntegrityFailure(
      () => env.createStore().disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 21 }),
      `a fresh store must reject ${label}`,
    );
    env.db.close();
  }
});

test('authenticated SQLite schema generation defeats restored-SQL warm trigger cache', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-authority-schema-cache-'));
  const databasePath = path.join(root, 'authority.db');
  const env = harness(null, databasePath);
  const second = new Database(databasePath);
  t.after(() => {
    second.close();
    env.db.close();
    fs.rmSync(root, { recursive: true, force: true });
  });
  second.pragma('foreign_keys = ON');
  const first = apply(env.store);
  acknowledgePair(env.store, first, NOW + 10);
  const firstDigest = env.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.acknowledgedPairDigest;
  const schemaVersion = second.pragma('schema_version', { simple: true });
  const triggerSql = second.prepare(`SELECT sql FROM main.sqlite_schema
    WHERE type = 'trigger' AND name = 'connected_authority_pair_record_delete'`).get().sql;

  second.exec(`DROP TRIGGER connected_authority_pair_record_delete;
    CREATE TRIGGER connected_authority_pair_record_delete
      AFTER DELETE ON connected_authority_pair_lineage BEGIN SELECT 1; END;`);
  assertIntegrityFailure(
    () => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'the warm connection must first observe and reject the malicious trigger body',
  );

  second.unsafeMode(true);
  try {
    second.pragma('writable_schema = ON');
    second.prepare(`UPDATE main.sqlite_schema SET sql = ?
      WHERE type = 'trigger' AND name = 'connected_authority_pair_record_delete'`)
      .run(triggerSql);
    second.pragma('writable_schema = OFF');
  } finally {
    second.unsafeMode(false);
  }
  assert.equal(env.db.prepare(`SELECT sql FROM main.sqlite_schema
    WHERE type = 'trigger' AND name = 'connected_authority_pair_record_delete'`).get().sql,
  triggerSql, 'the catalog text is restored without advancing the changed schema cookie');
  assertIntegrityFailure(
    () => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'the warmed store must reject restored SQL while its authenticated generation differs',
  );
  assertIntegrityFailure(
    () => env.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'a later store on the warmed connection must use the authenticated state generation',
  );

  second.unsafeMode(true);
  try { second.pragma(`schema_version = ${schemaVersion}`); }
  finally { second.unsafeMode(false); }
  assert.equal(env.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.acknowledgedPairDigest, firstDigest,
  'rewinding the cookie forces SQLite to reload the canonical trigger before authorization');
  const secondPair = applyVersion(env.store, 2, { seats: 50 });
  acknowledgePair(env.store, secondPair, NOW + 20);
  assert.deepEqual(env.db.prepare(`SELECT pair_digest, scope_seq
    FROM connected_authority_pair_deletions`).get(), {
    pair_digest: firstDigest,
    scope_seq: 1,
  }, 'the reloaded canonical trigger emits the exact deleted pair tombstone');
});

test('deletion history rejects reorder and duplicate replacement with stable count/high-water', () => {
  for (const mutation of ['reorder', 'duplicate']) {
    const env = harness();
    const v1 = apply(env.store);
    acknowledgePair(env.store, v1, NOW + 10);
    const v2 = applyVersion(env.store, 2, { seats: 50 });
    acknowledgePair(env.store, v2, NOW + 20);
    const v3 = applyVersion(env.store, 3, { seats: 75 });
    acknowledgePair(env.store, v3, NOW + 30);
    const summary = env.db.prepare(`SELECT COUNT(*) AS count,
      MAX(event_seq) AS high_water, MAX(scope_seq) AS scope_high_water
      FROM connected_authority_pair_deletions`).get();
    const guards = env.db.prepare(`SELECT name, sql FROM main.sqlite_schema
      WHERE type = 'trigger' AND name IN
        ('connected_authority_pair_deletions_no_update',
         'connected_authority_pair_deletions_no_delete') ORDER BY name`).all();
    env.db.exec(`DROP TRIGGER connected_authority_pair_deletions_no_update;
      DROP TRIGGER connected_authority_pair_deletions_no_delete;`);
    if (mutation === 'reorder') {
      env.db.exec(`UPDATE connected_authority_pair_deletions SET scope_seq = scope_seq + 10;
        UPDATE connected_authority_pair_deletions SET scope_seq = CASE scope_seq
          WHEN 11 THEN 2 WHEN 12 THEN 1 END;`);
    } else {
      env.db.exec(`DELETE FROM connected_authority_pair_deletions WHERE event_seq = 1;
        INSERT INTO connected_authority_pair_deletions
          (event_seq, event_version, customer_id, deployment_id, scope_seq, transition_kind,
           pair_digest, registry_generation, entitlement_version, applied_ack_id,
           applied_ack_payload_digest, deleted_at)
        SELECT 1, event_version, customer_id, deployment_id, 1, transition_kind,
          pair_digest, registry_generation, entitlement_version, applied_ack_id,
          applied_ack_payload_digest, deleted_at
        FROM connected_authority_pair_deletions WHERE event_seq = 2;`);
    }
    for (const guard of guards) env.db.exec(guard.sql);
    assert.deepEqual(env.db.prepare(`SELECT COUNT(*) AS count,
      MAX(event_seq) AS high_water, MAX(scope_seq) AS scope_high_water
      FROM connected_authority_pair_deletions`).get(), summary);
    assertIntegrityFailure(
      () => env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 40 }),
      `${mutation} must invalidate a warmed store`,
    );
    assertIntegrityFailure(
      () => env.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
      `${mutation} must invalidate a fresh store`,
    );
    env.db.close();
  }
});

test('deletion history scan is row-count and row-size bounded before authorization', () => {
  const overCap = harness();
  const first = apply(overCap.store);
  acknowledgePair(overCap.store, first, NOW + 10);
  overCap.db.prepare(`WITH RECURSIVE sequence(value) AS (
      SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < ?
    ) INSERT INTO connected_authority_pair_deletions
      (event_version, customer_id, deployment_id, scope_seq, transition_kind,
       pair_digest, registry_generation, entitlement_version, applied_ack_id,
       applied_ack_payload_digest, deleted_at)
    SELECT 1, ?, ?, value, 'entitlement_release', ?, value, value,
      'ack-' || value, ?, '2026-07-12T12:00:00.000Z' FROM sequence`).run(
    MAX_DELETION_HISTORY_ROWS + 1,
    CUSTOMER_ID,
    DEPLOYMENT_ID,
    'a'.repeat(64),
    'b'.repeat(64),
  );
  assert.deepEqual(
    overCap.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 20 }),
    {
      protectedEgress: 'block',
      mode: 'blocked',
      reason: 'connected_authority_history_capacity',
      authority: null,
    },
  );
  const capacityRuntime = realRuntime(overCap.store, NOW + 20);
  assert.equal(capacityRuntime.disposition().reason, 'connected_authority_history_capacity');
  assert.equal(capacityRuntime.serviceReadiness().serviceReady, false);
  assert.throws(
    () => overCap.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
    (error) => error?.code === 'CONNECTED_AUTHORITY_DELETION_HISTORY_CAPACITY',
  );

  const oversized = harness();
  const oversizedFirst = apply(oversized.store);
  acknowledgePair(oversized.store, oversizedFirst, NOW + 10);
  oversized.db.pragma('ignore_check_constraints = ON');
  oversized.db.prepare(`INSERT INTO connected_authority_pair_deletions
    (event_version, customer_id, deployment_id, scope_seq, transition_kind,
     pair_digest, registry_generation, entitlement_version, applied_ack_id,
     applied_ack_payload_digest, deleted_at)
    VALUES (1, ?, ?, 1, 'entitlement_release', ?, 1, 1, ?, ?, ?)`)
    .run(CUSTOMER_ID, DEPLOYMENT_ID, 'c'.repeat(64), 'x'.repeat(3000),
      'd'.repeat(64), '2026-07-12T12:00:00.000Z');
  oversized.db.pragma('ignore_check_constraints = OFF');
  assertIntegrityFailure(
    () => oversized.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 20 }),
    'an oversized tombstone row must fail closed before authorization',
  );
});

test('live authority pair count is capped before warm or fresh authorization', () => {
  const env = harness();
  const first = apply(env.store);
  acknowledgePair(env.store, first, NOW + 10);
  const currentPairDigest = env.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.currentPairDigest;

  env.db.prepare(`WITH RECURSIVE sequence(value) AS (
      SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < ?
    ) INSERT INTO connected_authority_pair_lineage
      (pair_digest, customer_id, deployment_id, transition_kind, registry_generation,
       registry_state_digest, registry_status, entitlement_version, entitlement_digest,
       artifact_digest, entitlement_status, authority_json, entitlement_issued_at,
       entitlement_expires_at, entitlement_fallback_until, entitlement_reason_code,
       entitlement_signing_key_id, delivered_ack_id, delivered_ack_payload_digest,
       applied_ack_id, applied_ack_payload_digest, created_at)
    SELECT printf('%064x', sequence.value), pair.customer_id, pair.deployment_id,
      pair.transition_kind, pair.registry_generation + sequence.value,
      pair.registry_state_digest, pair.registry_status,
      pair.entitlement_version + sequence.value, pair.entitlement_digest,
      pair.artifact_digest, pair.entitlement_status, pair.authority_json,
      pair.entitlement_issued_at, pair.entitlement_expires_at,
      pair.entitlement_fallback_until, pair.entitlement_reason_code,
      pair.entitlement_signing_key_id, pair.delivered_ack_id,
      pair.delivered_ack_payload_digest, pair.applied_ack_id,
      pair.applied_ack_payload_digest, pair.created_at
    FROM connected_authority_pair_lineage AS pair CROSS JOIN sequence
    WHERE pair.pair_digest = ?`).run(1024, currentPairDigest);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS count FROM connected_authority_pair_lineage',
  ).get().count, 1025);

  assertIntegrityFailure(
    () => env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 20 }),
    'the warmed store must not authorize more than the bounded live lineage set',
  );
  assertIntegrityFailure(
    () => env.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'a fresh store must reject the bounded count sentinel without scanning all lineages',
  );
});

test('bounded authority projections reject oversized and wrong-class SQLite values', () => {
  const oversized = 'x'.repeat(1024 * 1024);
  const stateMutations = [
    ['oversized state JSON', (env) => env.db.prepare(`UPDATE
      connected_acknowledged_authority_state SET state_json = ?`).run(oversized)],
    ['wrong-class state number', (env) => {
      env.db.pragma('ignore_check_constraints = ON');
      try {
        env.db.prepare(`UPDATE connected_acknowledged_authority_state
          SET current_registry_generation = ?`).run(oversized);
      } finally { env.db.pragma('ignore_check_constraints = OFF'); }
    }],
    ['oversized nullable state value', (env) => {
      env.db.pragma('ignore_check_constraints = ON');
      try {
        env.db.prepare(`UPDATE connected_acknowledged_authority_state
          SET acknowledged_registry_state_digest = ?`).run(oversized);
      } finally { env.db.pragma('ignore_check_constraints = OFF'); }
    }],
  ];
  for (const [label, mutate] of stateMutations) {
    const env = harness();
    apply(env.store);
    mutate(env);
    assertIntegrityFailure(
      () => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
      `the warmed store must reject ${label}`,
    );
    assertIntegrityFailure(
      () => env.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
      `a fresh store must reject ${label}`,
    );
    env.db.close();
  }

  for (const [label, column] of [
    ['oversized pair JSON', 'authority_json'],
    ['wrong-class pair number', 'registry_generation'],
  ]) {
    const env = harness();
    const first = apply(env.store);
    acknowledgePair(env.store, first, NOW + 10);
    const schemaVersion = env.db.pragma('schema_version', { simple: true });
    const guardSql = env.db.prepare(`SELECT sql FROM main.sqlite_schema
      WHERE type = 'trigger' AND name = 'connected_authority_pair_no_update'`).get().sql;
    env.db.exec('DROP TRIGGER connected_authority_pair_no_update');
    env.db.pragma('ignore_check_constraints = ON');
    try {
      env.db.prepare(`UPDATE connected_authority_pair_lineage SET ${column} = ?`).run(oversized);
    } finally { env.db.pragma('ignore_check_constraints = OFF'); }
    env.db.exec(guardSql);
    env.db.unsafeMode(true);
    try { env.db.pragma(`schema_version = ${schemaVersion}`); }
    finally { env.db.unsafeMode(false); }

    assertIntegrityFailure(
      () => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
      `the warmed store must reject ${label}`,
    );
    assertIntegrityFailure(
      () => env.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
      `a fresh store must reject ${label}`,
    );
    env.db.close();
  }
});

test('out-of-order v3 acknowledgement never lets a later v2 replay rewind the projection', () => {
  const env = harness();
  const v1 = apply(env.store);
  acknowledgePair(env.store, v1, NOW + 10);
  const v2 = applyVersion(env.store, 2, { seats: 50 });
  const v3 = applyVersion(env.store, 3, { seats: 75 });
  acknowledgePair(env.store, v3, NOW + 4000);
  const afterV3 = env.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.acknowledgedPairDigest;
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_authority_pair_lineage',
  ).get().n, 2, 'the unacknowledged v2 lineage cannot be compacted by v3');
  acknowledgePair(env.store, v2, NOW + 5000);
  assert.equal(env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.acknowledgedPairDigest, afterV3);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_authority_pair_lineage',
  ).get().n, 1, 'the behind lineage becomes compactable only after its exact ACKs are accepted');
});

test('exact replay after both durable ACKs is mutation-free and preserves the effective pair', () => {
  const env = harness();
  const first = apply(env.store);
  acknowledgePair(env.store, first, NOW + 10);
  const before = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).acknowledgedAuthority;
  const auditCount = env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n;
  const replay = apply(env.store);
  assert.equal(replay.contactAdvanced, false);
  assert.equal(replay.entitlement.idempotent, true);
  assert.deepEqual(
    env.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID).acknowledgedAuthority,
    before,
  );
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, auditCount);
  assert.equal(env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 1000, limit: 10,
  }).length, 0);
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 1000,
    clock: { bootId: '1'.repeat(32), nowMs: 6000 },
  }).protectedEgress, 'allow');
});

test('same registry generation or entitlement version conflicts cannot rewrite a staged pair', () => {
  const env = harness();
  const first = apply(env.store);
  const before = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).acknowledgedAuthority;
  const counts = () => ({
    pairs: env.db.prepare('SELECT COUNT(*) AS n FROM connected_authority_pair_lineage').get().n,
    audit: env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n,
  });
  const originalCounts = counts();
  assert.throws(() => apply(env.store, {
    signedOnlineRegistryVerdict: verdict({ registryStateDigest: 'a'.repeat(64) }),
  }), (error) => /conflict/.test(String(error?.code || error?.message || '')));
  assert.deepEqual(counts(), originalCounts);
  assert.throws(() => apply(env.store, {
    signedEntitlementArtifact: signedEntitlement(entitlement({ seats: 26 })),
  }), (error) => /conflict/.test(String(error?.code || error?.message || '')));
  assert.deepEqual(counts(), originalCounts);
  assert.deepEqual(
    env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).acknowledgedAuthority,
    before,
  );
  assert.equal(first.acknowledgedAuthority.acknowledged, false);
});

test('projection stage audit failure rolls back registry, entitlement, ACK, and pair writes', () => {
  const env = harness();
  env.failAudit('CONNECTED_ACKNOWLEDGED_AUTHORITY_STAGED',
    'forced projection stage audit failure');
  assert.throws(() => apply(env.store), /forced projection stage audit failure/);
  for (const table of [
    'connected_online_registry_state',
    'connected_entitlement_state',
    'connected_ack_outbox',
    'connected_ack_health',
    'connected_authority_pair_lineage',
    'connected_acknowledged_authority_state',
    'audit',
  ]) {
    assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0, table);
  }
});

test('projection advancement failure rolls the applied ACK and authority high-water back together', () => {
  const env = harness();
  const first = apply(env.store);
  env.store.recordAckResult(ackInput(first.entitlement.outboxes.delivered, NOW + 1));
  const auditCount = env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n;
  env.failAudit('CONNECTED_ACKNOWLEDGED_AUTHORITY_ADVANCED',
    'forced projection advancement failure');
  assert.throws(
    () => env.store.recordAckResult(ackInput(first.entitlement.outboxes.applied, NOW + 2)),
    /forced projection advancement failure/,
  );
  assert.equal(env.db.prepare(`SELECT status FROM connected_ack_outbox
    WHERE id = ?`).get(first.entitlement.outboxes.applied.id).status, 'pending');
  assert.equal(env.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).acknowledgedAuthority.acknowledgedPairDigest, null);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, auditCount);
  env.restoreAudit();
  env.store.recordAckResult(ackInput(first.entitlement.outboxes.applied, NOW + 3));
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 4, clock: { bootId: '1'.repeat(32), nowMs: 5004 },
  }).protectedEgress, 'allow');
});

test('missing, corrupt, rewound, or cross-scope authority state fails closed', () => {
  const missing = harness();
  const missingFirst = apply(missing.store);
  acknowledgePair(missing.store, missingFirst, NOW + 10);
  missing.db.exec('DELETE FROM connected_acknowledged_authority_state');
  assertIntegrityFailure(
    () => missing.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'a removed projection cannot grant from surviving signed authority rows',
  );

  const corrupt = harness();
  const corruptFirst = apply(corrupt.store);
  acknowledgePair(corrupt.store, corruptFirst, NOW + 10);
  corrupt.db.exec("UPDATE connected_acknowledged_authority_state SET state_json = '{}'");
  assertIntegrityFailure(
    () => corrupt.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 20 }),
    'corrupt compact state must block authorization',
  );

  const rewound = harness();
  const v1 = apply(rewound.store);
  acknowledgePair(rewound.store, v1, NOW + 10);
  const v1State = rewound.db.prepare(
    'SELECT * FROM connected_acknowledged_authority_state',
  ).get();
  applyVersion(rewound.store, 2, { seats: 50 });
  rewound.db.prepare(`UPDATE connected_acknowledged_authority_state SET
    current_pair_digest = @current_pair_digest,
    current_registry_generation = @current_registry_generation,
    current_registry_state_digest = @current_registry_state_digest,
    current_entitlement_version = @current_entitlement_version,
    current_entitlement_digest = @current_entitlement_digest,
    acknowledged_registry_generation = @acknowledged_registry_generation,
    acknowledged_registry_state_digest = @acknowledged_registry_state_digest,
    acknowledged_entitlement_version = @acknowledged_entitlement_version,
    acknowledged_entitlement_digest = @acknowledged_entitlement_digest,
    acknowledged_pair_digest = @acknowledged_pair_digest,
    state_json = @state_json,
    updated_at = @updated_at`).run(v1State);
  assertIntegrityFailure(
    () => rewound.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'an internally coherent row rewind must still disagree with the latest audit anchor',
  );

  const scoped = harness();
  assert.throws(
    () => scoped.store.getState('customer_sibling', DEPLOYMENT_ID),
    /scope|binding|input|rejected/i,
  );
  assert.throws(
    () => scoped.store.disposition(
      CUSTOMER_ID, `dep_${'f'.repeat(32)}`, { nowMs: NOW },
    ),
    /scope|binding|input|rejected/i,
  );
});

test('missing or mutated pair lineage and authority audit evidence fails closed', () => {
  const missing = harness();
  apply(missing.store);
  missing.db.pragma('foreign_keys = OFF');
  missing.db.exec('DELETE FROM connected_authority_pair_lineage');
  missing.db.pragma('foreign_keys = ON');
  assertIntegrityFailure(
    () => missing.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'the compact state cannot substitute for its missing exact pair lineage',
  );

  const mutated = harness();
  const mutatedFirst = apply(mutated.store);
  acknowledgePair(mutated.store, mutatedFirst, NOW + 10);
  mutated.db.exec('DROP TRIGGER connected_authority_pair_no_update');
  mutated.db.prepare(`UPDATE connected_authority_pair_lineage
    SET artifact_digest = ?`).run('0'.repeat(64));
  assertIntegrityFailure(
    () => mutated.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 20 }),
    'whole signed artifact envelope digest tamper must invalidate the pair',
  );

  const auditTamper = harness();
  const auditFirst = apply(auditTamper.store);
  acknowledgePair(auditTamper.store, auditFirst, NOW + 10);
  auditTamper.db.exec(`UPDATE audit SET entry = '{}'
    WHERE seq = (SELECT MAX(seq) FROM audit
      WHERE action = 'CONNECTED_ACKNOWLEDGED_AUTHORITY_ADVANCED')`);
  assertIntegrityFailure(
    () => auditTamper.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'projection state without its authenticated audit event grants nothing',
  );
});

test('ACK archive, mutation tombstone, and ACK audit tamper invalidates acknowledged authority', () => {
  const archiveTamper = harness();
  const first = apply(archiveTamper.store);
  acknowledgePair(archiveTamper.store, first, NOW + 10);
  applyVersion(archiveTamper.store, 2, { seats: 50 });
  assert.equal(archiveTamper.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive',
  ).get().n, 2);
  archiveTamper.db.exec('DROP TRIGGER connected_ack_archive_no_update');
  archiveTamper.db.exec(`UPDATE connected_ack_archive SET attempts = attempts + 1
    WHERE archive_seq = (SELECT MIN(archive_seq) FROM connected_ack_archive)`);
  assertIntegrityFailure(
    () => archiveTamper.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 3000 }),
    'an archived acknowledged receipt cannot be altered',
  );

  const tombstoneTamper = harness();
  const tombstoneFirst = apply(tombstoneTamper.store);
  acknowledgePair(tombstoneTamper.store, tombstoneFirst, NOW + 10);
  applyVersion(tombstoneTamper.store, 2, { seats: 50 });
  assert.ok(tombstoneTamper.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
  ).get().n > 0);
  tombstoneTamper.db.exec(`DELETE FROM connected_ack_archive_mutations
    WHERE event_seq = (SELECT MIN(event_seq) FROM connected_ack_archive_mutations)`);
  assertIntegrityFailure(
    () => tombstoneTamper.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
    'removing an archive mutation tombstone must invalidate the ledger',
  );

  const ackAuditTamper = harness();
  const ackFirst = apply(ackAuditTamper.store);
  acknowledgePair(ackAuditTamper.store, ackFirst, NOW + 10);
  ackAuditTamper.db.exec(`UPDATE audit SET entry = '{}'
    WHERE seq = (SELECT MAX(seq) FROM audit
      WHERE action = 'CONNECTED_ENTITLEMENT_ACKNOWLEDGED')`);
  assertIntegrityFailure(
    () => ackAuditTamper.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 20 }),
    'a pair cannot outlive its exact ACK audit evidence',
  );
});

test('entitlement verification failure rolls back the earlier registry write and every ACK', () => {
  const env = harness();
  const wrong = crypto.generateKeyPairSync('ed25519');
  assert.throws(() => apply(env.store, {
    signedEntitlementArtifact: signedEntitlement(entitlement(), wrong.privateKey),
  }), (error) => error && error.code === 'invalid_signature');
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_online_registry_state').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
});

test('a warmed TEMP registry collision blocks the composite before either authority writes', () => {
  const env = harness();
  env.db.exec('CREATE TEMP TABLE connected_online_registry_state (customer_id TEXT)');

  assert.throws(
    () => apply(env.store),
    (error) => error && error.code === 'CONNECTED_REGISTRY_INTEGRITY',
  );
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM main.connected_online_registry_state',
  ).get().n, 0);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM main.connected_entitlement_state',
  ).get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM main.connected_ack_outbox').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM main.audit').get().n, 0);
});

test('audit append failure rolls back both authority states and the ordered ACK outbox', () => {
  const env = harness();
  env.failAudit('CONNECTED_ENTITLEMENT_APPLIED', 'forced composite audit failure');
  assert.throws(() => apply(env.store), /forced composite audit failure/);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_online_registry_state').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
});

test('a failed failure-state audit latches composite reads and enforcement fail-closed', () => {
  const env = harness();
  apply(env.store);
  env.failAudit('CONNECTED_ENTITLEMENT_FAILURE_RECORDED', 'forced failure audit rejection');
  assert.throws(() => env.store.recordFailure({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    failureClass: 'protocol_rejected',
    nowMs: NOW + 1000,
  }), /forced failure audit rejection/);
  assert.throws(
    () => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
    (error) => error && error.code === 'CONNECTED_HEARTBEAT_INTEGRITY',
  );
  assert.throws(
    () => env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 1001 }),
    (error) => error && error.code === 'CONNECTED_HEARTBEAT_INTEGRITY',
  );
});

test('unhealthy external audit high-water blocks composite mutation and authorization reads', () => {
  const env = harness();
  apply(env.store);
  env.setAuditHealthy(false);
  assert.throws(
    () => env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 1 }),
    (error) => error && error.code === 'CONNECTED_HEARTBEAT_INTEGRITY',
  );
  assert.throws(
    () => apply(env.store, {
      signedOnlineRegistryVerdict: verdict({
        registryGeneration: 2,
        registryStateDigest: '2'.repeat(64),
        issuedAt: new Date(NOW + 1000).toISOString(),
      }),
      signedEntitlementArtifact: signedEntitlement(entitlement({
        messageId: '25394a93-c3b5-4a4b-8095-cb71bd6759b8',
        entitlementVersion: 2,
        previousVersion: 1,
        issuedAt: new Date(NOW + 1000).toISOString(),
      })),
      nowMs: NOW + 1000,
    }),
    (error) => error && error.code === 'CONNECTED_HEARTBEAT_INTEGRITY',
  );
  assert.equal(env.db.prepare('SELECT registry_generation AS value FROM connected_online_registry_state').get().value, 9);
  assert.equal(env.db.prepare('SELECT entitlement_version AS value FROM connected_entitlement_state').get().value, 1);
});

test('registry verification failure prevents entitlement and ACK writes', () => {
  const env = harness();
  const changed = verdict().replace(/.$/, (value) => (value === 'A' ? 'B' : 'A'));
  assert.throws(() => apply(env.store, {
    signedOnlineRegistryVerdict: changed,
  }));
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_online_registry_state').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 0);
});

test('null entitlement grants nothing even with an active registry verdict', () => {
  const env = harness();
  const result = apply(env.store, { signedEntitlementArtifact: null });
  assert.equal(result.entitlementMissing, true);
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 9);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 0);
  const disposition = env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 1,
    clock: { bootId: '1'.repeat(32), nowMs: 5001 },
  });
  assert.equal(disposition.protectedEgress, 'block');
  assert.equal(disposition.onlineRegistryGeneration, 9);
});

test('signed registry revoke remains most restrictive when entitlement is absent', () => {
  const env = harness();
  apply(env.store, {
    signedOnlineRegistryVerdict: verdict({
      status: 'revoked',
      registryStateDigest: 'a'.repeat(64),
    }),
    signedEntitlementArtifact: null,
  });
  const disposition = env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 1 });
  assert.equal(disposition.protectedEgress, 'block');
  assert.equal(disposition.reason, 'vendor_registry_revoked');
});

test('ACK capacity latches reductions and reserves two ordered escalation pairs', () => {
  const env = harness();
  const releaseCount = ACK_ORDINARY_PENDING_LIMIT / 2;
  for (let version = 1; version <= releaseCount; version += 1) {
    const generation = version + 8;
    const messageId = versionMessageId(version);
    apply(env.store, {
      signedOnlineRegistryVerdict: verdict({
        registryGeneration: generation,
        registryStateDigest: generationDigest(generation),
      }),
      signedEntitlementArtifact: signedEntitlement(entitlement({
        messageId,
        entitlementVersion: version,
        previousVersion: version - 1,
      })),
      nowMs: NOW + version,
      randomUUID: () => messageId,
      clock: { bootId: '1'.repeat(32), nowMs: 5000 + version },
    });
  }

  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE status = 'pending'`).get().n, ACK_ORDINARY_PENDING_LIMIT);
  assert.deepEqual(env.store.acknowledgementHealth(CUSTOMER_ID, DEPLOYMENT_ID), {
    ok: false,
    reason: 'connected_ack_backlog',
    pendingCount: ACK_ORDINARY_PENDING_LIMIT,
  });
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + releaseCount + 1,
  }).reason, 'connected_ack_backlog');
  assert.equal(env.createStore().acknowledgementHealth(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).reason, 'connected_ack_backlog');

  const reducedVersion = releaseCount + 1;
  const reducedGeneration = reducedVersion + 8;
  const reducedMessageId = versionMessageId(reducedVersion);
  const reducedVerdict = verdict({
    registryGeneration: reducedGeneration,
    registryStateDigest: generationDigest(reducedGeneration),
  });
  const reducedArtifact = signedEntitlement(entitlement({
    messageId: reducedMessageId,
    entitlementVersion: reducedVersion,
    previousVersion: reducedVersion - 1,
    seats: 24,
    features: [],
  }));
  env.failAudit('CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED', 'forced latch audit failure');
  assert.throws(() => apply(env.store, {
    signedOnlineRegistryVerdict: reducedVerdict,
    signedEntitlementArtifact: reducedArtifact,
    nowMs: NOW + reducedVersion,
    randomUUID: () => reducedMessageId,
    clock: { bootId: '1'.repeat(32), nowMs: 5000 + reducedVersion },
  }), /forced latch audit failure/);
  env.restoreAudit();
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), reducedGeneration - 1,
    'latch audit failure rolls the composite registry write back');
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n,
    ACK_ORDINARY_PENDING_LIMIT);

  const latched = apply(env.store, {
    signedOnlineRegistryVerdict: reducedVerdict,
    signedEntitlementArtifact: reducedArtifact,
    nowMs: NOW + reducedVersion,
    randomUUID: () => reducedMessageId,
    clock: { bootId: '1'.repeat(32), nowMs: 5000 + reducedVersion },
  });
  assert.equal(latched.entitlement.capacityRestricted, true);
  assert.equal(latched.entitlement.outboxes, null);
  assert.equal(env.store.entitlementVersion(CUSTOMER_ID, DEPLOYMENT_ID), releaseCount);
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE target_version = ?`).get(reducedVersion).n, 0,
  'an unapplied restriction cannot emit delivered or applied lifecycle claims');
  assert.deepEqual(JSON.parse(env.db.prepare(`SELECT state_json FROM connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).state_json).capacityRestriction, {
    entitlementVersion: reducedVersion,
    entitlementDigest: protocol.payloadDigest(
      reducedArtifact.payload, protocol.CHANNEL_KINDS.ENTITLEMENT,
    ),
    classification: 'seat_reduction',
  });
  assert.deepEqual(env.store.acknowledgementHealth(CUSTOMER_ID, DEPLOYMENT_ID), {
    ok: false,
    reason: 'connected_entitlement_capacity_restriction',
    entitlementVersion: reducedVersion,
    classification: 'seat_reduction',
  });
  assert.deepEqual(env.createStore().acknowledgementHealth(CUSTOMER_ID, DEPLOYMENT_ID), {
    ok: false,
    reason: 'connected_entitlement_capacity_restriction',
    entitlementVersion: reducedVersion,
    classification: 'seat_reduction',
  });

  const drainCount = ACK_ORDINARY_PENDING_LIMIT - ACK_BACKLOG_BLOCK_THRESHOLD + 2;
  const drainable = env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    nowMs: NOW + 100_000,
    limit: 100,
  });
  assert.equal(drainable.length >= drainCount, true);
  for (const row of drainable.slice(0, drainCount)) {
    env.store.recordAckResult(ackInput(row, NOW + 100_001));
  }
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE status = 'pending'`).get().n, ACK_BACKLOG_BLOCK_THRESHOLD - 2);
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 100_002,
  }).reason, 'connected_entitlement_capacity_restriction',
  'draining below the backlog threshold cannot clear the durable latch');

  const authoritySnapshot = () => JSON.stringify({
    registry: env.db.prepare(`SELECT * FROM connected_online_registry_state
      ORDER BY customer_id, deployment_id`).all(),
    entitlement: env.db.prepare(`SELECT * FROM connected_entitlement_state
      ORDER BY customer_id, deployment_id`).all(),
    acknowledgements: env.db.prepare(`SELECT * FROM connected_ack_outbox
      ORDER BY id`).all(),
    acknowledgementHealth: env.db.prepare(`SELECT * FROM connected_ack_health
      ORDER BY customer_id, deployment_id`).all(),
    archive: env.db.prepare(`SELECT * FROM connected_ack_archive
      ORDER BY customer_id, deployment_id, target_version, lifecycle_stage`).all(),
    archiveMutations: env.db.prepare(`SELECT * FROM connected_ack_archive_mutations
      ORDER BY customer_id, deployment_id, scope_seq`).all(),
    audit: env.db.prepare('SELECT seq, action, entry FROM audit ORDER BY seq').all(),
  });
  const assertLatchedRejection = (candidate, label, offset) => {
    const before = authoritySnapshot();
    const skippedGeneration = reducedGeneration + 1;
    const candidateArtifact = signedEntitlement(candidate);
    assert.throws(() => apply(env.store, {
      signedOnlineRegistryVerdict: verdict({
        registryGeneration: skippedGeneration,
        registryStateDigest: generationDigest(skippedGeneration),
      }),
      signedEntitlementArtifact: candidateArtifact,
      nowMs: NOW + 100_010 + offset,
      randomUUID: () => candidate.messageId,
      clock: { bootId: '1'.repeat(32), nowMs: 100_010 + offset },
    }), (error) => error?.code === 'connected_capacity_latch_conflict', label);
    assert.equal(authoritySnapshot(), before,
      `${label} cannot mutate either high-water, ACK/archive state, latch, or audit authority`);
    const restarted = env.createStore();
    assert.equal(restarted.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), reducedGeneration);
    assert.equal(restarted.entitlementVersion(CUSTOMER_ID, DEPLOYMENT_ID), releaseCount);
    assert.deepEqual(restarted.acknowledgementHealth(CUSTOMER_ID, DEPLOYMENT_ID), {
      ok: false,
      reason: 'connected_entitlement_capacity_restriction',
      entitlementVersion: reducedVersion,
      classification: 'seat_reduction',
    });
    assert.equal(restarted.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
      nowMs: NOW + 100_020 + offset,
    }).reason, 'connected_entitlement_capacity_restriction');
    assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
      WHERE target_version = ?`).get(candidate.entitlementVersion).n, 0);
  };

  assertLatchedRejection(entitlement({
    messageId: versionMessageId(reducedVersion + 100),
    entitlementVersion: reducedVersion + 1,
    previousVersion: releaseCount,
    seats: 100,
    features: ['policy', 'shadow_ai'],
  }), 'a higher active expansion cannot skip the latched reduction', 0);
  assertLatchedRejection(entitlement({
    messageId: versionMessageId(reducedVersion + 101),
    entitlementVersion: reducedVersion + 1,
    previousVersion: releaseCount,
    seats: 0,
    features: [],
  }), 'a higher stronger reduction cannot replace the exact latched release', 1);
  assertLatchedRejection(entitlement({
    messageId: versionMessageId(reducedVersion + 102),
    entitlementVersion: reducedVersion,
    previousVersion: releaseCount,
    seats: 23,
    features: [],
  }), 'a conflicting digest at the latched version cannot replace the exact release', 2);

  const beforeFailedExactRetry = authoritySnapshot();
  env.failAudit('CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED', 'forced exact retry audit failure');
  assert.throws(() => apply(env.store, {
    signedOnlineRegistryVerdict: reducedVerdict,
    signedEntitlementArtifact: reducedArtifact,
    nowMs: NOW + 100_030,
    randomUUID: () => reducedMessageId,
    clock: { bootId: '1'.repeat(32), nowMs: 100_030 },
  }), /forced exact retry audit failure/);
  env.restoreAudit();
  assert.equal(authoritySnapshot(), beforeFailedExactRetry,
    'failed exact retry rolls state, both ordered ACKs, latch clearing, and audit back together');
  assert.equal(env.createStore().disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 100_031,
  }).reason, 'connected_entitlement_capacity_restriction');

  const retried = apply(env.store, {
    signedOnlineRegistryVerdict: reducedVerdict,
    signedEntitlementArtifact: reducedArtifact,
    nowMs: NOW + 100_003,
    randomUUID: () => reducedMessageId,
    clock: { bootId: '1'.repeat(32), nowMs: 100_003 },
  });
  assert.equal(retried.registry.contactAdvanced, false);
  assert.equal(retried.entitlement.capacityRestricted, undefined);
  assert.equal(retried.entitlement.state.entitlementVersion, reducedVersion);
  assert.equal(retried.entitlement.state.entitlement.seats, 24);
  assert.deepEqual(retried.entitlement.state.entitlement.features, []);
  assert.deepEqual(env.db.prepare(`SELECT lifecycle_stage FROM connected_ack_outbox
    WHERE target_version = ? ORDER BY CASE lifecycle_stage WHEN 'delivered' THEN 0 ELSE 1 END`)
    .all(reducedVersion), [{ lifecycle_stage: 'delivered' }, { lifecycle_stage: 'applied' }]);

  let currentVersion = reducedVersion;
  for (let offset = 1; offset <= 10; offset += 1) {
    currentVersion += 1;
    const generation = currentVersion + 8;
    const messageId = versionMessageId(currentVersion);
    const successor = apply(env.store, {
      signedOnlineRegistryVerdict: verdict({
        registryGeneration: generation,
        registryStateDigest: generationDigest(generation),
      }),
      signedEntitlementArtifact: signedEntitlement(entitlement({
        messageId,
        entitlementVersion: currentVersion,
        previousVersion: currentVersion - 1,
        seats: 24,
        features: [],
      })),
      nowMs: NOW + 100_003 + offset,
      randomUUID: () => messageId,
      clock: { bootId: '1'.repeat(32), nowMs: 100_003 + offset },
    });
    if (offset === 1) {
      assert.equal(successor.entitlement.state.entitlementVersion, currentVersion,
        'a higher successor may apply only after the exact latched release commits');
    }
  }
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE status = 'pending'`).get().n, ACK_ORDINARY_PENDING_LIMIT);

  const pausedVersion = currentVersion + 1;
  const pausedMessageId = versionMessageId(pausedVersion);
  apply(env.store, {
    signedOnlineRegistryVerdict: verdict({
      registryGeneration: pausedVersion + 8,
      registryStateDigest: generationDigest(pausedVersion + 8),
    }),
    signedEntitlementArtifact: signedEntitlement(entitlement({
      messageId: pausedMessageId,
      entitlementVersion: pausedVersion,
      previousVersion: currentVersion,
      status: 'paused',
      seats: 24,
      features: [],
      fallbackUntil: null,
      reasonCode: 'manual_pause',
    })),
    nowMs: NOW + 200_000,
    randomUUID: () => pausedMessageId,
    clock: { bootId: '1'.repeat(32), nowMs: 200_000 },
  });
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE status = 'pending'`).get().n, ACK_ORDINARY_PENDING_LIMIT + 2);
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlement.entitlement.status, 'paused');

  const revokedVersion = pausedVersion + 1;
  const revokedMessageId = versionMessageId(revokedVersion);
  apply(env.store, {
    signedOnlineRegistryVerdict: verdict({
      registryGeneration: revokedVersion + 8,
      registryStateDigest: generationDigest(revokedVersion + 8),
    }),
    signedEntitlementArtifact: signedEntitlement(entitlement({
      messageId: revokedMessageId,
      entitlementVersion: revokedVersion,
      previousVersion: pausedVersion,
      status: 'revoked',
      seats: 24,
      features: [],
      fallbackUntil: null,
      reasonCode: 'manual_revoke',
    })),
    nowMs: NOW + 200_001,
    randomUUID: () => revokedMessageId,
    clock: { bootId: '1'.repeat(32), nowMs: 200_001 },
  });
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE status = 'pending'`).get().n, ACK_PENDING_HARD_LIMIT);
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlement.entitlement.status, 'revoked');

  const legacyFullVersion = revokedVersion + 1;
  const legacyFullMessageId = versionMessageId(legacyFullVersion);
  const legacyFullVerdict = verdict({
    registryGeneration: legacyFullVersion + 8,
    registryStateDigest: generationDigest(legacyFullVersion + 8),
  });
  const legacyFullArtifact = signedEntitlement(entitlement({
    messageId: legacyFullMessageId,
    entitlementVersion: legacyFullVersion,
    previousVersion: revokedVersion,
    status: 'revoked',
    seats: 24,
    features: [],
    fallbackUntil: null,
    reasonCode: 'manual_revoke',
  }));
  const legacyLatched = apply(env.store, {
    signedOnlineRegistryVerdict: legacyFullVerdict,
    signedEntitlementArtifact: legacyFullArtifact,
    nowMs: NOW + 200_002,
    randomUUID: () => legacyFullMessageId,
    clock: { bootId: '1'.repeat(32), nowMs: 200_002 },
  });
  assert.equal(legacyLatched.entitlement.capacityRestricted, true);
  assert.equal(env.store.entitlementVersion(CUSTOMER_ID, DEPLOYMENT_ID), revokedVersion);
  assert.equal(env.store.acknowledgementHealth(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).classification, 'capacity_restriction');

  const finalDrain = env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    nowMs: NOW + 250_000,
    limit: 6,
  });
  assert.equal(finalDrain.length, 6);
  for (const row of finalDrain) env.store.recordAckResult(ackInput(row, NOW + 250_001));
  const legacyApplied = apply(env.store, {
    signedOnlineRegistryVerdict: legacyFullVerdict,
    signedEntitlementArtifact: legacyFullArtifact,
    nowMs: NOW + 250_002,
    randomUUID: () => legacyFullMessageId,
    clock: { bootId: '1'.repeat(32), nowMs: 250_002 },
  });
  assert.equal(legacyApplied.entitlement.state.entitlementVersion, legacyFullVersion);
  assert.notEqual(env.store.acknowledgementHealth(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).reason, 'connected_entitlement_capacity_restriction');
});

test('exact registry replay does not advance registry contact or either high-water', () => {
  const env = harness();
  const first = apply(env.store);
  const auditCount = env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n;
  const replay = apply(env.store, { nowMs: NOW + 1000 });
  assert.equal(replay.registry.contactAdvanced, false);
  assert.equal(replay.contactAdvanced, false);
  assert.equal(replay.registry.state.lastContactAt, first.registry.state.lastContactAt);
  assert.equal(replay.entitlement.state.lastContactAt, first.entitlement.state.lastContactAt);
  assert.equal(replay.entitlement.state.trustedTimeMs, first.entitlement.state.trustedTimeMs);
  assert.equal(
    replay.entitlement.state.monotonicFallbackDeadlineMs,
    first.entitlement.state.monotonicFallbackDeadlineMs,
  );
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 9);
  assert.equal(env.store.entitlementVersion(CUSTOMER_ID, DEPLOYMENT_ID), 1);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 2);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, auditCount);
});

test('exact registry replay with null entitlement blocks without refreshing entitlement time', () => {
  const env = harness();
  const first = apply(env.store);
  const before = first.entitlement.state;
  const replay = apply(env.store, {
    signedEntitlementArtifact: null,
    nowMs: NOW + 1000,
  });
  const after = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlement;
  assert.equal(replay.registry.contactAdvanced, false);
  assert.equal(replay.applied, true);
  assert.equal(after.lastContactAt, before.lastContactAt);
  assert.equal(after.trustedTimeMs, before.trustedTimeMs);
  assert.equal(after.monotonicContactMs, before.monotonicContactMs);
  assert.equal(after.monotonicFallbackDeadlineMs, before.monotonicFallbackDeadlineMs);
  assert.equal(after.failureClass, 'protocol_rejected');
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 1001,
    clock: { bootId: '1'.repeat(32), nowMs: 5001 },
  }).protectedEgress, 'block');
});

test('exact registry replay can independently apply a newer entitlement without fresh registry contact', () => {
  const env = harness();
  const first = apply(env.store);
  const changed = entitlement({
    messageId: '985a77b8-dad6-4c1c-b67b-27ce433707ab',
    entitlementVersion: 2,
    previousVersion: 1,
  });
  const second = apply(env.store, {
    nowMs: NOW + 1000,
    signedEntitlementArtifact: signedEntitlement(changed),
    randomUUID: () => changed.messageId,
    clock: { bootId: '1'.repeat(32), nowMs: 6000 },
  });
  const state = env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.equal(second.registry.contactAdvanced, false);
  assert.equal(second.entitlement.idempotent, false);
  assert.equal(second.applied, true);
  assert.equal(state.registry.lastContactAt, first.registry.state.lastContactAt);
  assert.equal(state.entitlement.entitlementVersion, 2);
  assert.equal(state.entitlement.lastContactAt, new Date(NOW + 1000).toISOString());
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 4);

  const auditCount = env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n;
  const gap = entitlement({
    messageId: '731d4cf0-febc-4b37-a366-3f73e59fab65',
    entitlementVersion: 4,
    previousVersion: 1,
  });
  assert.throws(() => apply(env.store, {
    nowMs: NOW + 2000,
    signedEntitlementArtifact: signedEntitlement(gap),
    randomUUID: () => gap.messageId,
    clock: { bootId: '1'.repeat(32), nowMs: 7000 },
  }), (error) => error?.code === 'version_gap');
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 9);
  assert.equal(env.store.entitlementVersion(CUSTOMER_ID, DEPLOYMENT_ID), 2);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 4);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, auditCount);
});

test('ACK outbox exposes delivered first and refuses applied before delivery acceptance', () => {
  const env = harness();
  const result = apply(env.store);
  let pending = env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW,
  });
  assert.deepEqual(pending.map((item) => item.acknowledgement.lifecycleStage), ['delivered']);
  assert.equal(env.store.recordAckResult(ackInput(result.entitlement.outboxes.applied)), null);
  env.store.recordAckResult(ackInput(result.entitlement.outboxes.delivered));
  pending = env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 2,
  });
  assert.deepEqual(pending.map((item) => item.acknowledgement.lifecycleStage), ['applied']);
  env.store.recordAckResult(ackInput(result.entitlement.outboxes.applied, NOW + 3));
  assert.equal(env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 4,
  }).length, 0);
});
