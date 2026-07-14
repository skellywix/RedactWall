'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { MIGRATIONS } = require('../server/storage/migrations');
const {
  ACK_PENDING_HARD_LIMIT,
  createConnectedEntitlementStore,
} = require('../server/connected-entitlement-store');
const { keyFingerprint } = require('../server/vendor-signed-artifact');
const protocol = require('../server/vendor-control-protocol');

const CUSTOMER_ID = 'cu-store-1';
const DEPLOYMENT_ID = 'dep_44444444444444444444444444444444';
const NOW = Date.parse('2026-07-12T12:01:00.000Z');
const ARCHIVE_RETAINED_BOUND = 64;
const ARCHIVE_MUTATION_RETAINED_BOUND = 128;
const REFERENCE_KEY = Buffer.alloc(32, 7);
const AUDIT_KEY = Buffer.alloc(32, 8);
const onlineKeys = crypto.generateKeyPairSync('ed25519');
const offlineKeys = crypto.generateKeyPairSync('ed25519');
const KEY_ID = `rw-entitlement-${keyFingerprint(onlineKeys.publicKey)}`;

function entitlement(overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: '37b335ce-aa4e-4fe2-a6e9-dd63478e846b',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status: 'active', plan: 'enterprise', seats: 50, features: ['policy'],
    entitlementVersion: 1, previousVersion: 0,
    issuedAt: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-12T12:05:00.000Z',
    fallbackUntil: '2026-07-15T12:00:00.000Z',
    reasonCode: 'billing_active',
    ...overrides,
  };
}

function signedArtifact(payload = entitlement(), key = onlineKeys.privateKey, keyId = KEY_ID) {
  return {
    keyId,
    payload,
    signature: crypto.sign(null, protocol.signingInput(payload, keyId), key).toString('base64'),
  };
}

function offlineLicense(overrides = {}) {
  const payload = {
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    status: 'active',
    plan: 'enterprise',
    seats: 50,
    features: ['policy'],
    expires: '2026-07-20T00:00:00.000Z',
    graceDays: 0,
    ...overrides,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return {
    text: `${encoded}.${crypto.sign(null, Buffer.from(encoded), offlineKeys.privateKey).toString('base64')}`,
    publicKeyPem: offlineKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

function opaqueReference(kind, value) {
  return `${kind}_${crypto.createHmac('sha256', REFERENCE_KEY)
    .update(String(value)).digest('base64url').slice(0, 24)}`;
}

function auditMac(entry) {
  return crypto.createHmac('sha256', AUDIT_KEY)
    .update(protocol.canonicalJson(entry), 'utf8').digest('hex');
}

function harness(customerId = CUSTOMER_ID, deploymentId = DEPLOYMENT_ID, keyId = KEY_ID,
  forbiddenPublicKeyFingerprints = [], receivers = null, databasePath = ':memory:',
  driverFactory = null, beforeCreateStore = null) {
  const db = new Database(databasePath);
  db.pragma('foreign_keys = ON');
  const initialized = db.prepare(`SELECT 1 AS present FROM sqlite_schema
    WHERE type = 'table' AND name = 'connected_ack_health'`).get();
  if (!initialized) {
    db.exec('CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, entry TEXT NOT NULL)');
    db.exec(MIGRATIONS.find((migration) => migration.version === 11).sqlite);
    db.exec(MIGRATIONS.find((migration) => migration.version === 13).sqlite);
  }
  const appendAudit = (event) => {
    const body = {
      action: event.action,
      actor: event.actor,
      detail: event.detail,
      ...(event.connectedAuthorityRef
        ? { connectedAuthorityRef: event.connectedAuthorityRef } : {}),
      ...(event.connectedAckRef ? { connectedAckRef: event.connectedAckRef } : {}),
    };
    const entry = { ...body, mac: auditMac(body) };
    db.prepare('INSERT INTO audit (action, entry) VALUES (?, ?)').run(event.action, JSON.stringify(entry));
    return entry;
  };
  const verifyAuditEntry = (entry) => {
    if (!entry || typeof entry !== 'object') return false;
    const { mac, ...body } = entry;
    return typeof mac === 'string' && mac === auditMac(body);
  };
  const driver = driverFactory ? driverFactory(db) : db;
  if (beforeCreateStore) beforeCreateStore(db, driver);
  const createStore = () => createConnectedEntitlementStore({
      customerId,
      deploymentId,
      driver,
      appendAudit: observedCallback('appendAudit', appendAudit, receivers),
      authorityReference: observedCallback('authorityReference', (customerId, deploymentId) => opaqueReference(
        'connected', `${customerId}\0${deploymentId}`,
      ), receivers),
      ackReference: observedCallback('ackReference', (ackId) => opaqueReference('ack', ackId), receivers),
      verifyAuditState: observedCallback('verifyAuditState', () => ({ ok: true }), receivers),
      verifyAuditEntry: observedCallback('verifyAuditEntry', verifyAuditEntry, receivers),
      verificationKeys: observedCallback('verificationKeys', () => ({
        publicKeys: { [keyId]: onlineKeys.publicKey },
        offlineKeyFingerprint: keyFingerprint(offlineKeys.publicKey),
        forbiddenPublicKeyFingerprints,
      }), receivers),
      offlinePublicKey: observedCallback('offlinePublicKey', () => offlineKeys.publicKey
        .export({ type: 'spki', format: 'pem' }).toString(), receivers),
    });
  return { appendAudit, db, createStore, store: createStore() };
}

function commitResponseLossDriver(db, control) {
  return {
    kind: db.kind,
    prepare: db.prepare.bind(db),
    transaction(callback) {
      const transaction = db.transaction(callback);
      return (...args) => {
        const result = transaction(...args);
        if (control.failNext === true) {
          control.failNext = false;
          throw new Error('simulated transaction response loss after commit');
        }
        return result;
      };
    },
  };
}

function compactionFaultDriver(db, control) {
  return {
    kind: db.kind,
    prepare(sql) {
      const statement = db.prepare(sql);
      const normalized = sql.trim().replace(/\s+/g, ' ');
      let operation = null;
      if (/^INSERT INTO (?:main\.|public\.)?connected_ack_archive \(id,/.test(normalized)) {
        operation = 'archiveInsert';
      } else if (/^DELETE FROM (?:main\.|public\.)?connected_ack_archive WHERE archive_seq/
        .test(normalized)) {
        operation = 'archiveDelete';
      } else if (/^DELETE FROM (?:main\.|public\.)?connected_ack_archive_mutations WHERE event_seq/
        .test(normalized)) {
        operation = 'mutationDelete';
      }
      const invoke = (method, args) => {
          if (operation) {
            const callsKey = `${operation}Calls`;
            control[callsKey] = (control[callsKey] || 0) + 1;
            if (control[`${operation}FailureAt`] === control[callsKey]) {
              throw new Error(`forced ${operation} interruption`);
            }
          }
          return statement[method](...args);
      };
      return {
        get: (...args) => invoke('get', args),
        all: (...args) => invoke('all', args),
        run: (...args) => invoke('run', args),
      };
    },
    transaction: db.transaction.bind(db),
  };
}

function archiveFirstAcknowledgementPair(env) {
  const first = apply(env.store);
  acknowledgeInOrder(env.store, first);
  apply(env.store, entitlement({
    messageId: '6c1dba8d-fdb1-4cbc-8878-a37e83a14f6e',
    entitlementVersion: 2,
    previousVersion: 1,
  }), NOW + 2000);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n, 2);
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementVersion, 2);
  return first;
}

function applyAcknowledgedReleases(env, releaseCount) {
  let result = apply(env.store);
  acknowledgeInOrder(env.store, result, NOW + 10);
  for (let version = 2; version <= releaseCount; version += 1) {
    result = apply(env.store, entitlement({
      messageId: versionMessageId(10_000 + version),
      entitlementVersion: version,
      previousVersion: version - 1,
    }), NOW + (version * 10));
    acknowledgeInOrder(env.store, result, NOW + (version * 10) + 1);
  }
  return result;
}

function insertForgedArchiveRow(db) {
  db.exec(`INSERT INTO connected_ack_archive
    (id, customer_id, deployment_id, target_kind, target_version, target_digest,
     lifecycle_stage, payload_json, payload_digest, status, failure_class, attempts,
     next_attempt_at, created_at, updated_at, archived_at)
    SELECT id || '-forged', customer_id, deployment_id, target_kind,
      target_version + 100000, target_digest, lifecycle_stage, payload_json,
      payload_digest, status, failure_class, attempts, next_attempt_at,
      created_at, updated_at, archived_at
    FROM connected_ack_archive ORDER BY archive_seq LIMIT 1`);
}

function observedCallback(name, callback, receivers) {
  if (!receivers) return callback;
  return function observed(...args) {
    receivers.push([name, this]);
    return Reflect.apply(callback, undefined, args);
  };
}

function apply(store, value = entitlement(), nowMs = NOW, key = onlineKeys.privateKey) {
  return store.applyEntitlement({
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    signedArtifact: signedArtifact(value, key),
    nowMs,
    randomUUID: () => value.messageId,
  });
}

function ackResultInput(result, overrides = {}, lifecycleStage = 'delivered') {
  const outbox = result.outboxes[lifecycleStage];
  const value = {
    id: outbox.id,
    customerId: outbox.customerId,
    deploymentId: outbox.deploymentId,
    payloadDigest: outbox.payloadDigest,
    accepted: true,
    nowMs: NOW + 1000,
    ...overrides,
  };
  if (value.accepted === false && value.failureClass === undefined) {
    value.failureClass = 'transport_unavailable';
  }
  return value;
}

function acknowledgeInOrder(store, result, nowMs = NOW + 1000) {
  store.recordAckResult(ackResultInput(result, { nowMs }, 'delivered'));
  return store.recordAckResult(ackResultInput(result, { nowMs: nowMs + 1 }, 'applied'));
}

function versionMessageId(version) {
  return `00000000-0000-4000-8000-${version.toString(16).padStart(12, '0')}`;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function seededAcknowledgement(version, lifecycleStage, targetDigest, timestamp) {
  return protocol.assertChannel({
    schemaVersion: 1,
    messageId: versionMessageId((version * 2) + (lifecycleStage === 'applied' ? 1 : 0)),
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    targetVersion: version,
    targetDigest,
    lifecycleStage,
    outcome: 'success',
    reasonCode: lifecycleStage,
    recordedAt: timestamp,
  }, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
}

function seededAckRow(acknowledgement, status, timestamp) {
  const payloadJson = protocol.canonicalJson(acknowledgement);
  return {
    id: acknowledgement.messageId,
    customerId: acknowledgement.customerId,
    deploymentId: acknowledgement.deploymentId,
    targetKind: acknowledgement.targetKind,
    targetVersion: acknowledgement.targetVersion,
    targetDigest: acknowledgement.targetDigest,
    lifecycleStage: acknowledgement.lifecycleStage,
    payloadJson,
    payloadDigest: sha256(payloadJson),
    status,
    failureClass: null,
    attempts: status === 'acknowledged' ? 1 : 0,
    nextAttemptAt: timestamp,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function appendSeededAckAudit(env, row) {
  const authorityRef = opaqueReference('connected', `${CUSTOMER_ID}\0${DEPLOYMENT_ID}`);
  const ackRef = opaqueReference('ack', row.id);
  env.appendAudit({
    action: row.status === 'acknowledged'
      ? 'CONNECTED_ENTITLEMENT_ACKNOWLEDGED' : 'CONNECTED_ENTITLEMENT_ACK_QUEUED',
    actor: 'vendor_connector',
    connectedAuthorityRef: authorityRef,
    connectedAckRef: ackRef,
    detail: JSON.stringify({
      authorityRef,
      ackRef,
      entitlementVersion: row.targetVersion,
      digest: row.targetDigest,
      targetKind: row.targetKind,
      lifecycleStage: row.lifecycleStage,
      payloadDigest: row.payloadDigest,
      status: row.status,
      failureClass: null,
      attempts: row.attempts,
      nextAttemptAt: row.nextAttemptAt,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    }),
  });
}

function seededPendingRecord(row) {
  return {
    id: row.id,
    targetKind: row.targetKind,
    targetVersion: row.targetVersion,
    targetDigest: row.targetDigest,
    lifecycleStage: row.lifecycleStage,
    payloadDigest: row.payloadDigest,
    failureClass: null,
    attempts: row.attempts,
    nextAttemptAt: row.nextAttemptAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function seededHistoricalRecord(row) {
  return { ...seededPendingRecord(row), status: row.status };
}

function insertSeededAckRow(env, insertAck, row) {
  insertAck.run(row);
  appendSeededAckAudit(env, row);
}

function seedLongPartialRecovery(env, releaseCount) {
  const timestamp = new Date(NOW).toISOString();
  const finalEntitlement = entitlement({
    messageId: versionMessageId((releaseCount * 2) + 2),
    entitlementVersion: releaseCount,
    previousVersion: releaseCount - 1,
  });
  const finalDigest = protocol.payloadDigest(finalEntitlement, protocol.CHANNEL_KINDS.ENTITLEMENT);
  const state = {
    stateVersion: 1,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    connectedEver: true,
    highWaterIntact: true,
    entitlementVersion: releaseCount,
    entitlementDigest: finalDigest,
    signingKeyId: KEY_ID,
    entitlement: finalEntitlement,
    appliedAt: timestamp,
    lastContactAt: timestamp,
    trustedTimeMs: NOW,
    monotonicBootId: '1'.repeat(32),
    monotonicContactMs: 5000,
    monotonicFallbackDeadlineMs: 5001,
    failureClass: null,
  };
  const authorityRef = opaqueReference('connected', `${CUSTOMER_ID}\0${DEPLOYMENT_ID}`);
  const pending = [];
  const historical = [];
  const insertAck = env.db.prepare(`INSERT INTO connected_ack_outbox
    (id, customer_id, deployment_id, target_kind, target_version, target_digest,
     lifecycle_stage, payload_json, payload_digest, status, failure_class, attempts,
     next_attempt_at, created_at, updated_at)
    VALUES (@id, @customerId, @deploymentId, @targetKind, @targetVersion, @targetDigest,
     @lifecycleStage, @payloadJson, @payloadDigest, @status, @failureClass, @attempts,
     @nextAttemptAt, @createdAt, @updatedAt)`);
  env.db.transaction(() => {
    env.db.prepare(`INSERT INTO connected_entitlement_state
      (customer_id, deployment_id, authority_ref, entitlement_version,
       entitlement_digest, state_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(CUSTOMER_ID, DEPLOYMENT_ID, authorityRef, releaseCount,
        finalDigest, protocol.canonicalJson(state), timestamp);
    env.appendAudit({
      action: 'CONNECTED_ENTITLEMENT_APPLIED',
      actor: 'vendor_connector',
      connectedAuthorityRef: authorityRef,
      detail: JSON.stringify({
        authorityRef,
        entitlementVersion: releaseCount,
        status: finalEntitlement.status,
        digest: finalDigest,
        stateDigest: sha256(protocol.canonicalJson(state)),
        signingKeyId: KEY_ID,
        signatureDomain: protocol.SIGNATURE_DOMAINS[protocol.CHANNEL_KINDS.ENTITLEMENT],
      }),
    });
    for (let version = 1; version <= releaseCount; version += 1) {
      const targetDigest = version === releaseCount
        ? finalDigest : sha256(`seeded-entitlement-${version}`);
      const delivered = seededAckRow(
        seededAcknowledgement(version, 'delivered', targetDigest, timestamp),
        'acknowledged', timestamp,
      );
      const applied = seededAckRow(
        seededAcknowledgement(version, 'applied', targetDigest, timestamp),
        'pending', timestamp,
      );
      insertSeededAckRow(env, insertAck, delivered);
      insertSeededAckRow(env, insertAck, applied);
      historical.push(seededHistoricalRecord(delivered));
      pending.push(seededPendingRecord(applied));
    }
    const ledger = {
      stateVersion: 4,
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      pendingCount: pending.length,
      pendingDigest: sha256(protocol.canonicalJson(pending)),
      historicalCount: historical.length,
      historicalDigest: sha256(protocol.canonicalJson(historical)),
      archivedCount: 0,
      archivedDigest: sha256('redactwall.connected-ack-archive.empty.v2'),
      archivedPrefixCount: 0,
      archivedPrefixHighWater: 0,
      archivedPrefixDigest: sha256('redactwall.connected-ack-archive.empty.v2'),
      archiveMutationCount: 0,
      archiveMutationHighWater: 0,
      archiveMutationDigest: sha256('redactwall.connected-ack-archive-mutations.empty.v2'),
      archiveMutationPrefixCount: 0,
      archiveMutationPrefixHighWater: 0,
      archiveMutationPrefixDigest: sha256('redactwall.connected-ack-archive-mutations.empty.v2'),
      terminal: null,
      capacityRestriction: null,
    };
    env.db.prepare(`INSERT INTO connected_ack_health
      (customer_id, deployment_id, authority_ref, state_json, updated_at)
      VALUES (?, ?, ?, ?, ?)`)
      .run(CUSTOMER_ID, DEPLOYMENT_ID, authorityRef, protocol.canonicalJson(ledger), timestamp);
    env.appendAudit({
      action: 'CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED',
      actor: 'vendor_connector',
      connectedAuthorityRef: authorityRef,
      detail: JSON.stringify({
        authorityRef,
        stateDigest: sha256(protocol.canonicalJson(ledger)),
        entitlementVersion: releaseCount,
        pendingCount: pending.length,
        historicalCount: historical.length,
        archivedCount: 0,
        archivedPrefixCount: 0,
        archivedPrefixHighWater: 0,
        archivedPrefixDigest: sha256('redactwall.connected-ack-archive.empty.v2'),
        archiveMutationCount: 0,
        archiveMutationHighWater: 0,
        archiveMutationDigest: sha256('redactwall.connected-ack-archive-mutations.empty.v2'),
        archiveMutationPrefixCount: 0,
        archiveMutationPrefixHighWater: 0,
        archiveMutationPrefixDigest: sha256('redactwall.connected-ack-archive-mutations.empty.v2'),
        terminalFailureClass: null,
        capacityRestriction: null,
      }),
    });
  })();
  return { finalEntitlement, finalDigest };
}

function seededAckResultInput(env, version, overrides = {}) {
  const row = env.db.prepare(`SELECT id, customer_id, deployment_id, payload_digest
    FROM connected_ack_outbox WHERE target_version = ? AND lifecycle_stage = 'applied'`).get(version);
  return {
    id: row.id,
    customerId: row.customer_id,
    deploymentId: row.deployment_id,
    payloadDigest: row.payload_digest,
    accepted: true,
    nowMs: NOW + 1000,
    ...overrides,
  };
}

test('signed state, authenticated audit anchor, and ACK outbox commit atomically', () => {
  const env = harness();
  const result = apply(env.store);
  assert.equal(result.state.entitlementVersion, 1);
  assert.equal(result.state.signingKeyId, KEY_ID);
  assert.equal(result.outboxes.delivered.status, 'pending');
  assert.equal(result.outboxes.applied.status, 'pending');
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementDigest, result.state.entitlementDigest);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 1);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 2);
  assert.deepEqual(env.db.prepare('SELECT action FROM audit ORDER BY seq').all().map((row) => row.action), [
    'CONNECTED_ENTITLEMENT_APPLIED',
    'CONNECTED_ENTITLEMENT_ACK_QUEUED',
    'CONNECTED_ENTITLEMENT_ACK_QUEUED',
    'CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED',
  ]);
});

test('store option callbacks never receive the entitlement context as receiver', () => {
  const receivers = [];
  const env = harness(CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], receivers);
  apply(env.store);
  env.store.recordFailure({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    failureClass: 'transport_unavailable',
    nowMs: NOW + 1000,
  });
  env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 1001,
    offlineLicenseText: offlineLicense().text,
  });
  assert.deepEqual(new Set(receivers.map(([name]) => name)), new Set([
    'appendAudit', 'authorityReference', 'ackReference', 'verifyAuditState',
    'verifyAuditEntry', 'verificationKeys', 'offlinePublicKey',
  ]));
  assert.equal(receivers.every(([, receiver]) => receiver === undefined), true);
});

test('unsigned, wrong-key, and post-signature mutations create no durable authority', () => {
  const env = harness();
  const wrong = crypto.generateKeyPairSync('ed25519');
  assert.throws(() => apply(env.store, entitlement(), NOW, wrong.privateKey), (error) => error.code === 'invalid_signature');
  assert.throws(() => env.store.applyEntitlement({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    entitlement: entitlement(),
    nowMs: NOW,
  }), (error) => error.code === 'invalid_schema');
  const artifact = signedArtifact();
  artifact.payload.seats = 500;
  assert.throws(() => env.store.applyEntitlement({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedArtifact: artifact,
    nowMs: NOW,
  }), (error) => error.code === 'invalid_signature');
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
});

test('online-verdict key identities cannot be reused for signed entitlements', () => {
  const keyId = 'rw-online-verdict-current';
  const env = harness(CUSTOMER_ID, DEPLOYMENT_ID, keyId);
  assert.throws(
    () => env.store.applyEntitlement({
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      signedArtifact: signedArtifact(entitlement(), onlineKeys.privateKey, keyId),
      nowMs: NOW,
    }),
    (error) => error && error.code === 'vendor_key_purpose_mismatch',
  );
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 0);
});

test('an entitlement-prefixed key cannot reuse the online-verdict public identity', () => {
  const env = harness(CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [keyFingerprint(onlineKeys.publicKey)]);
  assert.throws(
    () => apply(env.store),
    (error) => error && error.code === 'vendor_key_identity_reused',
  );
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 0);
});

test('audit failure rolls back high-water and acknowledgement together', () => {
  const env = harness();
  env.db.exec(`
    CREATE TRIGGER reject_connected_audit BEFORE INSERT ON audit
    WHEN NEW.action = 'CONNECTED_ENTITLEMENT_APPLIED'
    BEGIN SELECT RAISE(ABORT, 'forced connected audit failure'); END;
  `);
  assert.throws(() => apply(env.store), /forced connected audit failure/);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 0);
  env.db.exec('DROP TRIGGER reject_connected_audit');
  assert.equal(apply(env.store).state.entitlementVersion, 1);
});

test('a preseeded future ACK cannot capture a signed entitlement apply', () => {
  const env = harness();
  apply(env.store);
  const next = entitlement({
    messageId: 'c0b96680-3d24-4655-9360-460accee1f61',
    entitlementVersion: 2,
    previousVersion: 1,
  });
  const targetDigest = protocol.payloadDigest(next, protocol.CHANNEL_KINDS.ENTITLEMENT);
  const planted = protocol.assertChannel({
    schemaVersion: 1,
    messageId: next.messageId,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    targetVersion: 2,
    targetDigest,
    lifecycleStage: 'applied',
    outcome: 'success',
    reasonCode: 'applied',
    recordedAt: new Date(NOW + 1000).toISOString(),
  }, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
  const payloadJson = protocol.canonicalJson(planted);
  env.db.prepare(`INSERT INTO connected_ack_outbox
    (id, customer_id, deployment_id, target_kind, target_version, target_digest,
     lifecycle_stage, payload_json, payload_digest, status, attempts,
     next_attempt_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 'applied', ?, ?, 'pending', 0, ?, ?, ?)`)
    .run(
      planted.messageId,
      CUSTOMER_ID,
      DEPLOYMENT_ID,
      planted.targetKind,
      planted.targetVersion,
      planted.targetDigest,
      payloadJson,
      crypto.createHash('sha256').update(payloadJson).digest('hex'),
      new Date(NOW + 1000).toISOString(),
      new Date(NOW + 1000).toISOString(),
      new Date(NOW + 1000).toISOString(),
    );
  assert.throws(() => apply(env.store, next, NOW + 1000), integrityFailure);
  const durableState = JSON.parse(env.db.prepare(`SELECT state_json
    FROM connected_entitlement_state`).get().state_json);
  assert.equal(durableState.entitlementVersion, 1);
  assert.throws(() => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM audit
    WHERE connected_entry_action = 'CONNECTED_ENTITLEMENT_APPLIED'`).get().n, 1);
});

test('same-version redelivery preserves one immutable already-acknowledged event', () => {
  const env = harness();
  const first = apply(env.store);
  acknowledgeInOrder(env.store, first);
  const duplicate = apply(env.store, entitlement(), NOW + 2000);
  assert.equal(duplicate.idempotent, true);
  assert.equal(duplicate.outbox.id, first.outbox.id);
  assert.equal(duplicate.outbox.payloadDigest, first.outbox.payloadDigest);
  assert.equal(duplicate.outbox.status, 'acknowledged');
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 2);
  assert.equal(env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 2000,
  }).length, 0);
});

test('stale or cross-tenant ACK completion cannot consume a pending event', () => {
  const env = harness();
  const first = apply(env.store);
  assert.equal(env.store.recordAckResult(ackResultInput(first, { payloadDigest: '0'.repeat(64) })), null);
  assert.throws(
    () => env.store.recordAckResult(ackResultInput(first, { customerId: 'cu-store-2' })),
    (error) => error.code === 'customer_mismatch',
  );
  assert.equal(env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 1000,
  }).length, 1);
});

test('late completion of an older ACK cannot replace the current ACK integrity anchor', () => {
  const env = harness();
  const first = apply(env.store);
  const secondValue = entitlement({
    messageId: 'cf4113de-c6eb-4651-ad20-aa8d86986462',
    entitlementVersion: 2,
    previousVersion: 1,
  });
  const second = apply(env.store, secondValue, NOW + 1000);
  assert.equal(second.state.entitlementVersion, 2);
  acknowledgeInOrder(env.store, first, NOW + 2000);
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementVersion, 2);
});

test('table and authenticated-audit tamper are rejected on authorization reads', () => {
  const env = harness();
  apply(env.store);
  const row = env.db.prepare(`SELECT state_json FROM connected_entitlement_state
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID);
  const changed = JSON.parse(row.state_json);
  changed.entitlement.seats = 500;
  changed.entitlementDigest = protocol.payloadDigest(changed.entitlement, protocol.CHANNEL_KINDS.ENTITLEMENT);
  env.db.prepare(`UPDATE connected_entitlement_state SET entitlement_digest = ?, state_json = ?
    WHERE customer_id = ? AND deployment_id = ?`).run(
    changed.entitlementDigest, protocol.canonicalJson(changed), CUSTOMER_ID, DEPLOYMENT_ID,
  );
  assert.throws(() => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);

  const fresh = harness();
  apply(fresh.store);
  const audit = fresh.db.prepare(`SELECT seq, entry FROM audit
    WHERE action = 'CONNECTED_ENTITLEMENT_APPLIED'`).get();
  const forged = JSON.parse(audit.entry);
  const detail = JSON.parse(forged.detail);
  detail.stateDigest = '0'.repeat(64);
  forged.detail = JSON.stringify(detail);
  fresh.db.prepare('UPDATE audit SET entry = ? WHERE seq = ?').run(JSON.stringify(forged), audit.seq);
  assert.throws(() => fresh.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);
});

test('hiding the newest pause audit through its physical action cannot authorize a rewind', () => {
  const env = harness();
  apply(env.store);
  const active = env.db.prepare(`SELECT authority_ref, entitlement_version,
    entitlement_digest, state_json, updated_at FROM connected_entitlement_state`).get();
  apply(env.store, entitlement({
    messageId: 'bfdf8d45-e044-460a-b743-30087549e394',
    status: 'paused',
    entitlementVersion: 2,
    previousVersion: 1,
    fallbackUntil: null,
    reasonCode: 'manual_pause',
  }), NOW + 1000);
  const pauseAudit = env.db.prepare(`SELECT seq FROM audit
    WHERE action = 'CONNECTED_ENTITLEMENT_APPLIED' ORDER BY seq DESC LIMIT 1`).get();
  env.db.prepare("UPDATE audit SET action = 'HIDDEN_PAUSE' WHERE seq = ?").run(pauseAudit.seq);
  env.db.prepare(`UPDATE connected_entitlement_state SET authority_ref = ?,
    entitlement_version = ?, entitlement_digest = ?, state_json = ?, updated_at = ?`).run(
    active.authority_ref,
    active.entitlement_version,
    active.entitlement_digest,
    active.state_json,
    active.updated_at,
  );
  assert.throws(() => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);
});

test('missing or cross-bound ACK payload is detected as integrity failure', () => {
  const removed = harness();
  apply(removed.store);
  removed.db.prepare('DELETE FROM connected_ack_outbox').run();
  assert.throws(() => removed.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);

  const changed = harness();
  apply(changed.store);
  const row = changed.db.prepare('SELECT id, payload_json FROM connected_ack_outbox').get();
  const payload = JSON.parse(row.payload_json);
  payload.customerId = 'cu-store-2';
  const json = protocol.canonicalJson(payload);
  changed.db.prepare('UPDATE connected_ack_outbox SET payload_json = ?, payload_digest = ? WHERE id = ?')
    .run(json, crypto.createHash('sha256').update(json).digest('hex'), row.id);
  assert.throws(() => changed.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);
});

test('pending ACK delivery requires an exact authenticated outbox anchor', () => {
  const fake = harness();
  apply(fake.store);
  const source = fake.db.prepare(`SELECT * FROM connected_ack_outbox
    WHERE lifecycle_stage = 'delivered'`).get();
  const payload = {
    ...JSON.parse(source.payload_json),
    messageId: '52b4a637-93d0-4d4a-b8f3-17fc0d2c7249',
    targetDigest: 'f'.repeat(64),
  };
  const payloadJson = protocol.canonicalJson(payload);
  fake.db.prepare(`INSERT INTO connected_ack_outbox
    (id, customer_id, deployment_id, target_kind, target_version, target_digest,
     lifecycle_stage, payload_json, payload_digest, status, attempts,
     next_attempt_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 'delivered', ?, ?, 'pending', 0, ?, ?, ?)`)
    .run(
      payload.messageId,
      CUSTOMER_ID,
      DEPLOYMENT_ID,
      payload.targetKind,
      payload.targetVersion,
      payload.targetDigest,
      payloadJson,
      crypto.createHash('sha256').update(payloadJson).digest('hex'),
      source.next_attempt_at,
      source.created_at,
      source.updated_at,
    );
  assert.throws(() => fake.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 1000,
  }), integrityFailure);

  const forgedDelivery = harness();
  apply(forgedDelivery.store);
  forgedDelivery.db.prepare(`UPDATE connected_ack_outbox SET status = 'acknowledged'
    WHERE lifecycle_stage = 'delivered'`).run();
  assert.throws(() => forgedDelivery.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 1000,
  }), integrityFailure);
});

test('authenticated ACK retry state rejects failure class, attempts, and timestamp tamper', () => {
  for (const mutation of [
    "failure_class = 'transport_unavailable'",
    "attempts = attempts + 7",
    "next_attempt_at = '9999-12-31T23:59:59.999Z'",
    "created_at = '9999-12-31T23:59:59.999Z'",
    "updated_at = '9999-12-31T23:59:59.999Z'",
  ]) {
    const env = harness();
    const first = apply(env.store);
    const second = apply(env.store, entitlement({
      messageId: '217a04ab-e579-4f34-858f-cb1825a7c845',
      entitlementVersion: 2,
      previousVersion: 1,
    }), NOW + 1000);
    assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementVersion, 2);
    assert.equal(second.outboxes.delivered.status, 'pending');

    env.db.prepare(`UPDATE connected_ack_outbox SET ${mutation} WHERE id = ?`)
      .run(first.outboxes.delivered.id);

    assert.throws(() => env.store.listPendingAcknowledgements({
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      nowMs: NOW + 2000,
    }), integrityFailure, `${mutation} cannot hide an older lifecycle event`);
  }
});

test('ACK completion reverifies the exact anchor after enumeration', () => {
  const env = harness();
  const applied = apply(env.store);
  const [pending] = env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 1000,
  });
  env.db.prepare(`UPDATE connected_ack_outbox SET status = 'acknowledged'
    WHERE id = ?`).run(pending.id);
  assert.throws(() => env.store.recordAckResult({
    id: pending.id,
    customerId: pending.customerId,
    deploymentId: pending.deploymentId,
    payloadDigest: pending.payloadDigest,
    accepted: true,
    nowMs: NOW + 1001,
  }), integrityFailure);
  assert.equal(applied.state.entitlementVersion, 1);
});

test('failure state is anchored and only genuine outage plus a signed offline license can fall back', () => {
  const env = harness();
  apply(env.store);
  env.store.recordFailure({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    failureClass: 'transport_unavailable',
    nowMs: NOW + 1000,
  });
  const degraded = env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: Date.parse('2026-07-13T12:00:00.000Z'),
    offlineLicenseText: offlineLicense().text,
  });
  assert.equal(degraded.mode, 'degraded_fallback');

  env.store.recordFailure({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    failureClass: 'invalid_signature',
    nowMs: NOW + 2000,
  });
  assert.equal(env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 3000,
    offlineLicenseText: offlineLicense().text,
  }).reason, 'fallback_failure_not_transport');
});

test('a file-backed connected pause survives restart and outranks an active offline outage artifact', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-connected-pause-'));
  const databasePath = path.join(tempRoot, 'connected.db');
  let env = harness(CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, databasePath);
  t.after(() => {
    try { env.db.close(); } catch {}
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  const paused = apply(env.store, entitlement({
    status: 'paused',
    reasonCode: 'manual_pause',
    fallbackUntil: null,
  }));
  assert.equal(paused.state.entitlement.status, 'paused');
  env.db.close();

  env = harness(CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, databasePath);
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlement.status, 'paused');
  env.store.recordFailure({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    failureClass: 'transport_unavailable',
    nowMs: NOW + 1000,
  });
  const disposition = env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: Date.parse('2026-07-13T12:00:00.000Z'),
    offlineLicenseText: offlineLicense({ status: 'active' }).text,
  });
  assert.equal(disposition.protectedEgress, 'block');
  assert.notEqual(disposition.mode, 'degraded_fallback');
  assert.equal(disposition.reason, 'vendor_paused');
});

test('ACK retry uses bounded store-owned backoff and accepted response becomes acknowledged', () => {
  const env = harness();
  const first = apply(env.store);
  const failed = env.store.recordAckResult(ackResultInput(first, {
    accepted: false,
    nowMs: NOW + 1000,
  }));
  assert.equal(failed.status, 'pending');
  assert.equal(failed.attempts, 1);
  assert.equal(env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 5999,
  }).length, 0);
  assert.equal(env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 6000,
  }).length, 1);
  const accepted = env.store.recordAckResult(ackResultInput(first, { nowMs: NOW + 7000 }));
  assert.equal(accepted.status, 'acknowledged');
  assert.equal(accepted.attempts, 2);
  assert.equal(env.store.listPendingAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 7001,
  })[0].acknowledgement.lifecycleStage, 'applied');
});

test('ACK terminal classes are sticky across store recreation while retryable classes stay queued', () => {
  for (const failureClass of [
    'authentication_rejected', 'version_conflict', 'protocol_rejected', 'invalid_schema',
  ]) {
    const env = harness();
    const first = apply(env.store);
    const terminal = env.store.recordAckResult(ackResultInput(first, {
      accepted: false,
      failureClass,
      nowMs: NOW + 1000,
    }));
    assert.equal(terminal.status, 'terminal');
    assert.equal(terminal.failureClass, failureClass);
    assert.deepEqual(env.store.acknowledgementHealth(CUSTOMER_ID, DEPLOYMENT_ID), {
      ok: false,
      reason: 'connected_ack_terminal_failure',
      failureClass,
      id: first.outboxes.delivered.id,
      payloadDigest: first.outboxes.delivered.payloadDigest,
    });
    assert.equal(env.store.listPendingAcknowledgements({
      customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 100_000,
    }).length, 0);
    const restarted = env.createStore();
    assert.equal(restarted.acknowledgementHealth(
      CUSTOMER_ID, DEPLOYMENT_ID,
    ).failureClass, failureClass);
    assert.equal(restarted.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
      nowMs: NOW + 1001,
    }).reason, 'connected_ack_terminal_failure');
  }

  for (const failureClass of ['transport_unavailable', 'transport_ambiguous', 'rate_limited']) {
    const env = harness();
    const first = apply(env.store);
    const retry = env.store.recordAckResult(ackResultInput(first, {
      accepted: false,
      failureClass,
      nowMs: NOW + 1000,
    }));
    assert.equal(retry.status, 'pending');
    assert.equal(retry.failureClass, failureClass);
    assert.deepEqual(env.store.acknowledgementHealth(CUSTOMER_ID, DEPLOYMENT_ID), { ok: true });
    const [pending] = env.store.listPendingAcknowledgements({
      customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 6000,
    });
    assert.equal(pending.failureClass, failureClass);
    assert.equal(pending.id, first.outboxes.delivered.id);
  }
});

test('long partial ACK recovery crosses the live-history boundary and terminal supersession still archives exact evidence', () => {
  const env = harness();
  const releaseCount = ACK_PENDING_HARD_LIMIT - 1;
  seedLongPartialRecovery(env, releaseCount);

  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE status = 'pending'`).get().n, releaseCount);
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE status = 'acknowledged'`).get().n, releaseCount);

  let recoveryTime = NOW + 1000;
  for (let version = 1; version <= 8; version += 1) {
    recoveryTime += 1;
    assert.equal(env.store.recordAckResult(seededAckResultInput(env, version, {
      nowMs: recoveryTime,
    })).status, 'acknowledged');
  }
  recoveryTime += 1;
  assert.equal(env.store.recordAckResult(seededAckResultInput(env, 9, {
    accepted: false,
    failureClass: 'version_conflict',
    nowMs: recoveryTime,
  })).status, 'terminal');

  recoveryTime += 1;
  assert.equal(env.store.recordAckResult(seededAckResultInput(env, 10, {
    accepted: false,
    failureClass: 'protocol_rejected',
    nowMs: recoveryTime,
  })), null, 'the first terminal result remains the single sticky authority');
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE status = 'terminal'`).get().n, 1);

  const nextVersion = releaseCount + 1;
  const nextMessageId = versionMessageId(1_000_000 + nextVersion);
  recoveryTime += 1;
  assert.equal(apply(env.store, entitlement({
    messageId: nextMessageId,
    entitlementVersion: nextVersion,
    previousVersion: releaseCount,
  }), recoveryTime).state.entitlementVersion, nextVersion);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n, 16);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 2032);
  assert.equal(env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).entitlementVersion, nextVersion, 'restart reverifies the exact chained archive');
  assert.equal(env.createStore().acknowledgementHealth(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).failureClass, 'version_conflict');
});

test('authenticated ACK ledger detects active, archived acknowledged, or terminal tamper', () => {
  const nextValue = entitlement({
    messageId: '6c1dba8d-fdb1-4cbc-8878-a37e83a14f6e',
    entitlementVersion: 2,
    previousVersion: 1,
  });

  const pending = harness();
  const firstPending = apply(pending.store);
  apply(pending.store, nextValue, NOW + 1000);
  pending.db.prepare('DELETE FROM connected_ack_outbox WHERE id = ?')
    .run(firstPending.outboxes.delivered.id);
  assert.throws(() => pending.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);

  for (const mutation of [
    "created_at = '9999-12-31T23:59:59.999Z'",
    "updated_at = '9999-12-31T23:59:59.999Z'",
  ]) {
    const historical = harness();
    const firstHistorical = apply(historical.store);
    acknowledgeInOrder(historical.store, firstHistorical);
    historical.db.prepare(`UPDATE connected_ack_outbox SET ${mutation} WHERE id = ?`)
      .run(firstHistorical.outboxes.delivered.id);
    assert.throws(
      () => historical.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
      integrityFailure,
    );
  }

  const acknowledged = harness();
  const firstAcknowledged = apply(acknowledged.store);
  acknowledgeInOrder(acknowledged.store, firstAcknowledged);
  apply(acknowledged.store, nextValue, NOW + 1000);
  assert.equal(acknowledged.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE target_version = 1`).get().n, 0);
  assert.equal(acknowledged.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_archive
    WHERE target_version = 1`).get().n, 2);
  assert.throws(() => acknowledged.db.prepare(`UPDATE connected_ack_archive
    SET attempts = attempts + 1 WHERE id = ?`)
    .run(firstAcknowledged.outboxes.delivered.id), /append-only/);
  acknowledged.db.exec('DROP TRIGGER connected_ack_archive_no_update');
  acknowledged.db.prepare(`UPDATE connected_ack_archive SET attempts = attempts + 1
    WHERE id = ?`).run(firstAcknowledged.outboxes.delivered.id);
  assert.throws(
    () => acknowledged.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID),
    integrityFailure,
  );

  for (const mutation of [
    "DELETE FROM connected_ack_outbox WHERE id = ?",
    "UPDATE connected_ack_outbox SET status = 'acknowledged', failure_class = NULL WHERE id = ?",
    "UPDATE connected_ack_outbox SET created_at = '9999-12-31T23:59:59.999Z' WHERE id = ?",
    "UPDATE connected_ack_outbox SET updated_at = '9999-12-31T23:59:59.999Z' WHERE id = ?",
  ]) {
    const terminal = harness();
    const firstTerminal = apply(terminal.store);
    terminal.store.recordAckResult(ackResultInput(firstTerminal, {
      accepted: false,
      failureClass: 'version_conflict',
    }));
    apply(terminal.store, nextValue, NOW + 1000);
    terminal.db.prepare(mutation).run(firstTerminal.outboxes.delivered.id);
    assert.throws(() => terminal.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);
  }
});

test('a warmed store cannot skip same-connection ACK archive mutations', () => {
  const mutations = [
    {
      name: 'update',
      mutate(db) {
        db.exec('DROP TRIGGER connected_ack_archive_no_update');
        db.exec(`UPDATE connected_ack_archive SET attempts = attempts + 1
          WHERE archive_seq = (SELECT MIN(archive_seq) FROM connected_ack_archive)`);
      },
    },
    {
      name: 'delete',
      mutate(db) {
        db.exec(`DELETE FROM connected_ack_archive
          WHERE archive_seq = (SELECT MIN(archive_seq) FROM connected_ack_archive)`);
      },
    },
    { name: 'direct insert', mutate: insertForgedArchiveRow },
  ];

  for (const mutation of mutations) {
    const env = harness();
    archiveFirstAcknowledgementPair(env);
    mutation.mutate(env.db);
    assert.throws(
      () => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
      integrityFailure,
      `${mutation.name} must invalidate the warmed archive cache`,
    );
  }
});

test('a TEMP authority shadow present before statement construction fails closed', () => {
  const env = harness(
    CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, ':memory:', null,
    (db) => db.exec(`CREATE TEMP TABLE connected_ack_outbox (
      id TEXT PRIMARY KEY, status TEXT NOT NULL
    ); INSERT INTO temp.connected_ack_outbox VALUES ('shadow', 'pending')`),
  );
  assert.equal(env.db.prepare('SELECT id FROM connected_ack_outbox').get().id, 'shadow',
    'the test connection demonstrates ordinary TEMP-first name resolution');
  assert.throws(
    () => env.store.acknowledgementHealth(CUSTOMER_ID, DEPLOYMENT_ID),
    integrityFailure,
  );
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM main.connected_ack_outbox').get().n, 0);
});

test('a warmed statement cannot bypass later TEMP index or trigger collisions', () => {
  for (const createCollision of [
    (db) => db.exec(`CREATE TEMP TABLE authority_probe (value INTEGER);
      CREATE INDEX temp.idx_connected_ack_archive_scope ON authority_probe(value)`),
    (db) => db.exec(`CREATE TEMP TABLE authority_probe (value INTEGER);
      CREATE TEMP TRIGGER connected_ack_archive_no_update
      AFTER INSERT ON authority_probe BEGIN SELECT 1; END`),
  ]) {
    const env = harness();
    const first = apply(env.store);
    assert.equal(env.store.getState(
      CUSTOMER_ID, DEPLOYMENT_ID,
    ).entitlementVersion, first.state.entitlementVersion);
    createCollision(env.db);
    assert.throws(
      () => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
      integrityFailure,
    );
  }
});

test('Postgres operational and catalog statements retain explicit trusted schemas', () => {
  const prepared = [];
  const inertStatement = Object.freeze({
    get: () => null,
    all: () => [],
    run: () => ({ changes: 0 }),
  });
  const driver = {
    kind: 'postgres',
    prepare(sql) {
      prepared.push(sql.trim().replace(/\s+/g, ' '));
      return inertStatement;
    },
    transaction(callback) { return callback; },
  };
  createConnectedEntitlementStore({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    driver,
    appendAudit() {},
    authorityReference: () => 'connected_ref',
    ackReference: () => 'ack_ref',
    verifyAuditState: () => ({ ok: true }),
    verifyAuditEntry: () => true,
    verificationKeys: () => ({ publicKeys: { [KEY_ID]: onlineKeys.publicKey } }),
    offlinePublicKey: () => offlineKeys.publicKey,
  });
  const catalog = prepared.at(-1);
  const operational = prepared.slice(0, -1).join('\n');
  for (const name of [
    'audit',
    'connected_entitlement_state',
    'connected_ack_outbox',
    'connected_ack_archive',
    'connected_ack_archive_mutations',
    'connected_ack_health',
  ]) {
    assert.match(operational, new RegExp(`public\\.${name}\\b`));
  }
  assert.doesNotMatch(operational,
    /(?:FROM|INTO|UPDATE|DELETE FROM)\s+(?:audit|connected_(?:entitlement_state|ack_(?:outbox|archive|archive_mutations|health)))\b/);
  assert.match(catalog, /FROM pg_catalog\.pg_class/);
  assert.match(catalog, /FROM pg_catalog\.pg_proc/);
  assert.match(catalog, /FROM pg_catalog\.pg_trigger/);
  assert.match(catalog, /FROM pg_catalog\.pg_policy/);
  assert.match(catalog, /FROM pg_catalog\.pg_index/);
  assert.doesNotMatch(catalog,
    /FROM (?:pg_class|pg_proc|pg_trigger|pg_policy|pg_index)\b/);
});

test('a second SQLite connection cannot bypass a warmed ACK archive cache', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-ack-archive-'));
  const databasePath = path.join(tempRoot, 'archive.db');
  const env = harness(CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, databasePath);
  const second = new Database(databasePath);
  t.after(() => {
    second.close();
    env.db.close();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  archiveFirstAcknowledgementPair(env);
  insertForgedArchiveRow(second);
  assert.throws(
    () => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID),
    integrityFailure,
  );
});

test('schema_version rewind cannot hide drop-mutate-recreate archive tamper', () => {
  const env = harness();
  archiveFirstAcknowledgementPair(env);
  const schemaVersion = env.db.pragma('schema_version', { simple: true });
  const triggerSql = env.db.prepare(`SELECT name, sql FROM sqlite_schema
    WHERE type = 'trigger' AND name IN
      ('connected_ack_archive_no_update', 'connected_ack_archive_record_update')
    ORDER BY name`).all();
  assert.equal(triggerSql.length, 2);
  env.db.exec(`DROP TRIGGER connected_ack_archive_no_update;
    DROP TRIGGER connected_ack_archive_record_update;`);
  env.db.exec(`UPDATE connected_ack_archive SET attempts = attempts + 1
    WHERE archive_seq = (SELECT MIN(archive_seq) FROM connected_ack_archive)`);
  for (const row of triggerSql) env.db.exec(row.sql);
  env.db.unsafeMode(true);
  env.db.exec(`PRAGMA schema_version = ${schemaVersion}`);
  env.db.unsafeMode(false);
  assert.equal(env.db.pragma('schema_version', { simple: true }), schemaVersion,
    'the attacker model restores the mutable catalog counter exactly');

  assert.throws(() => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);
  assert.throws(() => env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ), integrityFailure, 'a fresh store must replay the archive instead of trusting recreated DDL');
});

test('restored exact archive schema cannot replace bounded evidence verification', () => {
  const env = harness();
  archiveFirstAcknowledgementPair(env);
  const triggerSql = env.db.prepare(`SELECT sql FROM sqlite_schema
    WHERE type = 'trigger' AND name = 'connected_ack_archive_record_insert'`).get().sql;
  env.db.exec('DROP TRIGGER connected_ack_archive_record_insert');
  env.db.exec(triggerSql);

  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementVersion, 2,
    'schema history is not used as an authorization cache');
  assert.equal(env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).entitlementVersion, 2, 'a clean restart can fully scan unchanged evidence');
});

test('unexpected archive triggers fail closed instead of extending the trusted catalog', () => {
  const env = harness();
  archiveFirstAcknowledgementPair(env);
  env.db.exec(`CREATE TRIGGER connected_ack_archive_no_delete
    BEFORE DELETE ON connected_ack_archive
    BEGIN SELECT RAISE(ABORT, 'obsolete archive guard'); END;`);
  assert.throws(() => env.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ), integrityFailure, 'an already-stamped pre-compaction v13 schema must be reinitialized');
});

test('archive mutation evidence advances with the authenticated ledger and rejects tamper', () => {
  const env = harness();
  const first = apply(env.store);
  acknowledgeInOrder(env.store, first);
  const secondValue = entitlement({
    messageId: '6c1dba8d-fdb1-4cbc-8878-a37e83a14f6e',
    entitlementVersion: 2,
    previousVersion: 1,
  });
  const second = apply(env.store, secondValue, NOW + 2000);
  acknowledgeInOrder(env.store, second, NOW + 3000);
  const third = apply(env.store, entitlement({
    messageId: 'dd184093-4d63-4025-b935-a04977cfa492',
    entitlementVersion: 3,
    previousVersion: 2,
  }), NOW + 4000);
  assert.equal(third.state.entitlementVersion, 3);

  const summary = env.db.prepare(`SELECT COUNT(*) AS n, MAX(event_seq) AS high_water
    FROM connected_ack_archive_mutations`).get();
  assert.equal(summary.n, 4);
  const plan = env.db.prepare(`EXPLAIN QUERY PLAN
    SELECT scope_seq AS mutation_count, event_seq AS mutation_high_water
    FROM connected_ack_archive_mutations
    WHERE customer_id = ? AND deployment_id = ?
    ORDER BY scope_seq DESC LIMIT 1`).all(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.ok(plan.some((row) => /USING COVERING INDEX idx_connected_ack_archive_mutation_scope/
    .test(row.detail)), 'the authorization probe must use one indexed latest-row lookup');
  const ledger = JSON.parse(env.db.prepare(`SELECT state_json FROM connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID).state_json);
  assert.equal(ledger.archiveMutationCount, 4);
  assert.equal(ledger.archiveMutationHighWater, summary.high_water);
  assert.match(ledger.archiveMutationDigest, /^[a-f0-9]{64}$/);
  const auditDetail = JSON.parse(JSON.parse(env.db.prepare(`SELECT entry FROM audit
    WHERE connected_entry_action = 'CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED'
    ORDER BY seq DESC LIMIT 1`).get().entry).detail);
  assert.equal(auditDetail.archiveMutationCount, ledger.archiveMutationCount);
  assert.equal(auditDetail.archiveMutationHighWater, ledger.archiveMutationHighWater);
  assert.equal(auditDetail.archiveMutationDigest, ledger.archiveMutationDigest);
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementVersion, 3);
  assert.equal(env.createStore().getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementVersion, 3);
  assert.throws(() => env.db.exec(`UPDATE connected_ack_archive_mutations
    SET archive_id = archive_id || '-changed' WHERE event_seq = 1`), /append-only/);
  assert.throws(() => env.db.exec(`INSERT OR REPLACE INTO connected_ack_archive_mutations
    (event_seq, customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
    SELECT event_seq, customer_id, deployment_id, scope_seq, mutation_kind,
      archive_seq, archive_id || '-replacement'
    FROM connected_ack_archive_mutations WHERE scope_seq = 1`), /append-only/);
  assert.throws(() => env.db.prepare(`INSERT INTO connected_ack_archive_mutations
    (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
    VALUES (?, ?, 2, 'insert', 1, 'forged-low')`).run(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ), /append-only|UNIQUE/);
  env.db.prepare(`INSERT INTO connected_ack_archive_mutations
    (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
    VALUES (?, ?, 100, 'insert', 1, 'forged-high')`).run(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.throws(() => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);

  const deleted = harness();
  archiveFirstAcknowledgementPair(deleted);
  deleted.db.exec(`DELETE FROM connected_ack_archive_mutations
    WHERE event_seq = (SELECT MIN(event_seq) FROM connected_ack_archive_mutations)`);
  assert.throws(() => deleted.store.getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ), integrityFailure, 'only audit-coupled compaction may delete mutation evidence');
});

test('authenticated archive compaction bounds restart verification without discarding history', () => {
  const receivers = [];
  const env = harness(CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], receivers);
  const releaseCount = 80;
  applyAcknowledgedReleases(env, releaseCount);

  const archiveRows = env.db.prepare(`SELECT COUNT(*) AS n
    FROM connected_ack_archive WHERE customer_id = ? AND deployment_id = ?`)
    .get(CUSTOMER_ID, DEPLOYMENT_ID).n;
  const mutationRows = env.db.prepare(`SELECT COUNT(*) AS n
    FROM connected_ack_archive_mutations WHERE customer_id = ? AND deployment_id = ?`)
    .get(CUSTOMER_ID, DEPLOYMENT_ID).n;
  const ledger = JSON.parse(env.db.prepare(`SELECT state_json FROM connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID).state_json);
  assert.ok(archiveRows <= ARCHIVE_RETAINED_BOUND, 'the authoritative ACK suffix is fixed-size');
  assert.ok(mutationRows <= ARCHIVE_MUTATION_RETAINED_BOUND,
    'the authoritative mutation suffix is fixed-size');
  assert.equal(archiveRows, ledger.archivedCount - ledger.archivedPrefixCount);
  assert.equal(mutationRows, ledger.archiveMutationCount - ledger.archiveMutationPrefixCount);
  assert.ok(ledger.archivedPrefixCount > 0);
  assert.ok(ledger.archiveMutationPrefixCount > 0);

  receivers.length = 0;
  assert.equal(env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).entitlementVersion, releaseCount);
  assert.ok(receivers.filter(([name]) => name === 'verifyAuditEntry').length
    <= ARCHIVE_RETAINED_BOUND + 16,
  'a restart authenticates only the bounded suffix plus current state');

  env.db.exec('DROP TRIGGER connected_ack_archive_no_update');
  env.db.exec(`UPDATE connected_ack_archive SET attempts = attempts + 1
    WHERE archive_seq = (SELECT MIN(archive_seq) FROM connected_ack_archive)`);
  assert.throws(() => env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ), integrityFailure, 'compaction must not weaken retained-suffix tamper detection');
});

test('post-COMMIT response loss reconciles from durable bounded evidence without duplication', () => {
  const control = { failNext: false };
  const env = harness(
    CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, ':memory:',
    (db) => commitResponseLossDriver(db, control),
  );
  const first = apply(env.store);
  acknowledgeInOrder(env.store, first);
  const secondValue = entitlement({
    messageId: versionMessageId(20_002),
    entitlementVersion: 2,
    previousVersion: 1,
  });
  control.failNext = true;
  assert.throws(
    () => apply(env.store, secondValue, NOW + 2000),
    /response loss after commit/,
  );
  assert.equal(env.db.prepare(`SELECT entitlement_version FROM connected_entitlement_state
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID)
    .entitlement_version, 2);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n, 2);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
  ).get().n, 2);

  const retried = apply(env.store, secondValue, NOW + 2000);
  assert.equal(retried.idempotent, true);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n, 2);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
  ).get().n, 2);
  assert.equal(env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).entitlementVersion, 2);
});

test('post-COMMIT ACK result replay survives archival and bounded raw-history compaction', () => {
  const control = { failNext: false };
  const env = harness(
    CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, ':memory:',
    (db) => commitResponseLossDriver(db, control),
  );
  const first = apply(env.store);
  env.store.recordAckResult(ackResultInput(first, { nowMs: NOW + 1000 }, 'delivered'));
  let latest = apply(env.store, entitlement({
    messageId: versionMessageId(50_002),
    entitlementVersion: 2,
    previousVersion: 1,
  }), NOW + 2000);
  const oldAppliedResult = ackResultInput(first, { nowMs: NOW + 3000 }, 'applied');

  control.failNext = true;
  assert.throws(
    () => env.store.recordAckResult(oldAppliedResult),
    /response loss after commit/,
  );
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE target_version = 1`).get().n, 0);
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_archive
    WHERE target_version = 1`).get().n, 2);
  const replayed = env.store.recordAckResult(oldAppliedResult);
  assert.deepEqual(replayed, {
    id: oldAppliedResult.id,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    targetKind: first.outboxes.applied.targetKind,
    targetVersion: first.outboxes.applied.targetVersion,
    targetDigest: first.outboxes.applied.targetDigest,
    lifecycleStage: first.outboxes.applied.lifecycleStage,
    payloadDigest: oldAppliedResult.payloadDigest,
    status: 'acknowledged',
    failureClass: null,
    attempts: 1,
    nextAttemptAt: first.outboxes.applied.nextAttemptAt,
  });

  acknowledgeInOrder(env.store, latest, NOW + 4000);
  for (let version = 3; version <= 34; version += 1) {
    latest = apply(env.store, entitlement({
      messageId: versionMessageId(50_000 + version),
      entitlementVersion: version,
      previousVersion: version - 1,
    }), NOW + (version * 1000));
    acknowledgeInOrder(env.store, latest, NOW + (version * 1000) + 1);
  }
  assert.equal(env.db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_archive
    WHERE target_version = 1`).get().n, 0, 'the exact raw ACK pair is compacted');
  const beforeReplay = {
    archive: env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n,
    mutations: env.db.prepare(
      'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
    ).get().n,
  };
  assert.deepEqual(env.store.recordAckResult(oldAppliedResult), replayed);
  assert.deepEqual(env.createStore().recordAckResult(oldAppliedResult), replayed);
  assert.deepEqual({
    archive: env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n,
    mutations: env.db.prepare(
      'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
    ).get().n,
  }, beforeReplay, 'exact result replay does not mutate bounded archive evidence');
});

test('archived ACK result replay accepts an authenticated acknowledged reuse receipt', () => {
  const env = harness();
  const first = apply(env.store);
  acknowledgeInOrder(env.store, first);
  assert.equal(apply(env.store, entitlement(), NOW + 2000).idempotent, true);
  apply(env.store, entitlement({
    messageId: versionMessageId(60_002),
    entitlementVersion: 2,
    previousVersion: 1,
  }), NOW + 3000);

  assert.deepEqual(
    env.store.recordAckResult(ackResultInput(first, { nowMs: NOW + 4000 }, 'applied')),
    {
      ...first.outboxes.applied,
      status: 'acknowledged',
      failureClass: null,
      attempts: 1,
    },
  );
});

test('partial archive-prefix deletion rolls back the pair, mutation evidence, ledger, and state', () => {
  const control = { archiveDeleteFailureAt: 2 };
  const env = harness(
    CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, ':memory:',
    (db) => compactionFaultDriver(db, control),
  );
  applyAcknowledgedReleases(env, 33);
  const beforeLedger = env.db.prepare(`SELECT state_json FROM connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID).state_json;
  assert.throws(() => apply(env.store, entitlement({
    messageId: versionMessageId(30_034),
    entitlementVersion: 34,
    previousVersion: 33,
  }), NOW + 340), /forced archiveDelete interruption/);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n, 64);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
  ).get().n, 64);
  assert.equal(env.db.prepare(`SELECT state_json FROM connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID).state_json,
  beforeLedger);
  assert.equal(env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).entitlementVersion, 33);
});

test('partial mutation-prefix deletion rolls back compaction and all coupled authority', () => {
  const control = {};
  const env = harness(
    CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, ':memory:',
    (db) => compactionFaultDriver(db, control),
  );
  applyAcknowledgedReleases(env, 80);
  control.mutationDeleteCalls = 0;
  control.mutationDeleteFailureAt = 2;
  const beforeLedger = env.db.prepare(`SELECT state_json FROM connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID).state_json;
  assert.throws(() => apply(env.store, entitlement({
    messageId: versionMessageId(40_081),
    entitlementVersion: 81,
    previousVersion: 80,
  }), NOW + 810), /forced mutationDelete interruption/);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n, 64);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
  ).get().n, 128);
  assert.equal(env.db.prepare(`SELECT state_json FROM connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID).state_json,
  beforeLedger);
  assert.equal(env.createStore().getState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).entitlementVersion, 80);
});

test('failure on the second row of an archive pair rolls back rows, mutation events, ledger, and state', () => {
  const control = { archiveInsertFailureAt: 2 };
  const env = harness(
    CUSTOMER_ID, DEPLOYMENT_ID, KEY_ID, [], null, ':memory:',
    (db) => compactionFaultDriver(db, control),
  );
  const first = apply(env.store);
  acknowledgeInOrder(env.store, first);
  const secondValue = entitlement({
    messageId: '6c1dba8d-fdb1-4cbc-8878-a37e83a14f6e',
    entitlementVersion: 2,
    previousVersion: 1,
  });
  assert.throws(() => apply(env.store, secondValue, NOW + 2000), /forced archiveInsert interruption/);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n, 0);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
  ).get().n, 0);
  assert.equal(JSON.parse(env.db.prepare(`SELECT state_json FROM connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID).state_json)
    .archiveMutationCount, 0);
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementVersion, 1);

  const restarted = env.createStore();
  assert.equal(apply(restarted, secondValue, NOW + 2000).state.entitlementVersion, 2);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_ack_archive').get().n, 2);
  assert.equal(env.db.prepare(
    'SELECT COUNT(*) AS n FROM connected_ack_archive_mutations',
  ).get().n, 2);
});

test('one customer-side store is immutably bound to one deployment scope', () => {
  const env = harness();
  apply(env.store);
  const otherCustomer = 'cu-store-2';
  const otherDeployment = 'dep_55555555555555555555555555555555';
  const other = entitlement({
    messageId: '71f17727-226c-4a7f-9f9f-4c6e5e757956',
    customerId: otherCustomer,
    deploymentId: otherDeployment,
  });
  assert.throws(() => env.store.applyEntitlement({
    customerId: otherCustomer,
    deploymentId: otherDeployment,
    signedArtifact: signedArtifact(other),
    nowMs: NOW + 1000,
  }), (error) => error.code === 'customer_mismatch');
  assert.throws(() => env.store.getState(otherCustomer, otherDeployment), (
    error
  ) => error.code === 'customer_mismatch');
  assert.equal(env.db.prepare('SELECT COUNT(*) AS n FROM connected_entitlement_state').get().n, 1);
});

function integrityFailure(error) {
  return error && error.code === 'CONNECTED_ENTITLEMENT_INTEGRITY';
}
