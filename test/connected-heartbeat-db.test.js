'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../server/vendor-control-protocol');
const onlineVerdict = require('../server/connected-online-verdict');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-heartbeat-db-'));
process.env.NODE_ENV = 'test';
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'heartbeat.db');
const entitlementKeys = crypto.generateKeyPairSync('ed25519');
const verdictKeys = crypto.generateKeyPairSync('ed25519');
const offlineKeys = crypto.generateKeyPairSync('ed25519');
const publicPem = (key) => key.export({ type: 'spki', format: 'pem' }).toString();
const ENTITLEMENT_KEY_ID = entitlementKeyId(entitlementKeys.publicKey);
process.env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = publicPem(entitlementKeys.publicKey);
process.env.REDACTWALL_ENTITLEMENT_KEY_ID = ENTITLEMENT_KEY_ID;
process.env.REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY = publicPem(verdictKeys.publicKey);
process.env.REDACTWALL_LICENSE_PUBLIC_KEY = publicPem(offlineKeys.publicKey);
const CUSTOMER_ID = 'customer_heartbeat_db';
const DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
process.env.REDACTWALL_TENANT_ID = CUSTOMER_ID;
process.env.REDACTWALL_CONNECTED_DEPLOYMENT_ID = DEPLOYMENT_ID;
const db = require('../server/db');

const NOW = Date.parse('2026-07-13T12:00:00.000Z');
const VERDICT_KEY_ID = onlineVerdict.keyIdForPublicKey(verdictKeys.publicKey);

function entitlementKeyId(key) {
  const der = key.export({ type: 'spki', format: 'der' });
  return `rw-entitlement-${crypto.createHash('sha256').update(der).digest('hex')}`;
}

function entitlement(version = 1, overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: crypto.randomUUID(),
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status: 'active', plan: 'enterprise', seats: 40, features: ['policy'],
    entitlementVersion: version, previousVersion: version - 1,
    issuedAt: new Date(NOW + (version - 1) * 1000).toISOString(),
    expiresAt: new Date(NOW + 5 * 60 * 1000).toISOString(),
    fallbackUntil: new Date(NOW + 72 * 60 * 60 * 1000).toISOString(),
    reasonCode: 'billing_active',
    ...overrides,
  };
}

function signedEntitlement(value) {
  const keyId = process.env.REDACTWALL_ENTITLEMENT_KEY_ID;
  return {
    keyId,
    payload: value,
    signature: crypto.sign(
      null, protocol.signingInput(value, keyId), entitlementKeys.privateKey,
    ).toString('base64'),
  };
}

function signedVerdict(generation = 1, overrides = {}) {
  const value = {
    kind: onlineVerdict.VERDICT_DOMAIN,
    keyId: VERDICT_KEY_ID,
    status: 'active',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    issuedAt: new Date(NOW + (generation - 1) * 1000).toISOString(),
    registryGeneration: generation,
    registryStateDigest: String(generation).repeat(64).slice(0, 64),
    ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
  const signature = crypto.sign(
    null,
    Buffer.from(`${onlineVerdict.VERDICT_DOMAIN}\0${payload}`, 'utf8'),
    verdictKeys.privateKey,
  ).toString('base64');
  return `${payload}.${signature}`;
}

function apply(version = 1, overrides = {}) {
  const value = entitlement(version, overrides.entitlement);
  return db.applyConnectedHeartbeatResponse({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedOnlineRegistryVerdict: signedVerdict(version, overrides.verdict),
    signedEntitlementArtifact: signedEntitlement(value),
    nowMs: NOW + (version - 1) * 1000,
    randomUUID: crypto.randomUUID,
    clock: { bootId: '2'.repeat(32), nowMs: 10_000 + version },
  });
}

test('db composite commits both high-waters, both ACKs, and combined enforcement', () => {
  assert.equal(db.applyConnectedEntitlement, undefined);
  assert.equal(db.applyConnectedOnlineVerdict, undefined);
  assert.equal(db.connectedEntitlementDisposition, undefined);
  assert.equal(db.connectedOnlineRegistryDisposition, undefined);
  assert.equal(typeof db.connectedLicensingDisposition, 'function');
  const result = apply();
  assert.equal(result.registry.state.registryGeneration, 1);
  assert.equal(result.entitlement.state.entitlementVersion, 1);
  assert.equal(db.connectedOnlineRegistryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 1);
  assert.equal(db.connectedEntitlementVersion(CUSTOMER_ID, DEPLOYMENT_ID), 1);
  assert.equal(db._db.prepare('SELECT COUNT(*) AS n FROM connected_ack_outbox').get().n, 2);
  const disposition = db.connectedLicensingDisposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 1,
    clock: { bootId: '2'.repeat(32), nowMs: 10_002 },
  });
  assert.equal(disposition.protectedEgress, 'block');
  assert.equal(disposition.reason, 'connected_initial_acknowledgement_pending');
  assert.equal(db.verifyAuditChain().ok, true);
});

test('db ACK drain state exposes delivered before applied', () => {
  let pending = db.pendingConnectedAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW,
  });
  assert.deepEqual(pending.map((item) => item.acknowledgement.lifecycleStage), ['delivered']);
  const delivered = pending[0];
  db.recordConnectedAcknowledgementResult({
    id: delivered.id,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    payloadDigest: delivered.payloadDigest,
    accepted: true,
    nowMs: NOW + 1,
  });
  pending = db.pendingConnectedAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 2,
  });
  assert.deepEqual(pending.map((item) => item.acknowledgement.lifecycleStage), ['applied']);
  assert.equal(db.connectedLicensingDisposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 2,
    clock: { bootId: '2'.repeat(32), nowMs: 10_003 },
  }).protectedEgress, 'block');
  const applied = pending[0];
  db.recordConnectedAcknowledgementResult({
    id: applied.id,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    payloadDigest: applied.payloadDigest,
    accepted: true,
    nowMs: NOW + 3,
  });
  assert.equal(db.pendingConnectedAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 4,
  }).length, 0);
  assert.equal(db.connectedLicensingDisposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + 4,
    clock: { bootId: '2'.repeat(32), nowMs: 10_005 },
  }).protectedEgress, 'allow');
});

test('real audit append failure rolls back both newer high-waters and ACK rows', () => {
  db._db.exec(`CREATE TRIGGER reject_composite_db_audit BEFORE INSERT ON audit
    WHEN NEW.action = 'CONNECTED_ENTITLEMENT_APPLIED'
    BEGIN SELECT RAISE(ABORT, 'forced composite db audit failure'); END`);
  try {
    assert.throws(() => apply(2), /forced composite db audit failure/);
  } finally {
    db._db.exec('DROP TRIGGER reject_composite_db_audit');
  }
  assert.equal(db.connectedOnlineRegistryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 1);
  assert.equal(db.connectedEntitlementVersion(CUSTOMER_ID, DEPLOYMENT_ID), 1);
  assert.equal(db._db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE target_version = 2`).get().n, 0);
  assert.equal(db.verifyAuditChain().ok, true);
});
