'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../server/vendor-control-protocol');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-connected-db-'));
process.env.NODE_ENV = 'test';
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'connected.db');
const entitlementKeys = crypto.generateKeyPairSync('ed25519');
const verdictKeys = crypto.generateKeyPairSync('ed25519');
const offlineKeys = crypto.generateKeyPairSync('ed25519');
const KEY_ID = entitlementKeyId(entitlementKeys.publicKey);
process.env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = entitlementKeys.publicKey
  .export({ type: 'spki', format: 'pem' }).toString();
process.env.REDACTWALL_ENTITLEMENT_KEY_ID = KEY_ID;
process.env.REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY = verdictKeys.publicKey
  .export({ type: 'spki', format: 'pem' }).toString();
process.env.REDACTWALL_LICENSE_PUBLIC_KEY = offlineKeys.publicKey
  .export({ type: 'spki', format: 'pem' }).toString();
const CUSTOMER_ID = 'cu-db-connected-1';
const DEPLOYMENT_ID = 'dep_11111111111111111111111111111111';
process.env.REDACTWALL_TENANT_ID = CUSTOMER_ID;
process.env.REDACTWALL_CONNECTED_DEPLOYMENT_ID = DEPLOYMENT_ID;
const db = require('../server/db');

const NOW = Date.parse('2026-07-12T12:01:00.000Z');

function entitlementKeyId(key) {
  const der = key.export({ type: 'spki', format: 'der' });
  return `rw-entitlement-${crypto.createHash('sha256').update(der).digest('hex')}`;
}

function entitlement(overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: crypto.randomUUID(),
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status: 'active', plan: 'standard', seats: 20, features: ['policy'],
    entitlementVersion: 1, previousVersion: 0,
    issuedAt: '2026-07-12T12:00:00.000Z',
    expiresAt: '2026-07-12T12:05:00.000Z',
    fallbackUntil: '2026-07-15T12:00:00.000Z',
    reasonCode: 'billing_active',
    ...overrides,
  };
}

function apply(value = entitlement(), nowMs = NOW) {
  const signedArtifact = {
    keyId: KEY_ID,
    payload: value,
    signature: crypto.sign(
      null,
      protocol.signingInput(value, KEY_ID),
      entitlementKeys.privateKey,
    ).toString('base64'),
  };
  return db._internal.applyConnectedEntitlement({
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    signedArtifact,
    nowMs,
  });
}

test('db refuses to acknowledge a test-only entitlement without an exact registry pair', () => {
  const applied = apply();
  assert.equal(applied.state.entitlementVersion, 1);
  assert.equal(db.connectedEntitlementState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementDigest, applied.state.entitlementDigest);
  assert.equal(db.pendingConnectedAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW,
  }).length, 1);
  assert.equal(db.verifyAuditChain().ok, true);

  assert.throws(() => db.recordConnectedAcknowledgementResult({
    id: applied.outboxes.delivered.id,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    payloadDigest: applied.outboxes.delivered.payloadDigest,
    accepted: true,
    nowMs: NOW + 1000,
  }), (error) => error?.code === 'CONNECTED_ACKNOWLEDGED_AUTHORITY_INTEGRITY');
  const pending = db.pendingConnectedAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 1001,
  });
  assert.equal(pending.length, 1);
  assert.equal(pending[0].acknowledgement.lifecycleStage, 'delivered');
  assert.equal(db.verifyAuditChain().ok, true);
});

test('pause is adopted at a higher version and blocks protected egress', () => {
  const paused = apply(entitlement({
    messageId: crypto.randomUUID(),
    entitlementVersion: 2,
    previousVersion: 1,
    status: 'paused',
    fallbackUntil: null,
    reasonCode: 'manual_pause',
  }), NOW + 2000);
  assert.equal(paused.state.entitlement.status, 'paused');
  assert.equal(db._internal.connectedEntitlementDisposition(
    CUSTOMER_ID, DEPLOYMENT_ID, { nowMs: NOW + 3000 },
  ).protectedEgress, 'block');
  assert.equal(db.verifyAuditChain().ok, true);
});

test('audit failure rolls back a newer entitlement and its ACK outbox row', () => {
  db._db.exec(`
    CREATE TRIGGER connected_entitlement_audit_fail
    BEFORE INSERT ON audit
    WHEN NEW.action = 'CONNECTED_ENTITLEMENT_APPLIED'
    BEGIN SELECT RAISE(ABORT, 'forced connected entitlement audit failure'); END;
  `);
  try {
    assert.throws(
      () => apply(entitlement({
        messageId: crypto.randomUUID(),
        entitlementVersion: 3,
        previousVersion: 2,
        status: 'revoked',
        fallbackUntil: null,
        reasonCode: 'manual_revoke',
      }), NOW + 4000),
      /forced connected entitlement audit failure/,
    );
  } finally {
    db._db.exec('DROP TRIGGER connected_entitlement_audit_fail');
  }
  assert.equal(db.connectedEntitlementState(CUSTOMER_ID, DEPLOYMENT_ID).entitlementVersion, 2);
  assert.equal(db._db.prepare(`SELECT COUNT(*) AS n FROM connected_ack_outbox
    WHERE target_version = 3`).get().n, 0);
  assert.equal(db.verifyAuditChain().ok, true);
});
