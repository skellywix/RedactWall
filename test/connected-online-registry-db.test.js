'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const onlineVerdict = require('../server/connected-online-verdict');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-registry-db-'));
process.env.NODE_ENV = 'test';
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'registry.db');
const verdictKeys = crypto.generateKeyPairSync('ed25519');
const nextVerdictKeys = crypto.generateKeyPairSync('ed25519');
const entitlementKeys = crypto.generateKeyPairSync('ed25519');
const offlineKeys = crypto.generateKeyPairSync('ed25519');
process.env.REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY = publicPem(verdictKeys.publicKey);
process.env.REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY = publicPem(nextVerdictKeys.publicKey);
process.env.REDACTWALL_ENTITLEMENT_PUBLIC_KEY = publicPem(entitlementKeys.publicKey);
process.env.REDACTWALL_ENTITLEMENT_KEY_ID = entitlementKeyId(entitlementKeys.publicKey);
process.env.REDACTWALL_LICENSE_PUBLIC_KEY = publicPem(offlineKeys.publicKey);
const CUSTOMER_ID = 'customer_registry_db';
const DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
process.env.REDACTWALL_TENANT_ID = CUSTOMER_ID;
process.env.REDACTWALL_CONNECTED_DEPLOYMENT_ID = DEPLOYMENT_ID;
const db = require('../server/db');

const NOW = Date.parse('2026-07-13T12:00:00.000Z');
const CURRENT_KEY_ID = onlineVerdict.keyIdForPublicKey(verdictKeys.publicKey);

function entitlementKeyId(key) {
  const der = key.export({ type: 'spki', format: 'der' });
  return `rw-entitlement-${crypto.createHash('sha256').update(der).digest('hex')}`;
}

function payload(overrides = {}) {
  return {
    kind: onlineVerdict.VERDICT_DOMAIN,
    keyId: CURRENT_KEY_ID,
    status: 'active',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    issuedAt: new Date(NOW).toISOString(),
    registryGeneration: 7,
    registryStateDigest: '7'.repeat(64),
    ...overrides,
  };
}

function sign(value = payload(), privateKey = verdictKeys.privateKey) {
  const payloadB64 = Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
  const signature = crypto.sign(
    null, Buffer.from(`${onlineVerdict.VERDICT_DOMAIN}\0${payloadB64}`, 'utf8'), privateKey,
  ).toString('base64');
  return `${payloadB64}.${signature}`;
}

function apply(value = payload(), nowMs = NOW, privateKey = verdictKeys.privateKey) {
  return db._internal.applyConnectedOnlineVerdict({
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    signedVerdict: sign(value, privateKey),
    nowMs,
  });
}

test('db persists and audit-anchors the independent online registry high-water', () => {
  const applied = apply();
  assert.equal(applied.state.registryGeneration, 7);
  assert.equal(applied.state.signingKeyId, CURRENT_KEY_ID);
  assert.equal(db.connectedOnlineRegistryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 7);
  assert.equal(db.connectedOnlineRegistryState(
    CUSTOMER_ID, DEPLOYMENT_ID,
  ).registryStateDigest, '7'.repeat(64));
  assert.equal(db.verifyAuditChain().ok, true);
});

test('lower generation and same-generation conflict cannot replace durable state', () => {
  assert.throws(() => apply(payload({
    registryGeneration: 6,
    registryStateDigest: '6'.repeat(64),
  }), NOW + 1000), (error) => error && error.code === 'registry_generation_stale');
  assert.throws(() => apply(payload({
    status: 'revoked',
    issuedAt: new Date(NOW + 1000).toISOString(),
  }), NOW + 1000), (error) => error && error.code === 'registry_generation_conflict');
  assert.equal(db.connectedOnlineRegistryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 7);
});

test('audit failure rolls back a newer registry revoke', () => {
  db._db.exec(`
    CREATE TRIGGER connected_registry_audit_fail
    BEFORE INSERT ON audit
    WHEN NEW.action = 'CONNECTED_REGISTRY_VERDICT_REVOKED'
    BEGIN SELECT RAISE(ABORT, 'forced connected registry audit failure'); END;
  `);
  try {
    assert.throws(() => apply(payload({
      status: 'revoked',
      registryGeneration: 8,
      registryStateDigest: '8'.repeat(64),
      issuedAt: new Date(NOW + 2000).toISOString(),
    }), NOW + 2000), /forced connected registry audit failure/);
  } finally {
    db._db.exec('DROP TRIGGER connected_registry_audit_fail');
  }
  assert.equal(db.connectedOnlineRegistryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 7);
  assert.equal(db.verifyAuditChain().ok, true);
});

test('registry revoke remains more restrictive than an active entitlement disposition', () => {
  apply(payload({
    status: 'revoked',
    registryGeneration: 8,
    registryStateDigest: '8'.repeat(64),
    issuedAt: new Date(NOW + 3000).toISOString(),
  }), NOW + 3000);
  const result = db._internal.connectedOnlineRegistryDisposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    protectedEgress: 'allow',
    mode: 'connected',
    reason: null,
    authority: { plan: 'enterprise', seats: 100, features: ['policy'] },
  });
  assert.equal(result.protectedEgress, 'block');
  assert.equal(result.reason, 'vendor_registry_revoked');
  assert.equal(result.onlineRegistryGeneration, 8);
});

function publicPem(key) {
  return key.export({ type: 'spki', format: 'pem' }).toString();
}
