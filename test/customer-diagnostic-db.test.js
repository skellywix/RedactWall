'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-customer-diagnostic-db-'));
process.env.NODE_ENV = 'test';
process.env.REDACTWALL_DB_PATH = path.join(root, 'redactwall.db');
process.env.REDACTWALL_AUDIT_DIR = path.join(root, 'audit');
process.env.REDACTWALL_AUDIT_KEY = crypto.randomBytes(32).toString('base64');
process.env.REDACTWALL_SECRET = crypto.randomBytes(32).toString('base64');
process.env.REDACTWALL_DATA_KEY = crypto.randomBytes(32).toString('base64');
process.env.REDACTWALL_TENANT_ID = 'customer_diagnostic_db';
process.env.REDACTWALL_CONNECTED_DEPLOYMENT_ID = 'dep_44444444444444444444444444444444';

const db = require('../server/db');
const { createCustomerDiagnosticOutbox } = require('../server/customer-diagnostic-outbox');
const { createCustomerDiagnosticIntegrityAuthority } = require('../server/customer-diagnostic-integrity');

const NOW = Date.parse('2026-07-13T12:00:00.000Z');

function event() {
  return {
    schemaVersion: 1,
    messageId: crypto.randomUUID(),
    customerId: process.env.REDACTWALL_TENANT_ID,
    deploymentId: process.env.REDACTWALL_CONNECTED_DEPLOYMENT_ID,
    kind: 'diagnostic.event.v1',
    correlationId: crypto.randomUUID(),
    component: 'connector',
    code: 'CONNECTOR_TIMEOUT',
    severity: 'warning',
    outcome: 'retrying',
    countBucket: '1',
    sizeBucket: 'none',
    durationBucket: '1-5s',
    retryState: 'scheduled',
    componentVersion: '1.2.3',
    occurredAt: new Date(NOW).toISOString(),
  };
}

test('db exports the migrated main-store diagnostic adapter without affecting audit readiness', () => {
  const authority = createCustomerDiagnosticIntegrityAuthority({
    secret: Buffer.alloc(32, 0x44).toString('base64'), env: {},
  });
  const options = {
    customerId: process.env.REDACTWALL_TENANT_ID,
    deploymentId: process.env.REDACTWALL_CONNECTED_DEPLOYMENT_ID,
    integrityAuthority: authority,
    storage: db.customerDiagnosticStorage(),
    clock: () => NOW,
    leaseMs: 5_000,
  };
  const queue = createCustomerDiagnosticOutbox(options);
  const diagnostic = event();
  const accepted = queue.enqueue(diagnostic);
  const lease = queue.leaseReady({ limit: 1 })[0];
  assert.equal(queue.recordDelivery({
    messageId: lease.messageId,
    payloadDigest: lease.payloadDigest,
    leaseId: lease.leaseId,
    accepted: true,
  }).delivered, true);
  const restarted = createCustomerDiagnosticOutbox(options);
  assert.deepEqual(restarted.enqueue({ ...diagnostic }), {
    accepted: false, duplicate: true, digest: accepted.digest,
  });
  assert.equal(db._db.prepare(`SELECT COUNT(*) AS count
    FROM customer_diagnostic_audit WHERE customer_id = ?`).get(
    process.env.REDACTWALL_TENANT_ID,
  ).count >= 3, true);
  assert.equal(db.verifyAuditChain().ok, true);
  assert.equal(db.auditHealth().ok, true);
});

test.after(() => {
  try { db._db.close(); } catch {}
  try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
});
