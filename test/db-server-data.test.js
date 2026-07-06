'use strict';
/**
 * Regression coverage for the server-data audit fixes, run against the SQLite
 * path (Postgres unavailable in the gate). Isolate the DB before requiring the
 * module — it opens the store at load time.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-sd-test-' + crypto.randomBytes(6).toString('hex') + '.db');
const db = require('../server/db');
const { wireTenantContext } = db._internal;

test('wireTenantContext pins the RLS tenant GUC only when a valid silo tenant is configured', () => {
  const calls = [];
  const driver = { setTenantContext: (org) => calls.push(org) };

  assert.strictEqual(wireTenantContext(driver, { tenantId: 'cu-acme', tenantIdValid: true }), 'cu-acme');
  assert.deepStrictEqual(calls, ['cu-acme'], 'configured silo tenant is wired onto the driver');

  assert.strictEqual(wireTenantContext(driver, { tenantId: '', tenantIdValid: true }), null);
  assert.strictEqual(wireTenantContext(driver, { tenantId: 'BAD ORG', tenantIdValid: false }), null);
  assert.deepStrictEqual(calls, ['cu-acme'], 'no tenant / invalid tenant must NOT wire a context');
});

test('wireTenantContext is a no-op on a driver without setTenantContext (SQLite)', () => {
  assert.strictEqual(wireTenantContext({}, { tenantId: 'cu-acme', tenantIdValid: true }), null);
});

test('posture action state persists across heavy unrelated audit traffic', () => {
  const actionId = 'pa_' + crypto.randomBytes(4).toString('hex');
  db.appendAudit({
    action: db._internal.POSTURE_ACTION_AUDIT,
    actor: 'admin@example.test',
    detail: JSON.stringify({ id: actionId, status: 'resolved', note: 'handled' }),
  });
  // Bury the resolution under far more than any bounded listAudit() window.
  for (let i = 0; i < 1200; i++) db.appendAudit({ action: 'INGEST', actor: 'sensor', detail: 'n' + i });

  const states = db.postureActionStates();
  assert.ok(states[actionId], 'resolved action must not be evicted by newer audit traffic');
  assert.strictEqual(states[actionId].status, 'resolved');
});

test('seatStats counts unique billable users via SQL aggregation, excluding blocked + unknown', () => {
  const org = 'cu-seat-' + crypto.randomBytes(3).toString('hex');
  db.createQuery({ status: 'allowed', orgId: org, user: 'Casey@Example.Test', redactedPrompt: 'ok' });
  db.createQuery({ status: 'pending', orgId: org, user: 'casey@example.test', redactedPrompt: 'held' });
  db.createQuery({ status: 'allowed', orgId: org, user: 'dana@example.test', redactedPrompt: 'ok' });
  db.createQuery({ status: 'seat_limit_blocked', orgId: org, user: 'blocked@example.test', redactedPrompt: 'x' });
  db.createQuery({ status: 'allowed', orgId: org, user: 'unknown', redactedPrompt: 'ok' });

  const seats = db.seatStats({ orgId: org });
  assert.strictEqual(seats.seatsUsed, 2);
  assert.deepStrictEqual(seats.users.map((u) => u.user), ['casey@example.test', 'dana@example.test']);
  const casey = seats.users.find((u) => u.user === 'casey@example.test');
  assert.strictEqual(casey.events, 2, 'case-folded duplicate users collapse into one seat');
  assert.ok(seats.users.every((u) => u.orgId === org));
});

test('verifyAuditChain still holds after the batched evidence check', () => {
  const q = db.createQuery({ status: 'pending', user: 'evidence@example.test', findings: [{ type: 'US_SSN' }] });
  db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'sensor', detail: 'ssn' });
  db.updateQuery(q.id, { status: 'approved', decisionNote: 'ok' });
  db.appendAudit({ action: 'APPROVED', queryId: q.id, actor: 'admin', detail: 'ok' });
  assert.strictEqual(db.verifyAuditChain().ok, true);
});
