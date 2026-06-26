'use strict';
/**
 * Datastore + tamper-evident audit (src/db.js, SQLite-backed).
 * Uses an isolated temp DB so it never touches real data. Run: node --test
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Isolate the DB BEFORE requiring the module (it opens the file at load time).
// An explicit SENTINEL_DB_PATH also disables legacy JSON auto-migration, so the
// test store is hermetic.
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-db-test-' + crypto.randomBytes(6).toString('hex') + '.db');
const db = require('../src/db');

test('queries round-trip and update transactionally', () => {
  const q = db.createQuery({ status: 'pending', user: 'alice', redactedPrompt: '[US_SSN]', findings: [{ type: 'US_SSN' }] });
  assert.ok(q.id.startsWith('q_'));
  assert.strictEqual(db.getQuery(q.id).user, 'alice');
  const upd = db.updateQuery(q.id, { status: 'approved', decidedBy: 'admin' });
  assert.strictEqual(upd.status, 'approved');
  assert.strictEqual(db.getQuery(q.id).decidedBy, 'admin');
  assert.strictEqual(db.updateQuery('q_does_not_exist', { status: 'x' }), null);
});

test('audit chain verifies over many sequential appends (no dropped links)', () => {
  for (let i = 0; i < 1000; i++) db.appendAudit({ action: 'PING', actor: 'load', detail: 'n' + i });
  const v = db.verifyAuditChain();
  assert.strictEqual(v.ok, true, 'chain should verify');
  assert.ok(v.count >= 1000);
});

test('tampering with an audit detail breaks the chain (then restores)', () => {
  const e = db.appendAudit({ action: 'BLOCKED', actor: 'x', detail: 'original detail' });
  const original = db._db.prepare('SELECT entry FROM audit WHERE id = ?').get(e.id).entry;
  db._db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run(JSON.stringify({ ...e, detail: 'rewritten' }), e.id);
  const v = db.verifyAuditChain();
  assert.strictEqual(v.ok, false, 'edited detail must fail verification');
  assert.strictEqual(v.reason, 'chain');
  db._db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run(original, e.id); // restore for later subtests
  assert.strictEqual(db.verifyAuditChain().ok, true, 'chain clean after restore');
});

test('tampering with a query the audit vouched for breaks evidence binding (then restores)', () => {
  const q = db.createQuery({ status: 'pending', user: 'bob', findings: [{ type: 'CREDIT_CARD' }], decisionNote: '' });
  db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'bob', detail: 'card present' });
  assert.strictEqual(db.verifyAuditChain().ok, true, 'baseline verifies');
  const original = db._db.prepare('SELECT data FROM queries WHERE id = ?').get(q.id).data;
  db._db.prepare('UPDATE queries SET data = ? WHERE id = ?').run(JSON.stringify({ ...JSON.parse(original), findings: [] }), q.id);
  const v = db.verifyAuditChain();
  assert.strictEqual(v.ok, false, 'edited evidence must fail verification');
  assert.strictEqual(v.reason, 'evidence');
  assert.strictEqual(v.queryId, q.id);
  db._db.prepare('UPDATE queries SET data = ? WHERE id = ?').run(original, q.id); // restore
  assert.strictEqual(db.verifyAuditChain().ok, true, 'clean after restore');
});

test('legitimate state transition keeps evidence binding intact', () => {
  const q = db.createQuery({ status: 'pending', user: 'carol', findings: [{ type: 'US_SSN' }] });
  db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'carol' });
  db.updateQuery(q.id, { status: 'approved', decidedBy: 'admin', decisionNote: 'ok' });
  db.appendAudit({ action: 'APPROVED', queryId: q.id, actor: 'admin', detail: 'ok' });
  assert.strictEqual(db.verifyAuditChain().ok, true, 'transition + its audit event stay consistent');
});

test.after(() => { try { for (const s of ['', '-wal', '-shm']) fs.unlinkSync(process.env.SENTINEL_DB_PATH + s); } catch {} });
