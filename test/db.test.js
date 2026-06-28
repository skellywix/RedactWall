'use strict';
/**
 * Datastore + tamper-evident audit (server/db.js, SQLite-backed).
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
const db = require('../server/db');

test('queries round-trip and update transactionally', () => {
  const q = db.createQuery({ status: 'pending', user: 'alice', redactedPrompt: '[US_SSN]', findings: [{ type: 'US_SSN' }] });
  assert.ok(q.id.startsWith('q_'));
  assert.strictEqual(db.getQuery(q.id).user, 'alice');
  const upd = db.updateQuery(q.id, { status: 'approved', decidedBy: 'admin' });
  assert.strictEqual(upd.status, 'approved');
  assert.strictEqual(db.getQuery(q.id).decidedBy, 'admin');
  assert.strictEqual(db.updateQuery('q_does_not_exist', { status: 'x' }), null);
});

test('listQueries can return all rows for evidence summaries', () => {
  const first = db.createQuery({ status: 'allowed', user: 'summary-a', redactedPrompt: 'safe a' });
  const second = db.createQuery({ status: 'pending', user: 'summary-b', redactedPrompt: 'safe b' });
  const limited = db.listQueries({ limit: 1 }).map((q) => q.id);
  const all = db.listQueries({ all: true }).map((q) => q.id);

  assert.strictEqual(limited.length, 1);
  assert.ok(all.includes(first.id));
  assert.ok(all.includes(second.id));
  assert.ok(all.length > limited.length);
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

test('stats count only real blocked statuses for todayBlocked', () => {
  const before = db.stats().todayBlocked;
  for (const status of ['pending', 'file_blocked_unscanned', 'response_flagged', 'response_blocked', 'action_blocked']) {
    db.createQuery({ status, user: 'metric', redactedPrompt: '[' + status + ']' });
  }
  for (const status of ['allowed', 'redacted', 'response_redacted', 'paste_flagged', 'shadow_ai', 'warned_sent', 'justified']) {
    db.createQuery({ status, user: 'metric', redactedPrompt: '[' + status + ']' });
  }
  assert.strictEqual(db.stats().todayBlocked - before, 5);
});

test('seat stats count unique billable users by tenant', () => {
  db.createQuery({ status: 'allowed', orgId: 'cu-acme', user: 'Analyst@Example.Test', redactedPrompt: 'ok' });
  db.createQuery({ status: 'pending', orgId: 'cu-acme', user: 'analyst@example.test', redactedPrompt: 'held' });
  db.createQuery({ status: 'allowed', orgId: 'cu-acme', user: 'second@example.test', redactedPrompt: 'ok' });
  db.createQuery({ status: 'seat_limit_blocked', orgId: 'cu-acme', user: 'blocked@example.test', redactedPrompt: '[seat limit exceeded]' });
  db.createQuery({ status: 'allowed', orgId: 'other-cu', user: 'other@example.test', redactedPrompt: 'ok' });
  db.createQuery({ status: 'allowed', orgId: 'cu-acme', user: 'unknown', redactedPrompt: 'ok' });

  const seats = db.seatStats({ orgId: 'cu-acme' });
  assert.strictEqual(seats.seatsUsed, 2);
  assert.deepStrictEqual(seats.users.map((u) => u.user), ['analyst@example.test', 'second@example.test']);
  assert.ok(seats.users.every((u) => u.orgId === 'cu-acme'));
});

test('retention purge removes sealed raw/vault fields and preserves audit integrity', () => {
  const createdAt = '2026-01-01T00:00:00.000Z';
  const approved = db.createQuery({
    createdAt,
    status: 'approved',
    user: 'dana',
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'sealed-raw',
  });
  const redacted = db.createQuery({
    createdAt,
    status: 'redacted',
    user: 'erin',
    tokenizedPrompt: 'Member [[US_SSN_1]]',
    _tokenVault: 'sealed-vault',
  });
  const pending = db.createQuery({
    createdAt,
    status: 'pending',
    user: 'frank',
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'still-needed',
  });
  const recentlyDecided = db.createQuery({
    createdAt,
    status: 'approved',
    user: 'grace',
    decidedAt: '2026-02-02T00:00:00.000Z',
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'recent-decision',
  });
  db.appendAudit({ action: 'APPROVED', queryId: approved.id, actor: 'admin' });
  db.appendAudit({ action: 'REDACTED', queryId: redacted.id, actor: 'sensor' });
  db.appendAudit({ action: 'BLOCKED', queryId: pending.id, actor: 'sensor' });
  db.appendAudit({ action: 'APPROVED', queryId: recentlyDecided.id, actor: 'admin' });

  const purged = db.purgeRetainedSensitiveData({
    before: '2026-02-01T00:00:00.000Z',
    actor: 'retention',
    reason: 'rawRetentionDays=30',
  });

  assert.deepStrictEqual(purged.map((p) => p.id).sort(), [approved.id, redacted.id].sort());
  assert.strictEqual(db.getQuery(approved.id)._rawPrompt, undefined);
  assert.strictEqual(db.getQuery(redacted.id)._tokenVault, undefined);
  assert.strictEqual(db.getQuery(pending.id)._rawPrompt, 'still-needed');
  assert.strictEqual(db.getQuery(recentlyDecided.id)._rawPrompt, 'recent-decision');
  assert.strictEqual(db.listAudit(10).filter((a) => a.action === 'RETENTION_PURGED').length, 2);
  assert.strictEqual(db.verifyAuditChain().ok, true, 'purge audit event should rebind changed evidence');
});

test.after(() => { try { for (const s of ['', '-wal', '-shm']) fs.unlinkSync(process.env.SENTINEL_DB_PATH + s); } catch {} });
