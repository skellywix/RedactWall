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
// An explicit REDACTWALL_DB_PATH also disables legacy JSON auto-migration, so the
// test store is hermetic.
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-db-test-' + crypto.randomBytes(6).toString('hex') + '.db');
const db = require('../server/db');

function createQuery(query) {
  return db.createQueryWithAudit(query, {
    action: 'TEST_QUERY_CREATED',
    actor: 'db-test',
    detail: 'transactional test fixture',
  }).row;
}

test('queries round-trip and update transactionally', () => {
  const q = createQuery({ status: 'pending', user: 'alice', redactedPrompt: '[US_SSN]', findings: [{ type: 'US_SSN' }] });
  assert.ok(q.id.startsWith('q_'));
  assert.strictEqual(db.getQuery(q.id).user, 'alice');
  const upd = db.updateQuery(q.id, { status: 'approved', decidedBy: 'admin' });
  assert.strictEqual(upd.status, 'approved');
  assert.strictEqual(db.getQuery(q.id).decidedBy, 'admin');
  assert.strictEqual(db.updateQuery('q_does_not_exist', { status: 'x' }), null);
  db.appendAudit({ action: 'TEST_QUERY_UPDATED', queryId: q.id, actor: 'db-test' });
});

test('invalid native replay snapshot rolls back query, audit, and mapping together', () => {
  const beforeQueries = db.listQueries({ all: true }).length;
  const beforeAudit = db.listAudit(5000).length;
  const key = '9'.repeat(64);
  assert.throws(
    () => db.createQueryWithAudit({
      status: 'allowed',
      orgId: 'rollback-org',
      user: 'native-rollback@example.test',
      source: 'endpoint_agent',
      channel: 'file_upload',
      redactedPrompt: 'safe',
      riskScore: Infinity,
      findings: [],
      categories: [],
      reasons: [],
    }, { action: 'ALLOWED', actor: 'native-rollback', detail: 'sanitized rollback proof' }, {
      idempotency: { scope: 'native_handoff_v1', key },
    }),
    /replay snapshot is invalid/,
  );
  assert.strictEqual(db.listQueries({ all: true }).length, beforeQueries);
  assert.strictEqual(db.listAudit(5000).length, beforeAudit);
  const mapping = db._db.prepare(
    'SELECT COUNT(*) AS n FROM ingest_idempotency WHERE scope = ? AND orgId = ? AND keyHash = ?',
  ).get('native_handoff_v1', 'rollback-org', key);
  assert.strictEqual(mapping.n, 0);
  assert.strictEqual(db.verifyAuditChain().ok, true);
});

test('listQueries can return all rows for evidence summaries', () => {
  const first = createQuery({ status: 'allowed', user: 'summary-a', redactedPrompt: 'safe a' });
  const second = createQuery({ status: 'pending', user: 'summary-b', redactedPrompt: 'safe b' });
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

test('released vendor_license_state schema remains inert historical storage', () => {
  const customerId = 'cu-historical-vendor-row';
  db._db.prepare(
    'INSERT INTO vendor_license_state ("customerId", "issuedAt", "contactAt", status) VALUES (?, ?, ?, ?)',
  ).run(customerId, 10000, 10000, 'revoked');
  assert.deepStrictEqual(db._db.prepare(
    'SELECT "customerId", status FROM vendor_license_state WHERE "customerId" = ?',
  ).get(customerId), { customerId, status: 'revoked' });
  assert.strictEqual(db.applyVendorHeartbeat, undefined);
  assert.strictEqual(db.lastVendorHeartbeat, undefined);
});

test('audit table is append-only: SQL tampering is refused outright', () => {
  const e = db.appendAudit({ action: 'BLOCKED', actor: 'x', detail: 'immutable detail' });
  assert.throws(
    () => db._db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run('{}', e.id),
    /append-only/,
  );
  assert.throws(
    () => db._db.prepare('DELETE FROM audit WHERE id = ?').run(e.id),
    /append-only/,
  );
  assert.strictEqual(db.verifyAuditChain().ok, true, 'refused tampering leaves the chain clean');
});

test('tampering with an audit detail breaks the chain (then restores)', () => {
  // Simulate OUT-OF-BAND tampering (file editor, other tooling): the trigger
  // guards SQL, the hash chain must still catch everything else.
  const e = db.appendAudit({ action: 'BLOCKED', actor: 'x', detail: 'original detail' });
  const original = db._db.prepare('SELECT entry FROM audit WHERE id = ?').get(e.id).entry;
  db._db.exec('DROP TRIGGER audit_append_only_update');
  try {
    db._db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run(JSON.stringify({ ...e, detail: 'rewritten' }), e.id);
    const v = db.verifyAuditChain();
    assert.strictEqual(v.ok, false, 'edited detail must fail verification');
    assert.strictEqual(v.reason, 'checkpoint-truncated');
  } finally {
    // A failed verification deliberately freezes later mutations. Always put
    // the out-of-band fixture back before asking the anchor to clear that
    // fail-closed state, even if an assertion above changes in the future.
    db._db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run(original, e.id);
    db._db.exec("CREATE TRIGGER audit_append_only_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END");
  }
  assert.strictEqual(db.verifyAuditChain().ok, true, 'chain clean after restore');
});

test('tampering with a query the audit vouched for breaks evidence binding (then restores)', () => {
  const q = createQuery({ status: 'pending', user: 'bob', findings: [{ type: 'CREDIT_CARD' }], decisionNote: '' });
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
  const q = createQuery({ status: 'pending', user: 'carol', findings: [{ type: 'US_SSN' }] });
  db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'carol' });
  db.updateQuery(q.id, { status: 'approved', decidedBy: 'admin', decisionNote: 'ok' });
  db.appendAudit({ action: 'APPROVED', queryId: q.id, actor: 'admin', detail: 'ok' });
  assert.strictEqual(db.verifyAuditChain().ok, true, 'transition + its audit event stay consistent');
});

test('stats count only real blocked statuses for todayBlocked', () => {
  const before = db.stats().todayBlocked;
  for (const status of ['pending', 'file_blocked_unscanned', 'response_flagged', 'response_blocked', 'action_blocked']) {
    createQuery({ status, user: 'metric', redactedPrompt: '[' + status + ']' });
  }
  for (const status of ['allowed', 'redacted', 'response_redacted', 'paste_flagged', 'shadow_ai', 'warned_sent', 'justified']) {
    createQuery({ status, user: 'metric', redactedPrompt: '[' + status + ']' });
  }
  assert.strictEqual(db.stats().todayBlocked - before, 5);
});

test('seat stats count unique billable users by tenant', () => {
  createQuery({ status: 'allowed', orgId: 'cu-acme', user: 'Analyst@Example.Test', redactedPrompt: 'ok' });
  createQuery({ status: 'pending', orgId: 'cu-acme', user: 'analyst@example.test', redactedPrompt: 'held' });
  createQuery({ status: 'allowed', orgId: 'cu-acme', user: 'second@example.test', redactedPrompt: 'ok' });
  createQuery({ status: 'seat_limit_blocked', orgId: 'cu-acme', user: 'blocked@example.test', redactedPrompt: '[seat limit exceeded]' });
  createQuery({ status: 'allowed', orgId: 'other-cu', user: 'other@example.test', redactedPrompt: 'ok' });
  createQuery({ status: 'allowed', orgId: 'cu-acme', user: 'unknown', redactedPrompt: 'ok' });

  const seats = db.seatStats({ orgId: 'cu-acme' });
  assert.strictEqual(seats.seatsUsed, 2);
  assert.deepStrictEqual(seats.users.map((u) => u.user), ['analyst@example.test', 'second@example.test']);
  assert.ok(seats.users.every((u) => u.orgId === 'cu-acme'));
});

test('seat stats count only the trailing 30-day window; REDACTWALL_SEAT_WINDOW_DAYS=all restores lifetime', () => {
  const old = new Date(Date.now() - 60 * 86400000).toISOString();
  const recent = new Date(Date.now() - 1 * 86400000).toISOString();
  db._db.prepare('INSERT INTO queries (id, createdAt, status, user, orgId, data) VALUES (?,?,?,?,?,?)')
    .run('seatwin_old', old, 'allowed', 'lapsed@window.test', 'cu-window', '{}');
  db._db.prepare('INSERT INTO queries (id, createdAt, status, user, orgId, data) VALUES (?,?,?,?,?,?)')
    .run('seatwin_new', recent, 'allowed', 'active@window.test', 'cu-window', '{}');
  db.appendAudit({ action: 'TEST_QUERY_CREATED', queryId: 'seatwin_old', actor: 'db-test' });
  db.appendAudit({ action: 'TEST_QUERY_CREATED', queryId: 'seatwin_new', actor: 'db-test' });

  const windowed = db.seatStats({ orgId: 'cu-window' });
  assert.strictEqual(windowed.seatsUsed, 1);
  assert.deepStrictEqual(windowed.users.map((u) => u.user), ['active@window.test']);

  process.env.REDACTWALL_SEAT_WINDOW_DAYS = 'all';
  try {
    assert.strictEqual(db.seatStats({ orgId: 'cu-window' }).seatsUsed, 2);
  } finally {
    delete process.env.REDACTWALL_SEAT_WINDOW_DAYS;
  }
});

test('SCIM users persist, update, list, and deactivate in the SQLite store', () => {
  const created = db.saveScimUser({
    externalId: 'entra-db-user',
    userName: 'db-user@example.test',
    displayName: 'DB User',
    active: true,
    role: 'operator',
  });
  assert.ok(created.id.startsWith('su_'));
  assert.strictEqual(db.getScimUser(created.id).userName, 'db-user@example.test');
  assert.strictEqual(db.getScimUserByUserName('DB-USER@example.test').id, created.id);

  const updated = db.saveScimUser({
    ...created,
    displayName: 'DB User Updated',
    role: 'auditor',
  });
  assert.strictEqual(updated.createdAt, created.createdAt);
  assert.strictEqual(updated.displayName, 'DB User Updated');
  assert.ok(db.listScimUsers().some((user) => user.id === created.id));

  const deactivated = db.deactivateScimUser(created.id);
  assert.strictEqual(deactivated.active, false);
  assert.strictEqual(db.deactivateScimUser('su_missing'), null);
});

test('SCIM groups persist, update, list, and delete in the SQLite store', () => {
  const created = db.saveScimGroup({
    externalId: 'entra-db-group',
    displayName: 'DB Operators',
    members: [{ value: 'su_member', display: 'member@example.test' }],
  });
  assert.ok(created.id.startsWith('sg_'));
  assert.strictEqual(db.getScimGroup(created.id).displayName, 'DB Operators');
  assert.strictEqual(db.getScimGroupByDisplayName('DB Operators').id, created.id);

  const updated = db.saveScimGroup({
    ...created,
    displayName: 'DB Reviewers',
    members: [{ value: 'su_second', display: 'second@example.test' }],
  });
  assert.strictEqual(updated.createdAt, created.createdAt);
  assert.deepStrictEqual(updated.members.map((member) => member.value), ['su_second']);
  assert.ok(db.listScimGroups().some((group) => group.id === created.id));

  const deleted = db.deleteScimGroup(created.id);
  assert.strictEqual(deleted.displayName, 'DB Reviewers');
  assert.strictEqual(db.deleteScimGroup('sg_missing'), null);
});

test('retention purge removes sealed raw/vault fields and preserves audit integrity', () => {
  const createdAt = '2026-01-01T00:00:00.000Z';
  const approved = createQuery({
    createdAt,
    status: 'approved',
    user: 'dana',
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'sealed-raw',
  });
  const redacted = createQuery({
    createdAt,
    status: 'redacted',
    user: 'erin',
    tokenizedPrompt: 'Member [[US_SSN_1]]',
    _tokenVault: 'sealed-vault',
  });
  const pending = createQuery({
    createdAt,
    status: 'pending',
    user: 'frank',
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'still-needed',
  });
  const recentlyDecided = createQuery({
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

test.after(() => { try { for (const s of ['', '-wal', '-shm']) fs.unlinkSync(process.env.REDACTWALL_DB_PATH + s); } catch {} });
