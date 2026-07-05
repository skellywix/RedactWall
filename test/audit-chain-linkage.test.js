'use strict';
/**
 * Audit hash-chain LINKAGE attacks (server/audit-integrity.js).
 *
 * db.test.js proves an edited entry body fails verification; these tests cover
 * the attacks a hash chain specifically exists to catch even when every entry
 * body is self-consistent: forged prevHash links, a removed middle entry, and a
 * forged genesis link. Uses an isolated temp DB and out-of-band SQL (triggers
 * dropped) to simulate tampering the SQL guards cannot see.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-audit-link-test-' + crypto.randomBytes(6).toString('hex') + '.db');
const db = require('../server/db');
const integrity = require('../server/audit-integrity');

function readEntry(id) {
  return JSON.parse(db._db.prepare('SELECT entry FROM audit WHERE id = ?').get(id).entry);
}

// Rewrite an entry with a SELF-CONSISTENT hash (body hash matches) so only the
// prevHash linkage is wrong — this must still fail verification.
function rewriteEntry(id, mutate) {
  const { hash, ...body } = readEntry(id);
  mutate(body);
  const forged = { ...body, hash: integrity.sha(integrity.canonical(body)) };
  db._db.exec('DROP TRIGGER IF EXISTS audit_append_only_update');
  db._db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run(JSON.stringify(forged), id);
  db._db.exec("CREATE TRIGGER audit_append_only_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END");
  return forged;
}

test('a forged prevHash link fails verification even when the entry hash is self-consistent', () => {
  const entries = ['a', 'b', 'c'].map((d) => db.appendAudit({ action: 'PING', actor: 'link-test', detail: d }));
  assert.strictEqual(db.verifyAuditChain().ok, true, 'baseline verifies');

  const original = db._db.prepare('SELECT entry FROM audit WHERE id = ?').get(entries[1].id).entry;
  rewriteEntry(entries[1].id, (body) => { body.prevHash = integrity.sha('forged-link'); });

  const v = db.verifyAuditChain();
  assert.strictEqual(v.ok, false, 'forged link must fail');
  assert.strictEqual(v.reason, 'chain');
  assert.strictEqual(v.brokenAt, entries[1].id, 'break detected at the forged entry');

  db._db.exec('DROP TRIGGER IF EXISTS audit_append_only_update');
  db._db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run(original, entries[1].id);
  db._db.exec("CREATE TRIGGER audit_append_only_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END");
  assert.strictEqual(db.verifyAuditChain().ok, true, 'clean after restore');
});

test('removing a middle entry breaks the chain at its successor', () => {
  const entries = ['keep', 'remove-me', 'orphaned'].map((d) => db.appendAudit({ action: 'PING', actor: 'removal-test', detail: d }));
  assert.strictEqual(db.verifyAuditChain().ok, true, 'baseline verifies');

  const removedRow = db._db.prepare('SELECT * FROM audit WHERE id = ?').get(entries[1].id);
  db._db.exec('DROP TRIGGER IF EXISTS audit_append_only_delete');
  db._db.prepare('DELETE FROM audit WHERE id = ?').run(entries[1].id);
  db._db.exec("CREATE TRIGGER audit_append_only_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END");

  const v = db.verifyAuditChain();
  assert.strictEqual(v.ok, false, 'a removed entry must fail verification');
  assert.strictEqual(v.reason, 'chain');
  assert.strictEqual(v.brokenAt, entries[2].id, 'the successor exposes the missing link');

  const cols = Object.keys(removedRow);
  db._db.prepare(`INSERT INTO audit (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`)
    .run(...cols.map((c) => removedRow[c]));
  assert.strictEqual(db.verifyAuditChain().ok, true, 'clean after restore');
});

test('a forged genesis prevHash fails verification against the zero link', () => {
  // The first entry must chain from the all-zero hash; forging its prevHash
  // (with a self-consistent entry hash) simulates splicing in a new history.
  const firstId = JSON.parse(db._db.prepare('SELECT entry FROM audit ORDER BY seq ASC LIMIT 1').get().entry).id;
  const original = db._db.prepare('SELECT entry FROM audit WHERE id = ?').get(firstId).entry;
  rewriteEntry(firstId, (body) => { body.prevHash = integrity.sha('forged-genesis'); });

  const v = db.verifyAuditChain();
  assert.strictEqual(v.ok, false, 'forged genesis must fail');
  assert.strictEqual(v.reason, 'chain');
  assert.strictEqual(v.brokenAt, firstId);

  db._db.exec('DROP TRIGGER IF EXISTS audit_append_only_update');
  db._db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run(original, firstId);
  db._db.exec("CREATE TRIGGER audit_append_only_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END");
  assert.strictEqual(db.verifyAuditChain().ok, true, 'clean after restore');
});

test('canonical JSON is deterministic regardless of key order and handles all value shapes', () => {
  assert.strictEqual(
    integrity.canonical({ b: 1, a: { d: 2, c: [3, null, 'x'] } }),
    integrity.canonical({ a: { c: [3, null, 'x'], d: 2 }, b: 1 }),
    'key order must not change the hash input'
  );
  assert.strictEqual(integrity.canonical(null), 'null');
  assert.strictEqual(integrity.canonical([1, 'two', null]), '[1,"two",null]');
  assert.strictEqual(integrity.canonical({ z: 1, a: 2 }), '{"a":2,"z":1}');
  assert.notStrictEqual(
    integrity.canonical({ a: [1, 2] }),
    integrity.canonical({ a: [2, 1] }),
    'array order is significant'
  );
});

test('queryContentHash returns null for a query row that does not exist', () => {
  assert.strictEqual(integrity.queryContentHash(db._db, 'q_never_created'), null);
});
