'use strict';
/**
 * Security: the audit log is tamper-evident. Editing an audit row or the
 * evidence a chained entry hashes over must flip /api/audit integrity to
 * broken. The tamper happens through a second raw better-sqlite3 connection to
 * the same temp database file - exactly what an attacker with disk access
 * would do.
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const support = require('../support/app');
support.bootEnv();
const app = support.requireApp();
const Database = require(path.join(support.ROOT, 'node_modules', 'better-sqlite3'));

function withRawDb(fn) {
  const db = new Database(process.env.SENTINEL_DB_PATH);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

async function auditIntegrity(port, cookie) {
  const res = await support.request(port, '/api/audit', { headers: { cookie } });
  assert.strictEqual(res.status, 200);
  return (await res.json()).integrity;
}

test('mutating chained evidence and audit rows breaks /api/audit integrity', async () => support.withServer(app, async (port) => {
  const held = await support.seedHeldPrompt(port, { suffix: '7701' });
  const admin = await support.login(port, 'admin');
  const deny = await support.request(port, `/api/queries/${held.id}/deny`, {
    method: 'POST',
    headers: { cookie: admin.cookie, 'x-csrf-token': admin.csrfToken },
    body: { note: 'tamper baseline' },
  });
  assert.strictEqual(deny.status, 200);

  const clean = await auditIntegrity(port, admin.cookie);
  assert.strictEqual(clean.ok, true, 'chain verifies before tampering');
  assert.ok(clean.count > 0);

  // 1) Evidence tamper: rewrite the decided query's stored state.
  const originalData = withRawDb((db) => {
    const row = db.prepare('SELECT data FROM queries WHERE id = ?').get(held.id);
    const data = JSON.parse(row.data);
    data.decisionNote = 'silently rewritten after the fact';
    db.prepare('UPDATE queries SET data = ? WHERE id = ?').run(JSON.stringify(data), held.id);
    return row.data;
  });
  const evidenceBroken = await auditIntegrity(port, admin.cookie);
  assert.strictEqual(evidenceBroken.ok, false, 'evidence tamper must be detected');
  assert.strictEqual(evidenceBroken.reason, 'evidence');
  assert.strictEqual(evidenceBroken.queryId, held.id);

  // Restoring the original bytes heals the chain (proves no false positive).
  withRawDb((db) => db.prepare('UPDATE queries SET data = ? WHERE id = ?').run(originalData, held.id));
  const healed = await auditIntegrity(port, admin.cookie);
  assert.strictEqual(healed.ok, true, 'restoring the original evidence verifies again');

  // 2) Audit-row tamper: an attacker with disk access drops the append-only
  // guard triggers, then rewrites one entry's detail without recomputing hashes.
  withRawDb((db) => {
    db.exec('DROP TRIGGER IF EXISTS audit_append_only_update; DROP TRIGGER IF EXISTS audit_append_only_delete;');
    const row = db.prepare('SELECT id, entry FROM audit ORDER BY seq DESC LIMIT 1').get();
    const entry = JSON.parse(row.entry);
    entry.detail = 'forged detail';
    db.prepare('UPDATE audit SET entry = ? WHERE id = ?').run(JSON.stringify(entry), row.id);
  });
  const chainBroken = await auditIntegrity(port, admin.cookie);
  assert.strictEqual(chainBroken.ok, false, 'audit row tamper must be detected');
  assert.strictEqual(chainBroken.reason, 'chain');
  assert.ok(chainBroken.brokenAt, 'broken entry id is reported');
}));
