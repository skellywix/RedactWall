'use strict';
/**
 * Transactional datastore + tamper-evident audit log (SQLite / better-sqlite3).
 *
 * Why SQLite, not the old JSON file: the JSON store did unlocked
 * read-modify-write — two near-simultaneous writes last-write-win the whole
 * file, silently dropping an entry and breaking the audit hash-chain linkage
 * (REVIEW.md #6). With three sensors + SSE + polling that race is real even at
 * tiny scale, and a corrupted audit log is the one thing this product cannot
 * ship. better-sqlite3 gives real ACID transactions and WAL concurrency.
 *
 * Storage location: defaults to data/sentinel.db. A live SQLite file must sit
 * on LOCAL disk — never a network/cloud-synced share (locking + mmap break).
 * If the configured path's filesystem rejects SQLite, we fall back to a local
 * OS dir and log loudly. Set SENTINEL_DB_PATH to a real local-disk path (or a
 * managed Postgres in front of this interface) in production.
 *
 * Tamper-evidence (REVIEW.md #5): every audit entry's hash covers a CANONICAL
 * serialization of the FULL entry (action, queryId, actor, detail, ts,
 * prevHash, and — when the event names a query — a contentHash of that query's
 * current state). Editing a query's findings, decisionNote, or an audit detail
 * after the fact breaks verification, not just the thin event header.
 */
require('./env').loadEnv();
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const integrity = require('./audit-integrity');

const DATA_DIR = path.join(__dirname, '..', 'data');
const ZERO = integrity.ZERO;
const sha = integrity.sha;
const canonical = integrity.canonical;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Open a DB at `p`, preferring WAL, and force a real write so a filesystem that
// cannot host SQLite fails HERE (where we can fall back) rather than later.
function openAt(p) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const d = new Database(p);
  try { d.pragma('journal_mode = WAL'); } catch { try { d.pragma('journal_mode = DELETE'); } catch {} }
  try { d.pragma('synchronous = NORMAL'); } catch {}
  try { d.pragma('foreign_keys = ON'); } catch {}
  d.exec('CREATE TABLE IF NOT EXISTS _probe (x); DROP TABLE _probe;'); // throws on a bad FS
  return d;
}

let DB_PATH = process.env.SENTINEL_DB_PATH || path.join(DATA_DIR, 'sentinel.db');
let sdb;
try {
  sdb = openAt(DB_PATH);
} catch (e) {
  const fallback = path.join(os.tmpdir(), 'promptsentinel', 'sentinel.db');
  console.error(`[db] store at ${DB_PATH} unusable (${e.code || e.message}); falling back to ${fallback}. ` +
    'Set SENTINEL_DB_PATH to a local-disk path in production (never a cloud-synced folder).');
  DB_PATH = fallback;
  sdb = openAt(DB_PATH);
}

sdb.exec(`
  CREATE TABLE IF NOT EXISTS queries (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT UNIQUE NOT NULL,
    createdAt  TEXT NOT NULL,
    status     TEXT NOT NULL,
    user       TEXT,
    data       TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_queries_status ON queries(status);
  CREATE INDEX IF NOT EXISTS idx_queries_created ON queries(createdAt);

  CREATE TABLE IF NOT EXISTS audit (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    id        TEXT UNIQUE NOT NULL,
    ts        TEXT NOT NULL,
    action    TEXT,
    queryId   TEXT,
    actor     TEXT,
    prevHash  TEXT NOT NULL,
    hash      TEXT NOT NULL,
    entry     TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_audit_query ON audit(queryId);
`);

const id = (p) => p + '_' + crypto.randomBytes(8).toString('hex');

// ---- Queries -----------------------------------------------------------------
const qInsert = sdb.prepare('INSERT INTO queries (id, createdAt, status, user, data) VALUES (@id, @createdAt, @status, @user, @data)');
const qById = sdb.prepare('SELECT data FROM queries WHERE id = ?');
const qUpdateById = sdb.prepare('UPDATE queries SET status = @status, user = @user, data = @data WHERE id = @id');

function createQuery(q) {
  const row = { id: id('q'), createdAt: new Date().toISOString(), status: 'pending', ...q };
  qInsert.run({ id: row.id, createdAt: row.createdAt, status: row.status, user: row.user || null, data: JSON.stringify(row) });
  return row;
}
function getQuery(qid) {
  const r = qById.get(qid);
  return r ? JSON.parse(r.data) : null;
}
function listQueries(filter = {}) {
  const limit = filter.limit ? Math.max(1, Number(filter.limit)) : 200;
  const rows = filter.status
    ? sdb.prepare('SELECT data FROM queries WHERE status = ? ORDER BY createdAt DESC, seq DESC LIMIT ?').all(filter.status, limit)
    : sdb.prepare('SELECT data FROM queries ORDER BY createdAt DESC, seq DESC LIMIT ?').all(limit);
  return rows.map((r) => JSON.parse(r.data));
}
// Read-modify-write wrapped in a transaction so concurrent updates can't race.
const updateQuery = sdb.transaction((qid, patch) => {
  const cur = qById.get(qid);
  if (!cur) return null;
  const merged = { ...JSON.parse(cur.data), ...patch };
  qUpdateById.run({ id: qid, status: merged.status, user: merged.user || null, data: JSON.stringify(merged) });
  return merged;
});

/** Hash of a query's current full state — binds the evidence into the chain. */
function queryContentHash(qid) {
  return integrity.queryContentHash(sdb, qid);
}

// ---- Audit (append-only, hash-chained over the FULL canonical entry) ---------
const aLast = sdb.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1');
const aInsert = sdb.prepare('INSERT INTO audit (id, ts, action, queryId, actor, prevHash, hash, entry) VALUES (@id, @ts, @action, @queryId, @actor, @prevHash, @hash, @entry)');

function appendAuditRecord(event) {
  const last = aLast.get();
  const prevHash = last ? last.hash : ZERO;
  const contentHash = event.queryId ? queryContentHash(event.queryId) : undefined;
  const body = {
    id: id('a'),
    ts: new Date().toISOString(),
    prevHash,
    action: event.action || '',
    queryId: event.queryId || '',
    actor: event.actor || '',
    detail: event.detail || '',
    ...(contentHash ? { contentHash } : {}),
  };
  const hash = sha(canonical(body));
  const entry = { ...body, hash };
  aInsert.run({
    id: body.id, ts: body.ts, action: body.action, queryId: body.queryId || null,
    actor: body.actor || null, prevHash, hash, entry: JSON.stringify(entry),
  });
  return entry;
}

const appendAudit = sdb.transaction((event) => {
  return appendAuditRecord(event);
});

const RETENTION_FINAL_STATUSES = ['approved', 'denied', 'redacted'];
const SAFE_STATUS = /^[a-z_]+$/;
const STATS_BLOCKED_STATUSES = [
  'pending',
  'pending_justification',
  'denied',
  'blocked_by_user',
  'injection_blocked',
  'file_blocked_unscanned',
  'response_flagged',
];

function normalizePurgeStatuses(statuses) {
  const input = Array.isArray(statuses) && statuses.length ? statuses : RETENTION_FINAL_STATUSES;
  return [...new Set(input.map((s) => String(s || '').trim()).filter((s) => SAFE_STATUS.test(s)))];
}

const purgeRetainedSensitiveData = sdb.transaction((options = {}) => {
  const before = options.before instanceof Date ? options.before.toISOString() : String(options.before || '');
  if (!before) return [];
  const statuses = normalizePurgeStatuses(options.statuses);
  if (!statuses.length) return [];
  const placeholders = statuses.map(() => '?').join(', ');
  const rows = sdb.prepare(
    `SELECT data FROM queries WHERE createdAt < ? AND status IN (${placeholders}) ORDER BY createdAt ASC, seq ASC`,
  ).all(before, ...statuses);
  const now = new Date().toISOString();
  const purged = [];
  for (const r of rows) {
    const q = JSON.parse(r.data);
    const retentionAnchor = q.decidedAt || q.createdAt;
    if (retentionAnchor && retentionAnchor >= before) continue;
    const fields = [];
    if (q._rawPrompt) fields.push('rawPrompt');
    if (q._tokenVault) fields.push('tokenVault');
    if (!fields.length) continue;
    delete q._rawPrompt;
    delete q._tokenVault;
    q.retentionPurgedAt = now;
    q.retentionPurgedFields = fields;
    q.retentionPurgeReason = options.reason || 'retention window elapsed';
    qUpdateById.run({ id: q.id, status: q.status, user: q.user || null, data: JSON.stringify(q) });
    appendAuditRecord({
      action: 'RETENTION_PURGED',
      queryId: q.id,
      actor: options.actor || 'system',
      detail: fields.join(',') + ' removed after retention cutoff ' + before,
    });
    purged.push({ id: q.id, status: q.status, fields });
  }
  return purged;
});

function listAudit(limit = 200) {
  const rows = sdb.prepare('SELECT entry FROM audit ORDER BY seq DESC LIMIT ?').all(Math.max(1, Number(limit) || 200));
  return rows.map((r) => JSON.parse(r.entry));
}

/**
 * Verify the chain AND the evidence binding.
 *  - chain: each entry hash == sha256(canonical(entry-minus-hash)), prevHash links.
 *  - evidence: for every query, the most recent audit entry that recorded a
 *    contentHash must still match the query's current content hash.
 */
function verifyAuditChain() {
  return integrity.verifyAuditChainForDatabase(sdb);
}

// ---- Stats -------------------------------------------------------------------
function stats() {
  const counts = {};
  for (const r of sdb.prepare('SELECT status, COUNT(*) n FROM queries GROUP BY status').all()) counts[r.status] = r.n;
  const total = sdb.prepare('SELECT COUNT(*) n FROM queries').get().n;
  const today = new Date().toISOString().slice(0, 10);
  const blockedPlaceholders = STATS_BLOCKED_STATUSES.map(() => '?').join(', ');
  const todayBlocked = sdb.prepare(
    `SELECT COUNT(*) n FROM queries WHERE substr(createdAt,1,10) = ? AND status IN (${blockedPlaceholders})`,
  ).get(today, ...STATS_BLOCKED_STATUSES).n;
  const entity = {};
  for (const r of sdb.prepare('SELECT data FROM queries').all()) {
    const ec = JSON.parse(r.data).entityCounts || {};
    for (const [k, v] of Object.entries(ec)) entity[k] = (entity[k] || 0) + v;
  }
  return {
    total,
    pending: counts.pending || 0,
    approved: counts.approved || 0,
    denied: counts.denied || 0,
    allowed: counts.allowed || 0,
    todayBlocked,
    topEntities: Object.entries(entity).sort((a, b) => b[1] - a[1]).slice(0, 8),
  };
}

// ---- One-time migration from the legacy JSON store ---------------------------
function migrateFromJson() {
  if (process.env.SENTINEL_DB_PATH) return; // explicit path: caller owns its data, no legacy auto-import
  if (sdb.prepare('SELECT COUNT(*) n FROM queries').get().n > 0) return;
  const qf = path.join(DATA_DIR, 'queries.json');
  const af = path.join(DATA_DIR, 'audit.json');
  let importedQ = 0, importedA = 0;
  const tx = sdb.transaction(() => {
    if (fs.existsSync(qf)) {
      let rows = [];
      try { rows = JSON.parse(fs.readFileSync(qf, 'utf8')); } catch {}
      for (const r of rows) {
        if (!r || !r.id) continue;
        qInsert.run({ id: r.id, createdAt: r.createdAt || new Date().toISOString(), status: r.status || 'pending', user: r.user || null, data: JSON.stringify(r) });
        importedQ++;
      }
    }
    if (fs.existsSync(af)) {
      let rows = [];
      try { rows = JSON.parse(fs.readFileSync(af, 'utf8')); } catch {}
      rows.sort((a, b) => (a.ts < b.ts ? -1 : 1));
      for (const e of rows) { appendAudit({ action: e.action, queryId: e.queryId, actor: e.actor, detail: e.detail }); importedA++; }
    }
  });
  tx();
  if (importedQ || importedA) {
    appendAudit({ action: 'STORE_MIGRATED', actor: 'system', detail: `imported ${importedQ} queries, ${importedA} audit events from JSON store (re-anchored)` });
    try {
      if (fs.existsSync(qf)) fs.renameSync(qf, qf + '.migrated');
      if (fs.existsSync(af)) fs.renameSync(af, af + '.migrated');
    } catch {}
  }
}
try { migrateFromJson(); } catch (e) { console.error('[db] migration skipped:', e.message); }

module.exports = {
  createQuery, getQuery, listQueries, updateQuery,
  purgeRetainedSensitiveData,
  appendAudit, listAudit, verifyAuditChain, stats,
  _canonical: canonical, _db: sdb, _dbPath: DB_PATH,
};
