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
  const fallback = path.join(os.tmpdir(), 'promptwall', 'sentinel.db');
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

  CREATE TABLE IF NOT EXISTS scim_users (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    id        TEXT UNIQUE NOT NULL,
    userName  TEXT UNIQUE NOT NULL,
    active    INTEGER NOT NULL DEFAULT 1,
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL,
    data      TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_scim_users_username ON scim_users(userName);

  CREATE TABLE IF NOT EXISTS scim_groups (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    id          TEXT UNIQUE NOT NULL,
    displayName TEXT UNIQUE NOT NULL,
    createdAt   TEXT NOT NULL,
    updatedAt   TEXT NOT NULL,
    data        TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_scim_groups_display ON scim_groups(displayName);

  CREATE TABLE IF NOT EXISTS ai_apps (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    id            TEXT UNIQUE NOT NULL,
    canonicalHost TEXT UNIQUE NOT NULL,
    firstSeen     TEXT NOT NULL,
    lastSeen      TEXT NOT NULL,
    data          TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_ai_apps_host ON ai_apps(canonicalHost);

  CREATE TABLE IF NOT EXISTS deliveries (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    id           TEXT UNIQUE NOT NULL,
    ts           TEXT NOT NULL,
    destId       TEXT NOT NULL,
    dedupeKey    TEXT NOT NULL,
    status       TEXT NOT NULL,
    data         TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_deliveries_dest ON deliveries(destId);
  CREATE INDEX IF NOT EXISTS idx_deliveries_dedupe ON deliveries(destId, dedupeKey);

  CREATE TABLE IF NOT EXISTS detector_feedback (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT UNIQUE NOT NULL,
    createdAt  TEXT NOT NULL,
    queryId    TEXT NOT NULL,
    detectorId TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    actor      TEXT,
    data       TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_detector_feedback_query ON detector_feedback(queryId);
  CREATE INDEX IF NOT EXISTS idx_detector_feedback_detector ON detector_feedback(detectorId);
  CREATE INDEX IF NOT EXISTS idx_detector_feedback_verdict ON detector_feedback(verdict);

  CREATE TABLE IF NOT EXISTS identity_revocations (
    identity  TEXT PRIMARY KEY,
    revokedAt INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS mfa_recovery_used (
    codeIndex INTEGER PRIMARY KEY,
    usedAt    TEXT NOT NULL
  );
`);

const id = (p) => p + '_' + crypto.randomBytes(8).toString('hex');

// ---- Queries -----------------------------------------------------------------
const qInsert = sdb.prepare('INSERT INTO queries (id, createdAt, status, user, data) VALUES (@id, @createdAt, @status, @user, @data)');
const qById = sdb.prepare('SELECT data FROM queries WHERE id = ?');
const qUpdateById = sdb.prepare('UPDATE queries SET status = @status, user = @user, data = @data WHERE id = @id');
const detectorFeedbackInsert = sdb.prepare('INSERT INTO detector_feedback (id, createdAt, queryId, detectorId, verdict, actor, data) VALUES (@id, @createdAt, @queryId, @detectorId, @verdict, @actor, @data)');

function boundedLimit(value, fallback = 200, max = 5000) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(Math.trunc(parsed), max));
}

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
  const all = filter.all === true;
  const limit = boundedLimit(filter.limit, 200, filter.maxLimit || 5000);
  const rows = all
    ? (filter.status
      ? sdb.prepare('SELECT data FROM queries WHERE status = ? ORDER BY createdAt DESC, seq DESC').all(filter.status)
      : sdb.prepare('SELECT data FROM queries ORDER BY createdAt DESC, seq DESC').all())
    : (filter.status
      ? sdb.prepare('SELECT data FROM queries WHERE status = ? ORDER BY createdAt DESC, seq DESC LIMIT ?').all(filter.status, limit)
      : sdb.prepare('SELECT data FROM queries ORDER BY createdAt DESC, seq DESC LIMIT ?').all(limit));
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

function createDetectorFeedback(input = {}) {
  const now = new Date().toISOString();
  const record = {
    id: input.id || id('df'),
    createdAt: input.createdAt || now,
    queryId: String(input.queryId || '').trim(),
    detectorId: String(input.detectorId || '').trim(),
    verdict: String(input.verdict || '').trim(),
    reason: String(input.reason || '').trim().slice(0, 240),
    actor: String(input.actor || '').trim().slice(0, 120),
    role: String(input.role || '').trim().slice(0, 80),
    queryUser: String(input.queryUser || '').trim().slice(0, 160),
    orgId: String(input.orgId || '').trim().slice(0, 120),
    source: String(input.source || '').trim().slice(0, 80),
    channel: String(input.channel || '').trim().slice(0, 80),
    destination: String(input.destination || '').trim().slice(0, 253),
    queryStatus: String(input.queryStatus || '').trim().slice(0, 80),
    riskScore: Number.isFinite(Number(input.riskScore)) ? Math.max(0, Math.min(100, Math.round(Number(input.riskScore)))) : 0,
    maxSeverity: Number.isFinite(Number(input.maxSeverity)) ? Math.max(0, Math.min(4, Math.round(Number(input.maxSeverity)))) : 0,
  };
  detectorFeedbackInsert.run({
    id: record.id,
    createdAt: record.createdAt,
    queryId: record.queryId,
    detectorId: record.detectorId,
    verdict: record.verdict,
    actor: record.actor || null,
    data: JSON.stringify(record),
  });
  return record;
}

function listDetectorFeedback(filter = {}) {
  const limit = boundedLimit(filter.limit, 500, filter.maxLimit || 5000);
  const rows = filter.queryId
    ? sdb.prepare('SELECT data FROM detector_feedback WHERE queryId = ? ORDER BY createdAt DESC, seq DESC LIMIT ?').all(String(filter.queryId), limit)
    : sdb.prepare('SELECT data FROM detector_feedback ORDER BY createdAt DESC, seq DESC LIMIT ?').all(limit);
  return rows.map((r) => JSON.parse(r.data));
}

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

const POSTURE_ACTION_AUDIT = 'POSTURE_ACTION_UPDATED';
const POSTURE_ACTION_STATUSES = new Set(['open', 'assigned', 'snoozed', 'resolved']);

function parsePostureActionDetail(detail) {
  try {
    const payload = JSON.parse(String(detail || '{}'));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    const actionId = String(payload.id || '').trim();
    const status = String(payload.status || '').trim();
    if (!actionId || !POSTURE_ACTION_STATUSES.has(status)) return null;
    return {
      id: actionId.slice(0, 160),
      status,
      owner: String(payload.owner || '').trim().slice(0, 120),
      note: String(payload.note || '').trim().slice(0, 240),
      snoozeUntil: payload.snoozeUntil ? String(payload.snoozeUntil).slice(0, 80) : null,
    };
  } catch {
    return null;
  }
}

function postureActionStates(limit = 1000) {
  const rows = listAudit(limit).reverse();
  const states = {};
  for (const entry of rows) {
    if (!entry || entry.action !== POSTURE_ACTION_AUDIT) continue;
    const parsed = parsePostureActionDetail(entry.detail);
    if (!parsed) continue;
    states[parsed.id] = {
      ...parsed,
      actor: entry.actor || '',
      updatedAt: entry.ts || null,
    };
  }
  return states;
}

const RETENTION_FINAL_STATUSES = ['approved', 'denied', 'redacted'];
const SEAT_EXCLUDED_STATUSES = new Set(['seat_limit_blocked']);
const SAFE_STATUS = /^[a-z_]+$/;
const STATS_BLOCKED_STATUSES = [
  'pending',
  'pending_justification',
  'denied',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'action_blocked',
  'injection_blocked',
  'file_blocked_unscanned',
  'ocr_required',
  'response_flagged',
  'response_blocked',
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
  const rows = sdb.prepare('SELECT entry FROM audit ORDER BY seq DESC LIMIT ?').all(boundedLimit(limit, 200));
  return rows.map((r) => JSON.parse(r.entry));
}

function normalizedSeatUser(value) {
  const user = String(value || '').trim().toLowerCase();
  if (!user || user === 'unknown' || user === 'unattributed@unmanaged') return '';
  return user;
}

function normalizedSeatOrg(value) {
  return String(value || '').trim().toLowerCase();
}

function seatStats(filter = {}) {
  const wantedOrg = normalizedSeatOrg(filter.orgId);
  const rows = sdb.prepare('SELECT data FROM queries ORDER BY createdAt ASC, seq ASC').all();
  const users = new Map();
  const inactiveIdentities = inactiveScimIdentitySet();
  for (const r of rows) {
    const q = JSON.parse(r.data);
    if (SEAT_EXCLUDED_STATUSES.has(q.status)) continue;
    const orgId = normalizedSeatOrg(q.orgId);
    if (wantedOrg && orgId !== wantedOrg) continue;
    const user = normalizedSeatUser(q.user);
    if (!user) continue;
    if (inactiveIdentities.has(user)) continue; // deactivation releases the seat
    const current = users.get(user) || {
      user,
      orgId: orgId || null,
      events: 0,
      firstSeen: q.createdAt || null,
      lastSeen: q.createdAt || null,
    };
    current.events += 1;
    if (q.createdAt && (!current.firstSeen || q.createdAt < current.firstSeen)) current.firstSeen = q.createdAt;
    if (q.createdAt && (!current.lastSeen || q.createdAt > current.lastSeen)) current.lastSeen = q.createdAt;
    users.set(user, current);
  }
  const list = Array.from(users.values()).sort((a, b) => a.user.localeCompare(b.user));
  return { orgId: wantedOrg || null, seatsUsed: list.length, users: list };
}

// ---- SCIM provisioning -------------------------------------------------------
const scimUserInsert = sdb.prepare(
  'INSERT INTO scim_users (id, userName, active, createdAt, updatedAt, data) VALUES (@id, @userName, @active, @createdAt, @updatedAt, @data)',
);
const scimUserUpdate = sdb.prepare(
  'UPDATE scim_users SET userName = @userName, active = @active, updatedAt = @updatedAt, data = @data WHERE id = @id',
);
const scimUserById = sdb.prepare('SELECT data FROM scim_users WHERE id = ?');
const scimUserByUserName = sdb.prepare('SELECT data FROM scim_users WHERE lower(userName) = lower(?)');
const scimUsersAll = sdb.prepare('SELECT data FROM scim_users ORDER BY lower(userName), seq');

const scimGroupInsert = sdb.prepare(
  'INSERT INTO scim_groups (id, displayName, createdAt, updatedAt, data) VALUES (@id, @displayName, @createdAt, @updatedAt, @data)',
);
const scimGroupUpdate = sdb.prepare(
  'UPDATE scim_groups SET displayName = @displayName, updatedAt = @updatedAt, data = @data WHERE id = @id',
);
const scimGroupById = sdb.prepare('SELECT data FROM scim_groups WHERE id = ?');
const scimGroupByDisplayName = sdb.prepare('SELECT data FROM scim_groups WHERE lower(displayName) = lower(?)');
const scimGroupsAll = sdb.prepare('SELECT data FROM scim_groups ORDER BY lower(displayName), seq');

function parseStoredScim(row) {
  return row ? JSON.parse(row.data) : null;
}

function getScimUser(scimId) {
  return parseStoredScim(scimUserById.get(scimId));
}

function getScimUserByUserName(userName) {
  return parseStoredScim(scimUserByUserName.get(String(userName || '').trim()));
}

function listScimUsers() {
  return scimUsersAll.all().map(parseStoredScim);
}

function saveScimUser(user) {
  const now = new Date().toISOString();
  const existing = user.id ? getScimUser(user.id) : getScimUserByUserName(user.userName);
  const merged = {
    ...(existing || {}),
    ...user,
    id: existing ? existing.id : (user.id || id('su')),
    userName: String(user.userName || (existing && existing.userName) || '').trim(),
    active: user.active !== false,
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
  };
  const row = {
    id: merged.id,
    userName: merged.userName,
    active: merged.active ? 1 : 0,
    updatedAt: merged.updatedAt,
    data: JSON.stringify(merged),
  };
  if (existing) scimUserUpdate.run(row);
  else scimUserInsert.run({ ...row, createdAt: merged.createdAt });
  inactiveIdentityCache = null;
  if ((!existing || existing.active !== false) && merged.active === false) {
    for (const identity of scimIdentities(merged)) revokeIdentity(identity);
  }
  return merged;
}

function deactivateScimUser(scimId) {
  const existing = getScimUser(scimId);
  if (!existing) return null;
  return saveScimUser({ ...existing, active: false });
}

// ---- Identity lifecycle -------------------------------------------------------
const revocationUpsert = sdb.prepare(
  'INSERT INTO identity_revocations (identity, revokedAt) VALUES (@identity, @revokedAt) '
  + 'ON CONFLICT(identity) DO UPDATE SET revokedAt = @revokedAt',
);
const revocationByIdentity = sdb.prepare('SELECT revokedAt FROM identity_revocations WHERE identity = ?');

function normalizedIdentity(value) {
  return String(value || '').trim().toLowerCase();
}

function scimIdentities(user = {}) {
  const identities = new Set();
  const userName = normalizedIdentity(user.userName);
  if (userName) identities.add(userName);
  for (const email of Array.isArray(user.emails) ? user.emails : []) {
    const value = normalizedIdentity(email && email.value);
    if (value) identities.add(value);
  }
  return [...identities];
}

function revokeIdentity(identity, revokedAt = Date.now()) {
  const normalized = normalizedIdentity(identity);
  if (!normalized) return false;
  revocationUpsert.run({ identity: normalized, revokedAt: Math.floor(revokedAt) });
  return true;
}

function identityRevokedSince(identity, issuedAtMs) {
  const row = revocationByIdentity.get(normalizedIdentity(identity));
  if (!row) return false;
  return Number(issuedAtMs || 0) <= Number(row.revokedAt);
}

// Cached because the sensor gate consults it on every event; saveScimUser
// invalidates so provisioning changes apply immediately.
let inactiveIdentityCache = null;

function inactiveScimIdentitySet() {
  if (inactiveIdentityCache) return inactiveIdentityCache;
  const inactive = new Set();
  for (const user of listScimUsers()) {
    if (user.active === false) for (const identity of scimIdentities(user)) inactive.add(identity);
  }
  inactiveIdentityCache = inactive;
  return inactive;
}

function scimIdentityInactive(identity) {
  const normalized = normalizedIdentity(identity);
  if (!normalized) return false;
  return inactiveScimIdentitySet().has(normalized);
}

// ---- MFA recovery codes --------------------------------------------------------
const recoveryCodeInsert = sdb.prepare('INSERT INTO mfa_recovery_used (codeIndex, usedAt) VALUES (?, ?)');
const recoveryCodeUsedRow = sdb.prepare('SELECT usedAt FROM mfa_recovery_used WHERE codeIndex = ?');

function mfaRecoveryCodeUsed(codeIndex) {
  return !!recoveryCodeUsedRow.get(Math.floor(Number(codeIndex)));
}

function consumeMfaRecoveryCode(codeIndex) {
  const index = Math.floor(Number(codeIndex));
  if (!Number.isFinite(index) || index < 0 || mfaRecoveryCodeUsed(index)) return false;
  recoveryCodeInsert.run(index, new Date().toISOString());
  return true;
}

function getScimGroup(scimId) {
  return parseStoredScim(scimGroupById.get(scimId));
}

function getScimGroupByDisplayName(displayName) {
  return parseStoredScim(scimGroupByDisplayName.get(String(displayName || '').trim()));
}

function listScimGroups() {
  return scimGroupsAll.all().map(parseStoredScim);
}

function saveScimGroup(group) {
  const now = new Date().toISOString();
  const existing = group.id ? getScimGroup(group.id) : getScimGroupByDisplayName(group.displayName);
  const merged = {
    ...(existing || {}),
    ...group,
    id: existing ? existing.id : (group.id || id('sg')),
    displayName: String(group.displayName || (existing && existing.displayName) || '').trim(),
    members: Array.isArray(group.members) ? group.members : ((existing && existing.members) || []),
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
  };
  const row = {
    id: merged.id,
    displayName: merged.displayName,
    updatedAt: merged.updatedAt,
    data: JSON.stringify(merged),
  };
  if (existing) scimGroupUpdate.run(row);
  else scimGroupInsert.run({ ...row, createdAt: merged.createdAt });
  return merged;
}

function deleteScimGroup(scimId) {
  const existing = getScimGroup(scimId);
  if (!existing) return null;
  sdb.prepare('DELETE FROM scim_groups WHERE id = ?').run(scimId);
  return existing;
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
function migrateFromJson(opts = {}) {
  const env = opts.env || process.env;
  const db = opts.db || sdb;
  const queryInsert = opts.qInsert || qInsert;
  const append = opts.appendAudit || appendAudit;
  const fsModule = opts.fs || fs;
  const dataDir = opts.dataDir || DATA_DIR;
  if (env.SENTINEL_DB_PATH) return; // explicit path: caller owns its data, no legacy auto-import
  if (db.prepare('SELECT COUNT(*) n FROM queries').get().n > 0) return;
  const qf = path.join(dataDir, 'queries.json');
  const af = path.join(dataDir, 'audit.json');
  let importedQ = 0, importedA = 0;
  const tx = db.transaction(() => {
    if (fsModule.existsSync(qf)) {
      let rows = [];
      try { rows = JSON.parse(fsModule.readFileSync(qf, 'utf8')); } catch {}
      for (const r of rows) {
        if (!r || !r.id) continue;
        queryInsert.run({ id: r.id, createdAt: r.createdAt || new Date().toISOString(), status: r.status || 'pending', user: r.user || null, data: JSON.stringify(r) });
        importedQ++;
      }
    }
    if (fsModule.existsSync(af)) {
      let rows = [];
      try { rows = JSON.parse(fsModule.readFileSync(af, 'utf8')); } catch {}
      rows.sort((a, b) => (a.ts < b.ts ? -1 : 1));
      for (const e of rows) { append({ action: e.action, queryId: e.queryId, actor: e.actor, detail: e.detail }); importedA++; }
    }
  });
  tx();
  if (importedQ || importedA) {
    append({ action: 'STORE_MIGRATED', actor: 'system', detail: `imported ${importedQ} queries, ${importedA} audit events from JSON store (re-anchored)` });
    try {
      if (fsModule.existsSync(qf)) fsModule.renameSync(qf, qf + '.migrated');
      if (fsModule.existsSync(af)) fsModule.renameSync(af, af + '.migrated');
    } catch {}
  }
}
try { migrateFromJson(); } catch (e) { console.error('[db] migration skipped:', e.message); }

// ---- AI app catalog ----------------------------------------------------------
const aiAppInsert = sdb.prepare('INSERT INTO ai_apps (id, canonicalHost, firstSeen, lastSeen, data) VALUES (@id, @canonicalHost, @firstSeen, @lastSeen, @data)');
const aiAppByHost = sdb.prepare('SELECT data FROM ai_apps WHERE canonicalHost = ?');
const aiAppUpdate = sdb.prepare('UPDATE ai_apps SET lastSeen = @lastSeen, data = @data WHERE canonicalHost = @canonicalHost');

function getAiApp(canonicalHost) {
  const row = aiAppByHost.get(canonicalHost);
  return row ? JSON.parse(row.data) : null;
}

function listAiApps() {
  return sdb.prepare('SELECT data FROM ai_apps ORDER BY lastSeen DESC, seq DESC').all().map((r) => JSON.parse(r.data));
}

// Insert-or-update a catalog entry keyed by canonical host. `patch` is merged
// over the stored record; discovery counters are additive via the caller.
const upsertAiApp = sdb.transaction((canonicalHost, patch, now) => {
  const existing = getAiApp(canonicalHost);
  if (existing) {
    const merged = { ...existing, ...patch, canonicalHost, id: existing.id, firstSeen: existing.firstSeen, lastSeen: now };
    aiAppUpdate.run({ canonicalHost, lastSeen: now, data: JSON.stringify(merged) });
    return merged;
  }
  const record = { id: id('app'), canonicalHost, firstSeen: now, lastSeen: now, ...patch };
  aiAppInsert.run({ id: record.id, canonicalHost, firstSeen: now, lastSeen: now, data: JSON.stringify(record) });
  return record;
});

// ---- Delivery history (SIEM/SOAR subscriptions) ------------------------------
const deliveryInsert = sdb.prepare('INSERT INTO deliveries (id, ts, destId, dedupeKey, status, data) VALUES (@id, @ts, @destId, @dedupeKey, @status, @data)');

function recordDelivery(record) {
  const row = { id: id('dlv'), ts: new Date().toISOString(), destId: record.destId, dedupeKey: record.dedupeKey || '', status: record.status || 'unknown', ...record };
  deliveryInsert.run({ id: row.id, ts: row.ts, destId: row.destId, dedupeKey: row.dedupeKey, status: row.status, data: JSON.stringify(row) });
  // Bounded history: keep the most recent 2000 rows.
  sdb.prepare('DELETE FROM deliveries WHERE seq <= (SELECT MAX(seq) - 2000 FROM deliveries)').run();
  return row;
}

function listDeliveries(limit = 200) {
  const n = Math.max(1, Math.min(2000, Number(limit) || 200));
  return sdb.prepare('SELECT data FROM deliveries ORDER BY seq DESC LIMIT ?').all(n).map((r) => JSON.parse(r.data));
}

function recentDeliverySuccess(destId, dedupeKey, sinceIso) {
  const row = sdb.prepare('SELECT data FROM deliveries WHERE destId = ? AND dedupeKey = ? AND status = ? ORDER BY seq DESC LIMIT 1').get(destId, dedupeKey, 'delivered');
  if (!row) return false;
  const rec = JSON.parse(row.data);
  return !sinceIso || rec.ts >= sinceIso;
}

module.exports = {
  createQuery, getQuery, listQueries, updateQuery,
  createDetectorFeedback, listDetectorFeedback,
  purgeRetainedSensitiveData,
  appendAudit, listAudit, verifyAuditChain, stats, seatStats, postureActionStates,
  getScimUser, getScimUserByUserName, listScimUsers, saveScimUser, deactivateScimUser,
  revokeIdentity, identityRevokedSince, scimIdentityInactive,
  mfaRecoveryCodeUsed, consumeMfaRecoveryCode,
  getScimGroup, getScimGroupByDisplayName, listScimGroups, saveScimGroup, deleteScimGroup,
  getAiApp, listAiApps, upsertAiApp,
  recordDelivery, listDeliveries, recentDeliverySuccess,
  _canonical: canonical, _db: sdb, _dbPath: DB_PATH,
  _internal: { migrateFromJson, parsePostureActionDetail, POSTURE_ACTION_AUDIT },
};
