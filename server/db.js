'use strict';
/**
 * Transactional datastore + tamper-evident audit log (SQLite / better-sqlite3).
 *
 * Why SQLite, not the old JSON file: the JSON store did unlocked
 * read-modify-write — two near-simultaneous writes last-write-win the whole
 * file, silently dropping an entry and breaking the audit hash-chain linkage
 * With three sensors + SSE + polling that race is real even at
 * tiny scale, and a corrupted audit log is the one thing this product cannot
 * ship. better-sqlite3 gives real ACID transactions and WAL concurrency.
 *
 * Storage location: defaults to data/redactwall.db. A live SQLite file must sit
 * on LOCAL disk — never a network/cloud-synced share (locking + mmap break).
 * If the configured path's filesystem rejects SQLite, we fall back to a local
 * OS dir and log loudly. Set REDACTWALL_DB_PATH to a real local-disk path (or a
 * managed Postgres in front of this interface) in production.
 *
 * Tamper-evidence: every audit entry's hash covers a CANONICAL
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
const storage = require('./storage');
const integrity = require('./audit-integrity');
const tenant = require('./tenant');

const DATA_DIR = path.join(__dirname, '..', 'data');
const ZERO = integrity.ZERO;
const sha = integrity.sha;
const canonical = integrity.canonical;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const store = storage.openStore({ env: process.env, dataDir: DATA_DIR });
const sdb = store.driver;
const DB_PATH = store.dbPath;
const DRIVER_KIND = store.kind;
storage.runMigrations(sdb, DRIVER_KIND);

/** Postgres row-level security context; no-op on single-node SQLite. */
function setTenantContext(orgId) {
  if (typeof sdb.setTenantContext === 'function') sdb.setTenantContext(orgId);
}

/**
 * Wire Postgres row-level security for the customer-silo deployment tenant.js
 * implements (one RedactWall stack per customer). With a tenant configured we
 * pin the driver's session GUC to it at startup so the v3 RLS policy actually
 * enforces isolation instead of sitting inert; the pg worker re-applies the GUC
 * across reconnects. No-op on SQLite and when no tenant is configured (operator
 * / self-host mode, RLS fail-open by design). Per-request multi-tenancy on a
 * SHARED plane is out of scope and would need a transaction-local GUC bound on
 * the request path — do not rely on this for that model.
 */
function wireTenantContext(driver = sdb, cfg = tenant.config(process.env)) {
  if (cfg && cfg.tenantId && cfg.tenantIdValid && typeof driver.setTenantContext === 'function') {
    driver.setTenantContext(cfg.tenantId);
    return cfg.tenantId;
  }
  return null;
}
try { wireTenantContext(); } catch (e) { console.error('[db] tenant context not wired:', e.message); }


const id = (p) => p + '_' + crypto.randomBytes(8).toString('hex');
const orgColumn = (value) => String(value || '').trim().toLowerCase() || null;

// ---- Queries -----------------------------------------------------------------
const qInsert = sdb.prepare('INSERT INTO queries (id, createdAt, status, user, orgId, data) VALUES (@id, @createdAt, @status, @user, @orgId, @data)');
const qById = sdb.prepare('SELECT data FROM queries WHERE id = ?');
const qUpdateById = sdb.prepare('UPDATE queries SET status = @status, user = @user, orgId = @orgId, data = @data WHERE id = @id');
const detectorFeedbackInsert = sdb.prepare('INSERT INTO detector_feedback (id, createdAt, queryId, detectorId, verdict, actor, data) VALUES (@id, @createdAt, @queryId, @detectorId, @verdict, @actor, @data)');

function boundedLimit(value, fallback = 200, max = 5000) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(Math.trunc(parsed), max));
}

function createQuery(q) {
  const row = { id: id('q'), createdAt: new Date().toISOString(), status: 'pending', ...q };
  qInsert.run({ id: row.id, createdAt: row.createdAt, status: row.status, user: row.user || null, orgId: orgColumn(row.orgId), data: JSON.stringify(row) });
  return row;
}
function getQuery(qid) {
  const r = qById.get(qid);
  return r ? JSON.parse(r.data) : null;
}
function listQueries(filter = {}) {
  const all = filter.all === true;
  const limit = boundedLimit(filter.limit, 200, filter.maxLimit || 5000);
  const where = [];
  const params = [];
  if (filter.status) { where.push('status = ?'); params.push(filter.status); }
  if (filter.orgId) { where.push('orgId = ?'); params.push(String(filter.orgId).trim().toLowerCase()); }
  const clause = where.length ? ` WHERE ${where.join(' AND ')}` : '';
  const tail = all ? '' : ' LIMIT ?';
  if (!all) params.push(limit);
  const rows = sdb.prepare(`SELECT data FROM queries${clause} ORDER BY createdAt DESC, seq DESC${tail}`).all(...params);
  return rows.map((r) => JSON.parse(r.data));
}
// Read-modify-write wrapped in a transaction so concurrent updates can't race.
// A single-writer SQLite transaction already serializes this; on a shared
// Postgres plane two instances could both read the pre-image under READ
// COMMITTED and lose one patch, so take a transaction-scoped per-row advisory
// lock first (no-op on SQLite, which lacks the hook).
const updateQuery = sdb.transaction((qid, patch) => {
  if (typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(qid);
  const cur = qById.get(qid);
  if (!cur) return null;
  const merged = { ...JSON.parse(cur.data), ...patch };
  qUpdateById.run({ id: qid, status: merged.status, user: merged.user || null, orgId: orgColumn(merged.orgId), data: JSON.stringify(merged) });
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
  // Serialize concurrent appends on a shared database (Postgres multi-instance)
  // so the read-head-then-insert below is atomic and the hash chain cannot fork.
  // No-op on SQLite, whose single-writer transaction already serializes writes.
  if (typeof sdb.lockAuditAppend === 'function') sdb.lockAuditAppend();
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

// Posture-action workflow state is persistent: it must reconstruct from EVERY
// posture entry (oldest -> newest so the latest wins), not the last N entries
// of the whole log — otherwise ordinary ingest traffic evicts the update entry
// and a resolved/snoozed action silently reverts to open. Scoped by action via
// idx_audit_action so it stays cheap on a busy append-only log.
const aPostureEntries = sdb.prepare('SELECT entry FROM audit WHERE action = ? ORDER BY seq ASC');

function postureActionStates() {
  const states = {};
  for (const row of aPostureEntries.all(POSTURE_ACTION_AUDIT)) {
    const entry = JSON.parse(row.entry);
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
const SEAT_EXCLUDED_STATUSES = new Set(['seat_limit_blocked', 'license_revoked']);
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
    qUpdateById.run({ id: q.id, status: q.status, user: q.user || null, orgId: orgColumn(q.orgId), data: JSON.stringify(q) });
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

// Aggregate seats in SQL over the indexed user/org/createdAt columns instead of
// scanning + JSON.parsing every queries row: seatStats runs on every billable
// ingest when a seat limit is set, so the old full-table parse made ingest
// latency grow with history. GROUP BY lower(user) mirrors normalizedSeatUser's
// case-folding; unknown/unattributed and SCIM-inactive users are dropped after.
const SEAT_EXCLUDED_LIST = [...SEAT_EXCLUDED_STATUSES].map((s) => `'${s}'`).join(', ');
// A seat is a distinct billable user seen in the trailing window (default 30
// days, matching docs/process/CUSTOMER_LICENSING.md), so inactive identities roll off
// and billing reflects current usage. ISO-8601 createdAt compares
// chronologically, so a string cutoff uses idx_queries_created directly.
// REDACTWALL_SEAT_WINDOW_DAYS=0 (or 'all') restores lifetime counting.
const SEAT_SELECT = `SELECT lower("user") AS user, COUNT(*) AS events, MIN("createdAt") AS firstSeen,
    MAX("createdAt") AS lastSeen, MIN("orgId") AS orgId FROM queries
  WHERE "user" IS NOT NULL AND status NOT IN (${SEAT_EXCLUDED_LIST}) AND "createdAt" >= ?`;
const seatStatsAll = sdb.prepare(`${SEAT_SELECT} GROUP BY lower("user")`);
const seatStatsByOrg = sdb.prepare(`${SEAT_SELECT} AND lower("orgId") = ? GROUP BY lower("user")`);

const DEFAULT_SEAT_WINDOW_DAYS = 30;
function seatWindowDays() {
  const raw = process.env.REDACTWALL_SEAT_WINDOW_DAYS;
  if (raw == null || raw === '') return DEFAULT_SEAT_WINDOW_DAYS;
  if (String(raw).toLowerCase() === 'all') return 0;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : DEFAULT_SEAT_WINDOW_DAYS;
}

// Cutoff ISO for the seat window; '' (matches every createdAt) when windowless.
function seatCutoff(nowMs) {
  const days = seatWindowDays();
  if (!days) return '';
  return new Date((Number.isFinite(nowMs) ? nowMs : Date.now()) - days * 24 * 60 * 60 * 1000).toISOString();
}

function seatStats(filter = {}) {
  const wantedOrg = normalizedSeatOrg(filter.orgId);
  const cutoff = seatCutoff(filter.nowMs);
  const rows = wantedOrg ? seatStatsByOrg.all(cutoff, wantedOrg) : seatStatsAll.all(cutoff);
  const inactiveIdentities = inactiveScimIdentitySet();
  const users = [];
  for (const r of rows) {
    const user = normalizedSeatUser(r.user);
    if (!user || inactiveIdentities.has(user)) continue; // deactivation releases the seat
    users.push({
      user,
      orgId: normalizedSeatOrg(r.orgId) || null,
      events: r.events,
      firstSeen: r.firstSeen || null,
      lastSeen: r.lastSeen || null,
    });
  }
  users.sort((a, b) => a.user.localeCompare(b.user));
  return { orgId: wantedOrg || null, seatsUsed: users.length, users };
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
// invalidates locally so provisioning changes apply immediately on THIS
// instance. On a shared Postgres plane a deactivation handled by another
// instance never fires our local invalidation, so the cache is also bounded by
// a short TTL and revalidated against a cheap version signature (row count +
// newest updatedAt) — a deprovisioned user stops passing the gate everywhere
// within the TTL instead of only after a restart.
const scimVersionStmt = sdb.prepare('SELECT COUNT(*) AS n, MAX(updatedAt) AS v FROM scim_users');
const INACTIVE_CACHE_TTL_MS = (() => {
  const n = Number(process.env.REDACTWALL_SCIM_CACHE_TTL_MS);
  return Number.isFinite(n) && n >= 0 ? n : 5000;
})();
let inactiveIdentityCache = null;
let inactiveIdentityVersion = null;
let inactiveIdentityCheckedAt = 0;

function inactiveScimIdentitySet() {
  const now = Date.now();
  if (inactiveIdentityCache && (now - inactiveIdentityCheckedAt) < INACTIVE_CACHE_TTL_MS) {
    return inactiveIdentityCache;
  }
  const ver = scimVersionStmt.get() || {};
  const signature = `${ver.n || 0}:${ver.v || ''}`;
  inactiveIdentityCheckedAt = now;
  if (inactiveIdentityCache && signature === inactiveIdentityVersion) return inactiveIdentityCache;
  const inactive = new Set();
  for (const user of listScimUsers()) {
    if (user.active === false) for (const identity of scimIdentities(user)) inactive.add(identity);
  }
  inactiveIdentityCache = inactive;
  inactiveIdentityVersion = signature;
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
// topEntities requires scanning and JSON-parsing every query row, and stats()
// is broadcast after essentially every ingest event. Cache the result for a
// short interval so this O(N) scan runs at most once per window instead of once
// per request; the "top data types" widget tolerates a few seconds of lag.
const TOP_ENTITIES_TTL_MS = (() => {
  const n = Number(process.env.REDACTWALL_TOP_ENTITIES_TTL_MS);
  return Number.isFinite(n) && n >= 0 ? n : 10000;
})();
let _topEntitiesCache = null;
let _topEntitiesAt = 0;
function topEntities() {
  const now = Date.now();
  if (_topEntitiesCache && now - _topEntitiesAt < TOP_ENTITIES_TTL_MS) return _topEntitiesCache;
  const entity = {};
  for (const r of sdb.prepare('SELECT data FROM queries').all()) {
    const ec = JSON.parse(r.data).entityCounts || {};
    for (const [k, v] of Object.entries(ec)) entity[k] = (entity[k] || 0) + v;
  }
  _topEntitiesCache = Object.entries(entity).sort((a, b) => b[1] - a[1]).slice(0, 8);
  _topEntitiesAt = now;
  return _topEntitiesCache;
}

function stats() {
  const counts = {};
  for (const r of sdb.prepare('SELECT status, COUNT(*) n FROM queries GROUP BY status').all()) counts[r.status] = r.n;
  const total = sdb.prepare('SELECT COUNT(*) n FROM queries').get().n;
  const today = new Date().toISOString().slice(0, 10);
  const blockedPlaceholders = STATS_BLOCKED_STATUSES.map(() => '?').join(', ');
  const todayBlocked = sdb.prepare(
    `SELECT COUNT(*) n FROM queries WHERE substr(createdAt,1,10) = ? AND status IN (${blockedPlaceholders})`,
  ).get(today, ...STATS_BLOCKED_STATUSES).n;
  return {
    total,
    pending: counts.pending || 0,
    approved: counts.approved || 0,
    denied: counts.denied || 0,
    allowed: counts.allowed || 0,
    todayBlocked,
    topEntities: topEntities(),
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
  if (env.REDACTWALL_DB_PATH) return; // explicit path: caller owns its data, no legacy auto-import
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
        queryInsert.run({ id: r.id, createdAt: r.createdAt || new Date().toISOString(), status: r.status || 'pending', user: r.user || null, orgId: orgColumn(r.orgId), data: JSON.stringify(r) });
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

// ---- AI use-case inventory (PLANS/ncua-readiness-center.md slice 2) -----------
const useCaseInsert = sdb.prepare('INSERT INTO ai_use_cases (id, orgId, canonicalHost, department, reviewStatus, nextReviewAt, createdAt, updatedAt, data) VALUES (@id, @orgId, @canonicalHost, @department, @reviewStatus, @nextReviewAt, @createdAt, @updatedAt, @data)');
const useCaseById = sdb.prepare('SELECT data FROM ai_use_cases WHERE id = ?');
const useCaseByKey = sdb.prepare('SELECT data FROM ai_use_cases WHERE canonicalHost = ? AND department = ?');
const useCaseUpdate = sdb.prepare('UPDATE ai_use_cases SET orgId = @orgId, reviewStatus = @reviewStatus, nextReviewAt = @nextReviewAt, updatedAt = @updatedAt, data = @data WHERE id = @id');

// Departments are stored normalized: the unique-key column is trimmed,
// single-spaced, AND lowercased so 'Lending' and 'lending ' cannot become two
// rows under the default case-sensitive collation; the record keeps the
// operator's display casing.
const departmentDisplay = (value) => String(value || '').trim().replace(/\s+/g, ' ');
const departmentKey = (value) => departmentDisplay(value).toLowerCase();

// Drop undefined-valued keys before merging a patch over a stored record: a
// route that omits a field must not erase it (spread copies undefined keys and
// JSON.stringify then deletes them).
function definedEntries(record) {
  return Object.fromEntries(Object.entries(record || {}).filter(([, value]) => value !== undefined));
}

function getAiUseCase(useCaseId) {
  const row = useCaseById.get(useCaseId);
  return row ? JSON.parse(row.data) : null;
}

function listAiUseCases() {
  return sdb.prepare('SELECT data FROM ai_use_cases ORDER BY department, canonicalHost, seq').all().map((r) => JSON.parse(r.data));
}

function useCaseRow(merged, now) {
  return {
    id: merged.id,
    orgId: merged.orgId,
    canonicalHost: merged.canonicalHost,
    department: departmentKey(merged.department),
    reviewStatus: merged.reviewStatus,
    nextReviewAt: merged.nextReviewAt || null,
    createdAt: merged.createdAt,
    updatedAt: now,
    data: JSON.stringify(merged),
  };
}

function buildUseCaseMerge(existing, record, now) {
  // A stamped tenant id is never erased by a later write from an unconfigured
  // process (orgColumn('') is null); insert-time defaults must not clobber a
  // reviewed record on re-POST — only reviews change review evidence.
  const stampedOrg = orgColumn(record.orgId);
  return {
    ...(existing || { vendorStatus: 'not_reviewed', allowedDataClasses: [] }),
    ...definedEntries(record),
    id: existing ? existing.id : id('uc'),
    canonicalHost: record.canonicalHost,
    department: departmentDisplay(record.department),
    orgId: stampedOrg != null ? stampedOrg : orgColumn(existing && existing.orgId),
    reviewStatus: record.reviewStatus || (existing && existing.reviewStatus) || 'under_review',
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
  };
}

// Insert-or-update keyed by (canonicalHost, department) so each department's
// approval of the same tool stays a distinct record ("ChatGPT in Lending" is
// not "ChatGPT in Marketing"). The concurrent-insert race loses to the unique
// index; one retry re-reads the winner and applies this write as an update.
const upsertAiUseCase = sdb.transaction((record, now, retried = false) => {
  const row = useCaseByKey.get(record.canonicalHost, departmentKey(record.department));
  const existing = row ? JSON.parse(row.data) : null;
  const merged = buildUseCaseMerge(existing, record, now);
  try {
    if (existing) useCaseUpdate.run(useCaseRow(merged, now));
    else useCaseInsert.run(useCaseRow(merged, now));
  } catch (e) {
    if (retried || !/unique/i.test(String(e && e.message))) throw e;
    return upsertAiUseCase(record, now, true);
  }
  return merged;
});

// Review decision on an existing record; returns null for an unknown id.
const reviewAiUseCase = sdb.transaction((useCaseId, patch, now) => {
  const existing = getAiUseCase(useCaseId);
  if (!existing) return null;
  const merged = {
    ...existing,
    ...definedEntries(patch),
    id: existing.id,
    canonicalHost: existing.canonicalHost,
    department: existing.department,
    orgId: orgColumn(existing.orgId),
    createdAt: existing.createdAt,
    updatedAt: now,
  };
  useCaseUpdate.run(useCaseRow(merged, now));
  return merged;
});

// ---- AI incidents (PLANS/ncua-readiness-center.md slice 3) --------------------
const incidentInsert = sdb.prepare('INSERT INTO ai_incidents (id, orgId, status, detectedAt, deadlineAt, reportedAt, createdAt, updatedAt, data) VALUES (@id, @orgId, @status, @detectedAt, @deadlineAt, @reportedAt, @createdAt, @updatedAt, @data)');
const incidentById = sdb.prepare('SELECT data FROM ai_incidents WHERE id = ?');
const incidentUpdate = sdb.prepare('UPDATE ai_incidents SET status = @status, reportedAt = @reportedAt, updatedAt = @updatedAt, data = @data WHERE id = @id');

function listAiIncidents() {
  return sdb.prepare('SELECT data FROM ai_incidents ORDER BY detectedAt DESC, seq DESC').all().map((r) => JSON.parse(r.data));
}

// Incident rows hold status/deadline metadata and referenced query ids only;
// the examiner timeline is derived on read from those queries.
function createAiIncident(record, now) {
  const incident = {
    ...definedEntries(record),
    id: id('inc'),
    orgId: orgColumn(record.orgId),
    status: 'open',
    reportedAt: null,
    createdAt: now,
    updatedAt: now,
  };
  incidentInsert.run({
    id: incident.id,
    orgId: incident.orgId,
    status: incident.status,
    detectedAt: incident.detectedAt,
    deadlineAt: incident.deadlineAt,
    reportedAt: null,
    createdAt: now,
    updatedAt: now,
    data: JSON.stringify(incident),
  });
  return incident;
}

// Status transition on an existing incident; returns null for an unknown id.
// detectedAt/deadlineAt are immutable and the FIRST reportedAt stamp is
// permanent — the 72-hour clock cannot be rewound and a late report cannot
// be rewritten into an on-time one. (The route's strict schema means only
// status/notes/reportedAt can reach `patch`.)
const setAiIncidentStatus = sdb.transaction((incidentId, patch, now) => {
  const row = incidentById.get(incidentId);
  if (!row) return null;
  const existing = JSON.parse(row.data);
  const merged = {
    ...existing,
    ...definedEntries(patch),
    id: existing.id,
    orgId: orgColumn(existing.orgId),
    detectedAt: existing.detectedAt,
    deadlineAt: existing.deadlineAt,
    ...(existing.reportedAt ? { reportedAt: existing.reportedAt } : {}),
    createdAt: existing.createdAt,
    updatedAt: now,
  };
  incidentUpdate.run({ id: merged.id, status: merged.status, reportedAt: merged.reportedAt || null, updatedAt: now, data: JSON.stringify(merged) });
  return merged;
});

// Most recent timestamp of an audit action (idx_audit_action); lets cadence
// controls (board reporting) derive state from the append-only log instead of
// new persistence.
function lastAuditActionAt(action) {
  const row = sdb.prepare('SELECT ts FROM audit WHERE action = ? ORDER BY seq DESC LIMIT 1').get(action);
  return row ? row.ts : null;
}

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
  listAiUseCases, upsertAiUseCase, reviewAiUseCase,
  listAiIncidents, createAiIncident, setAiIncidentStatus, lastAuditActionAt,
  recordDelivery, listDeliveries, recentDeliverySuccess,
  setTenantContext,
  _canonical: canonical, _db: sdb, _dbPath: DB_PATH, _driverKind: DRIVER_KIND,
  _internal: { migrateFromJson, parsePostureActionDetail, POSTURE_ACTION_AUDIT, wireTenantContext },
};
