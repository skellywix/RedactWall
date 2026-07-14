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
 * If the configured path's filesystem rejects SQLite, development may fall
 * back to a local OS dir and logs loudly. Production fails startup instead of
 * silently moving compliance evidence onto ephemeral storage. Set
 * REDACTWALL_DB_PATH to a durable local-disk path (or use managed Postgres).
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
const { openAuditAnchor } = require('./audit-anchor');
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
function wireTenantContext(
  driver = sdb,
  cfg = tenant.config(process.env),
  options = { driverKind: DRIVER_KIND, env: process.env },
) {
  const driverKind = String(options.driverKind || '').trim().toLowerCase();
  const production = String((options.env || process.env).NODE_ENV || '').trim().toLowerCase() === 'production';
  const tenantRequired = cfg && (cfg.saasMode === true || (driverKind === 'postgres' && production));
  if (tenantRequired && (!cfg.tenantId || !cfg.tenantIdValid)) {
    const error = new Error('tenant-scoped datastore requires a valid REDACTWALL_TENANT_ID');
    error.code = 'REDACTWALL_TENANT_CONTEXT_REQUIRED';
    throw error;
  }
  if (cfg && cfg.tenantId && cfg.tenantIdValid && typeof driver.setTenantContext === 'function') {
    driver.setTenantContext(cfg.tenantId);
    return cfg.tenantId;
  }
  if (tenantRequired && driverKind === 'postgres') {
    const error = new Error('Postgres tenant context cannot be enforced by the configured driver');
    error.code = 'REDACTWALL_TENANT_CONTEXT_UNAVAILABLE';
    throw error;
  }
  return null;
}
// A configured Postgres silo without its session GUC would hit the RLS policy's
// intentionally unscoped operator branch. Let any wiring failure abort module
// initialization so readiness can never report healthy cross-tenant access.
const AUDIT_DIR = path.resolve(process.env.REDACTWALL_AUDIT_DIR || (
  DB_PATH && DB_PATH !== 'postgres' && DB_PATH !== ':memory:'
    ? `${DB_PATH}.audit-integrity`
    : path.join(process.env.REDACTWALL_DATA_DIR || DATA_DIR, '.audit-integrity')
));
const auditAnchor = openAuditAnchor({
  directory: AUDIT_DIR,
  statePath: process.env.REDACTWALL_AUDIT_STATE_PATH,
  checkpointPath: process.env.REDACTWALL_AUDIT_CHECKPOINT_PATH,
  pendingPath: process.env.REDACTWALL_AUDIT_PENDING_PATH,
  // Migration 8 is the durable one-time bootstrap marker. Under the same
  // interprocess sidecar lock, create/load the private state first and only
  // then record migrations. A crash can therefore leave state without v8
  // (safe to resume), never v8 without state (indistinguishable from tamper).
  allowBootstrap: () => !storage.migrationApplied(sdb, DRIVER_KIND, 8),
  initialize: () => storage.runMigrations(sdb, DRIVER_KIND),
});
const appliedMigrations = auditAnchor.initialization || [];
wireTenantContext();
const recordAuditTransactionEntry = storage.installAuditTransactionProtocol(sdb, auditAnchor);


const id = (p) => p + '_' + crypto.randomBytes(8).toString('hex');
const orgColumn = (value) => String(value || '').trim().toLowerCase() || null;

// ---- Queries -----------------------------------------------------------------
const qInsert = sdb.prepare('INSERT INTO queries (id, createdAt, status, user, orgId, data) VALUES (@id, @createdAt, @status, @user, @orgId, @data)');
const qById = sdb.prepare('SELECT data FROM queries WHERE id = ?');
const qUpdateById = sdb.prepare('UPDATE queries SET status = @status, user = @user, orgId = @orgId, data = @data WHERE id = @id');
const ingestIdempotencyByKey = sdb.prepare(
  'SELECT queryId, auditId, replaySnapshot FROM ingest_idempotency WHERE scope = ? AND orgId = ? AND "keyHash" = ?',
);
const ingestIdempotencyInsert = sdb.prepare(
  'INSERT INTO ingest_idempotency (scope, orgId, "keyHash", queryId, auditId, replaySnapshot, createdAt) '
    + 'VALUES (@scope, @orgId, @keyHash, @queryId, @auditId, @replaySnapshot, @createdAt)',
);
const ingestIdempotencyAuditById = sdb.prepare('SELECT id, ingestIdentityHash, entry FROM audit WHERE id = ?');
const ingestIdempotencyAuditByIdentity = sdb.prepare(
  'SELECT id, ingestIdentityHash, entry FROM audit WHERE ingestIdentityHash = ?',
);
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

function normalizedIngestIdempotency(input, orgId) {
  if (input == null) return null;
  if (!input || input.scope !== 'native_handoff_v1' || !/^[0-9a-f]{64}$/.test(String(input.key || ''))) {
    throw new TypeError('invalid native handoff idempotency identity');
  }
  return {
    scope: input.scope,
    orgId: orgColumn(orgId) || '',
    keyHash: input.key,
  };
}

function ingestIdempotencyError(reason) {
  const error = new Error('native handoff idempotency evidence is unavailable');
  error.code = 'REDACTWALL_IDEMPOTENCY_INTEGRITY';
  error.reason = reason;
  return error;
}

function replayDecisionForStatus(status) {
  if (status === 'allowed') return 'allow';
  if (status === 'redacted') return 'redact';
  if (status === 'warned' || status === 'warned_sent') return 'warn';
  if (status === 'shadow_ai' || status === 'paste_flagged' || status === 'proxy_observed') return 'log';
  return 'block';
}

function boundedReplayString(value, max) {
  return String(value == null ? '' : value).slice(0, max);
}

function replayFindingSnapshot(finding = {}) {
  return {
    type: boundedReplayString(finding.type, 80),
    severity: Number(finding.severity || 0),
    score: Number(finding.score || 0),
    ...(finding.confidence ? { confidence: boundedReplayString(finding.confidence, 32) } : {}),
    ...(finding.masked ? { masked: boundedReplayString(finding.masked, 160) } : {}),
    ...(finding.vendor ? { vendor: boundedReplayString(finding.vendor, 80) } : {}),
    ...(finding.vendorLabel ? { vendorLabel: boundedReplayString(finding.vendorLabel, 80) } : {}),
  };
}

function buildIngestReplaySnapshot(row) {
  const status = boundedReplayString(row && row.status, 80);
  return {
    id: boundedReplayString(row && row.id, 120),
    decision: replayDecisionForStatus(status),
    mode: typeof row.mode === 'string' && row.mode ? row.mode.slice(0, 80) : null,
    status,
    riskScore: Number(row.riskScore || 0),
    findings: Array.isArray(row.findings) ? row.findings.slice(0, 250).map(replayFindingSnapshot) : [],
    categories: Array.isArray(row.categories)
      ? row.categories.slice(0, 250).map((category) => boundedReplayString(category, 80)) : [],
    reasons: Array.isArray(row.reasons)
      ? row.reasons.slice(0, 40).map((reason) => boundedReplayString(reason, 240)) : [],
  };
}

function hasExactKeys(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.includes(key)) && required.every((key) => keys.includes(key));
}

function validReplayFinding(finding) {
  const allowed = ['type', 'severity', 'score', 'confidence', 'masked', 'vendor', 'vendorLabel'];
  if (!hasExactKeys(finding, allowed, ['type', 'severity', 'score'])) return false;
  if (typeof finding.type !== 'string' || !finding.type || finding.type.length > 80) return false;
  if (!Number.isFinite(finding.severity) || finding.severity < 0 || finding.severity > 4) return false;
  if (!Number.isFinite(finding.score) || finding.score < 0 || finding.score > 1) return false;
  return ['confidence', 'masked', 'vendor', 'vendorLabel'].every((key) => (
    finding[key] === undefined || (typeof finding[key] === 'string' && finding[key].length <= (key === 'masked' ? 160 : 80))
  ));
}

function validIngestReplaySnapshot(snapshot) {
  const fields = ['id', 'decision', 'mode', 'status', 'riskScore', 'findings', 'categories', 'reasons'];
  if (!hasExactKeys(snapshot, fields)) return false;
  if (typeof snapshot.id !== 'string' || !/^q_[0-9a-f]{16}$/.test(snapshot.id)) return false;
  if (!['allow', 'redact', 'warn', 'log', 'block'].includes(snapshot.decision)) return false;
  if (snapshot.decision !== replayDecisionForStatus(snapshot.status)) return false;
  if (snapshot.mode !== null && (typeof snapshot.mode !== 'string' || !snapshot.mode || snapshot.mode.length > 80)) return false;
  if (typeof snapshot.status !== 'string' || !snapshot.status || snapshot.status.length > 80) return false;
  if (!Number.isFinite(snapshot.riskScore) || snapshot.riskScore < 0 || snapshot.riskScore > 100) return false;
  if (!Array.isArray(snapshot.findings) || snapshot.findings.length > 250
      || !snapshot.findings.every(validReplayFinding)) return false;
  if (!Array.isArray(snapshot.categories) || snapshot.categories.length > 250
      || !snapshot.categories.every((value) => typeof value === 'string' && value.length <= 80)) return false;
  return Array.isArray(snapshot.reasons) && snapshot.reasons.length <= 40
    && snapshot.reasons.every((value) => typeof value === 'string' && value.length <= 240);
}

function ingestIdentityHash(identity) {
  return sha(canonical({
    version: 1,
    scope: identity.scope,
    orgId: identity.orgId,
    keyHash: identity.keyHash,
  }));
}

function ingestSnapshotHash(snapshot) {
  return sha(canonical(snapshot));
}

function parseIngestReplaySnapshot(value) {
  let snapshot;
  try { snapshot = JSON.parse(String(value || '')); } catch { throw ingestIdempotencyError('snapshot_parse'); }
  if (!validIngestReplaySnapshot(snapshot)) throw ingestIdempotencyError('snapshot_shape');
  return snapshot;
}

function authenticatedIngestAudit(auditRow, identity) {
  if (!auditRow) return null;
  let audit;
  try { audit = JSON.parse(auditRow.entry); } catch { throw ingestIdempotencyError('audit_parse'); }
  if (!auditAnchor.verifyAuthenticatedEntry(audit)) throw ingestIdempotencyError('audit_authentication');
  const evidence = audit.ingestIdempotency;
  if (!hasExactKeys(evidence, ['version', 'identityHash', 'snapshotHash', 'snapshot'])
      || evidence.version !== 1
      || auditRow.ingestIdentityHash !== ingestIdentityHash(identity)
      || evidence.identityHash !== ingestIdentityHash(identity)
      || !validIngestReplaySnapshot(evidence.snapshot)
      || evidence.snapshotHash !== ingestSnapshotHash(evidence.snapshot)
      || audit.queryId !== evidence.snapshot.id) {
    throw ingestIdempotencyError('audit_binding');
  }
  const stored = qById.get(evidence.snapshot.id);
  if (!stored) throw ingestIdempotencyError('query_dangling');
  let row;
  try { row = JSON.parse(stored.data); } catch { throw ingestIdempotencyError('query_parse'); }
  return { auditId: auditRow.id, row, snapshot: evidence.snapshot };
}

function resolvedIngestIdempotency(identity) {
  if (!identity) return null;
  const identityHash = ingestIdentityHash(identity);
  const mapping = ingestIdempotencyByKey.get(identity.scope, identity.orgId, identity.keyHash);
  const indexedAudit = authenticatedIngestAudit(ingestIdempotencyAuditByIdentity.get(identityHash), identity);
  if (!mapping) return indexedAudit;
  const mappedAudit = authenticatedIngestAudit(ingestIdempotencyAuditById.get(mapping.auditId), identity);
  if (!mappedAudit || !indexedAudit || mappedAudit.auditId !== indexedAudit.auditId
      || mapping.auditId !== mappedAudit.auditId || mapping.queryId !== mappedAudit.snapshot.id) {
    throw ingestIdempotencyError('audit_mapping');
  }
  const snapshot = parseIngestReplaySnapshot(mapping.replaySnapshot);
  if (canonical(snapshot) !== canonical(mappedAudit.snapshot)) {
    throw ingestIdempotencyError('snapshot_mapping');
  }
  return { row: mappedAudit.row, snapshot: mappedAudit.snapshot };
}

function getIdempotentIngestQuery(input = {}) {
  const identity = normalizedIngestIdempotency(input, input.orgId);
  const resolved = resolvedIngestIdempotency(identity);
  return resolved && resolved.row;
}

function getIdempotentIngestReplay(input = {}) {
  const identity = normalizedIngestIdempotency(input, input.orgId);
  const resolved = resolvedIngestIdempotency(identity);
  return resolved && resolved.snapshot;
}

const createQueryWithAudits = sdb.transaction((query, audits = [], opts = {}) => {
  if (!Array.isArray(audits) || !audits.length) throw new TypeError('createQueryWithAudits requires audit events');
  const identity = normalizedIngestIdempotency(opts.idempotency, query && query.orgId);
  if (identity && typeof sdb.lockRowForUpdate === 'function') {
    sdb.lockRowForUpdate(`ingest-idempotency\0${identity.scope}\0${identity.orgId}\0${identity.keyHash}`);
  }
  const prior = resolvedIngestIdempotency(identity);
  if (prior) return { row: prior.row, audits: [], replayed: true, replaySnapshot: prior.snapshot };
  const row = createQuery(query);
  const replaySnapshot = identity ? buildIngestReplaySnapshot(row) : null;
  if (replaySnapshot && !validIngestReplaySnapshot(replaySnapshot)) {
    throw new TypeError('native handoff replay snapshot is invalid');
  }
  const ingestEvidence = identity ? {
    version: 1,
    identityHash: ingestIdentityHash(identity),
    snapshotHash: ingestSnapshotHash(replaySnapshot),
    snapshot: replaySnapshot,
  } : null;
  const entries = audits.map((event, index) => appendAuditRecord({
    ...event,
    queryId: row.id,
    ...(index === 0 && ingestEvidence ? { ingestIdempotency: ingestEvidence } : {}),
  }));
  if (identity) {
    ingestIdempotencyInsert.run({
      ...identity,
      queryId: row.id,
      auditId: entries[0].id,
      replaySnapshot: JSON.stringify(replaySnapshot),
      createdAt: row.createdAt,
    });
  }
  return { row, audits: entries, replayed: false, replaySnapshot };
});

function createQueryWithAudit(query, audit, opts = {}) {
  return createQueryWithAudits(query, [audit], opts);
}

const createQueriesWithAudits = sdb.transaction((items) => {
  if (!Array.isArray(items) || !items.length) return [];
  return items.map((item) => createQueryWithAudits(item.query, item.audits));
});
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
  // Once asynchronous checkpoint publication reports a failure, no further
  // audit-coupled mutation may begin until the exact committed tail has been
  // synchronously verified and durably repaired. This call never appends an
  // audit row itself, so it cannot recurse through this path.
  auditAnchor.requireMutationReady(sdb);
  // Serialize concurrent appends on a shared database (Postgres multi-instance)
  // so the read-head-then-insert below is atomic and the hash chain cannot fork.
  // No-op on SQLite, whose single-writer transaction already serializes writes.
  if (typeof sdb.lockAuditAppend === 'function') sdb.lockAuditAppend();
  const last = aLast.get();
  const prevHash = last ? last.hash : ZERO;
  const contentHash = event.queryId ? queryContentHash(event.queryId) : undefined;
  const ingestEvidence = event.ingestIdempotency;
  if (ingestEvidence && (!hasExactKeys(ingestEvidence, ['version', 'identityHash', 'snapshotHash', 'snapshot'])
      || ingestEvidence.version !== 1
      || !/^[0-9a-f]{64}$/.test(String(ingestEvidence.identityHash || ''))
      || !/^[0-9a-f]{64}$/.test(String(ingestEvidence.snapshotHash || ''))
      || !validIngestReplaySnapshot(ingestEvidence.snapshot)
      || ingestEvidence.snapshotHash !== ingestSnapshotHash(ingestEvidence.snapshot))) {
    throw new TypeError('native handoff audit evidence is invalid');
  }
  const body = {
    id: id('a'),
    ts: new Date().toISOString(),
    prevHash,
    action: event.action || '',
    queryId: event.queryId || '',
    actor: event.actor || '',
    detail: event.detail || '',
    ...(contentHash ? { contentHash } : {}),
    ...(ingestEvidence ? { ingestIdempotency: ingestEvidence } : {}),
  };
  const entry = auditAnchor.authenticate(prevHash, body);
  const { hash } = entry;
  aInsert.run({
    id: body.id, ts: body.ts, action: body.action, queryId: body.queryId || null,
    actor: body.actor || null, prevHash, hash, entry: JSON.stringify(entry),
  });
  // The outer transaction adapter writes an independently authenticated
  // high-water sidecar after every nested savepoint succeeds and before COMMIT.
  // A crash before the batched checkpoint publication therefore cannot turn a
  // deleted committed tail into an apparently valid older database.
  recordAuditTransactionEntry(entry);
  return entry;
}

const appendAudit = sdb.transaction((event) => {
  return appendAuditRecord(event);
});

const appendAudits = sdb.transaction((events) => {
  if (!Array.isArray(events)) throw new TypeError('appendAudits requires an array');
  return events.map((event) => appendAuditRecord(event));
});

// Couple control-plane state with its immutable evidence. `mutate` must contain
// only database work; nested datastore transactions become savepoints on both
// SQLite and Postgres. If the audit insert fails, the outer rollback restores
// every identity, invitation, seat, or renewal row and any revocation rows.
const mutateWithAudit = sdb.transaction((mutate, auditForResult) => {
  if (typeof mutate !== 'function') throw new TypeError('mutateWithAudit requires a mutation function');
  auditAnchor.requireMutationReady(sdb);
  const result = mutate();
  if (result == null) return { result, audit: null };
  const event = typeof auditForResult === 'function' ? auditForResult(result) : auditForResult;
  const audit = event ? appendAuditRecord(event) : null;
  return { result, audit };
});

function queryMatchesExpectedState(query, expected = {}) {
  return Object.entries(expected).every(([key, value]) => query[key] === value);
}

// Compare-and-transition a query and append its new evidence anchor in the same
// transaction. The row lock makes competing browser/admin decisions single-win
// on Postgres; SQLite's writer transaction provides the same guarantee locally.
const transitionQueryWithAudit = sdb.transaction((qid, expected, patch, audit) => {
  if (typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(qid);
  const currentRow = qById.get(qid);
  if (!currentRow) return { outcome: 'not_found', row: null, audit: null };
  const current = JSON.parse(currentRow.data);
  if (!queryMatchesExpectedState(current, expected)) {
    return { outcome: 'conflict', row: current, audit: null };
  }
  const merged = { ...current, ...patch };
  qUpdateById.run({ id: qid, status: merged.status, user: merged.user || null, orgId: orgColumn(merged.orgId), data: JSON.stringify(merged) });
  const auditEntry = appendAuditRecord({ ...(audit || {}), queryId: qid });
  return { outcome: 'updated', row: merged, audit: auditEntry };
});

// Compute a query patch from the fresh row while holding the same per-row lock
// that protects publication, then append the new content-hash anchor before
// commit. This is for workflow mutations whose patch depends on counters or
// arrays in the current row and therefore cannot be expressed as a shallow CAS.
const mutateQueryWithAudit = sdb.transaction((qid, mutate, auditForResult) => {
  if (typeof mutate !== 'function') throw new TypeError('mutateQueryWithAudit requires a mutation function');
  if (typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(qid);
  const currentRow = qById.get(qid);
  if (!currentRow) return { outcome: 'not_found', row: null, audit: null };
  const current = JSON.parse(currentRow.data);
  const patch = mutate(current);
  if (!patch || typeof patch !== 'object') return { outcome: 'no_change', row: current, audit: null };
  const merged = { ...current, ...patch };
  qUpdateById.run({ id: qid, status: merged.status, user: merged.user || null, orgId: orgColumn(merged.orgId), data: JSON.stringify(merged) });
  const event = typeof auditForResult === 'function' ? auditForResult(merged, current) : auditForResult;
  const auditEntry = event ? appendAuditRecord({ ...event, queryId: qid }) : null;
  return { outcome: 'updated', row: merged, audit: auditEntry };
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
const SEAT_EXCLUDED_STATUSES = new Set(['seat_limit_blocked', 'seat_released', 'license_revoked']);
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
  const releasedIdentities = new Set(listLicenseSeatAssignments()
    .filter((assignment) => assignment.status === 'released')
    .map((assignment) => normalizedSeatUser(assignment.userKey || assignment.userName))
    .filter(Boolean));
  const users = [];
  for (const r of rows) {
    const user = normalizedSeatUser(r.user);
    if (!user || inactiveIdentities.has(user) || releasedIdentities.has(user)) continue;
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
  if (!row) return null;
  const record = JSON.parse(row.data);
  return { ...record, version: entityVersion(record) };
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

const saveScimUser = sdb.transaction((user) => {
  if (user.id && typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(`scim-user:${user.id}`);
  const now = new Date().toISOString();
  const existing = user.id ? getScimUser(user.id) : getScimUserByUserName(user.userName);
  const targetUserName = String(user.userName || (existing && existing.userName) || '').trim();
  if (typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(`identity:${normalizedIdentity(targetUserName)}`);
  const current = user.id ? getScimUser(user.id) : getScimUserByUserName(targetUserName);
  assertFreshEntity(current, user);
  const { expectedVersion, version, updatedAt, ...updates } = user;
  const merged = {
    ...(current || {}),
    ...updates,
    id: current ? current.id : (user.id || id('su')),
    userName: targetUserName,
    active: updates.active !== false,
    createdAt: current ? current.createdAt : now,
    updatedAt: now,
    version: current ? entityVersion(current) + 1 : 1,
  };
  assertCrossSourceIdentityAvailable('scim', current, merged);
  const row = {
    id: merged.id,
    userName: merged.userName,
    active: merged.active ? 1 : 0,
    updatedAt: merged.updatedAt,
    data: JSON.stringify(merged),
  };
  if (current) scimUserUpdate.run(row);
  else scimUserInsert.run({ ...row, createdAt: merged.createdAt });
  inactiveIdentityCache = null;
  // Sessions embed both identity and role in the signed cookie. Revoke every
  // old/new identity when SCIM changes either, so a rename cannot leave the old
  // username live and an alias cannot retain a stale role.
  const wasActive = !current || current.active !== false;
  const roleChanged = !!current && normalizedIdentity(current.role) !== normalizedIdentity(merged.role);
  const identitiesChanged = !!current && !sameIdentitySet(scimIdentities(current), scimIdentities(merged));
  if (identitiesChanged || (wasActive && (merged.active === false || roleChanged))) {
    for (const identity of new Set([
      ...scimIdentities(current || {}),
      ...scimIdentities(merged),
    ])) revokeIdentity(identity);
  }
  return merged;
});

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
const staleSessionRevocationsDelete = sdb.prepare(
  "DELETE FROM identity_revocations WHERE identity LIKE 'session:%' AND revokedAt < ?",
);
const SESSION_REVOCATION_RETENTION_MS = 24 * 60 * 60 * 1000;
const SESSION_REVOCATION_PRUNE_INTERVAL_MS = 60 * 60 * 1000;
let lastSessionRevocationPruneAt = 0;

function normalizedIdentity(value) {
  return String(value || '').trim().toLowerCase();
}

function entityVersion(record = {}) {
  const version = Number(record && record.version);
  return Number.isSafeInteger(version) && version >= 0 ? version : 0;
}

function identityWriteError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function assertFreshEntity(existing, input = {}) {
  const hasExpectedVersion = input.expectedVersion !== undefined || input.version !== undefined;
  if (!existing) {
    if (hasExpectedVersion) {
      throw identityWriteError('IDENTITY_WRITE_CONFLICT', 'identity changed before this update');
    }
    return;
  }
  const expected = input.expectedVersion !== undefined ? Number(input.expectedVersion) : Number(input.version);
  if (!Number.isSafeInteger(expected) || expected !== entityVersion(existing)) {
    throw identityWriteError('IDENTITY_WRITE_CONFLICT', 'identity changed before this update');
  }
}

function assertCrossSourceIdentityAvailable(kind, existing, merged) {
  const collision = kind === 'scim'
    ? getAdminUserByUserName(merged.userName)
    : getScimUserByUserName(merged.userName);
  if (!collision) return;
  const resolvingLegacyDuplicate = !!existing
    && normalizedIdentity(existing.userName) === normalizedIdentity(merged.userName)
    && merged.active === false;
  if (!resolvingLegacyDuplicate) {
    throw identityWriteError('IDENTITY_ALREADY_EXISTS', 'identity exists in another authentication source');
  }
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

function sameIdentitySet(left = [], right = []) {
  if (left.length !== right.length) return false;
  const wanted = new Set(left);
  return right.every((identity) => wanted.has(identity));
}

function scimGroupMemberIds(group = {}) {
  const source = group || {};
  return new Set((Array.isArray(source.members) ? source.members : [])
    .map((member) => String(member && member.value || '').trim())
    .filter(Boolean));
}

function scimGroupAccessChanged(existing, merged) {
  if (!existing) return scimGroupMemberIds(merged).size > 0;
  if (normalizedIdentity(existing.displayName) !== normalizedIdentity(merged.displayName)) return true;
  const before = scimGroupMemberIds(existing);
  const after = scimGroupMemberIds(merged);
  return before.size !== after.size || [...before].some((id) => !after.has(id));
}

function revokeScimGroupMembers(...groups) {
  const userIds = new Set();
  for (const group of groups) {
    for (const userId of scimGroupMemberIds(group)) userIds.add(userId);
  }
  for (const userId of userIds) {
    const user = getScimUser(userId);
    if (!user) continue;
    for (const identity of scimIdentities(user)) revokeIdentity(identity);
  }
}

function revokeIdentity(identity, revokedAt = Date.now()) {
  const normalized = normalizedIdentity(identity);
  if (!normalized) return false;
  const timestamp = Number.isFinite(Number(revokedAt)) ? Math.floor(Number(revokedAt)) : Date.now();
  revocationUpsert.run({ identity: normalized, revokedAt: timestamp });
  if (normalized.startsWith('session:')) {
    const now = Date.now();
    const cutoff = now - SESSION_REVOCATION_RETENTION_MS;
    if (timestamp < cutoff || now - lastSessionRevocationPruneAt >= SESSION_REVOCATION_PRUNE_INTERVAL_MS) {
      staleSessionRevocationsDelete.run(cutoff);
      lastSessionRevocationPruneAt = now;
    }
  }
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
// a short TTL and rebuilt from authoritative rows. A count/max-timestamp
// signature is insufficient here because same-millisecond identity changes can
// preserve both values and leave a security decision stale indefinitely.
const INACTIVE_CACHE_TTL_MS = (() => {
  const n = Number(process.env.REDACTWALL_SCIM_CACHE_TTL_MS);
  return Number.isFinite(n) && n >= 0 ? n : 5000;
})();
let inactiveIdentityCache = null;
let inactiveIdentityCheckedAt = 0;

function inactiveScimIdentitySet() {
  const now = Date.now();
  if (inactiveIdentityCache && (now - inactiveIdentityCheckedAt) < INACTIVE_CACHE_TTL_MS) {
    return inactiveIdentityCache;
  }
  inactiveIdentityCheckedAt = now;
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

const consumeMfaRecoveryCodeWithAudits = sdb.transaction((codeIndex, events = []) => {
  if (!consumeMfaRecoveryCode(codeIndex)) return false;
  for (const event of events) appendAuditRecord(event);
  return true;
});

function getScimGroup(scimId) {
  return parseStoredScim(scimGroupById.get(scimId));
}

function getScimGroupByDisplayName(displayName) {
  return parseStoredScim(scimGroupByDisplayName.get(String(displayName || '').trim()));
}

function listScimGroups() {
  return scimGroupsAll.all().map(parseStoredScim);
}

const saveScimGroup = sdb.transaction((group) => {
  if (group.id && typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(`scim-group:${group.id}`);
  const now = new Date().toISOString();
  const existing = group.id ? getScimGroup(group.id) : getScimGroupByDisplayName(group.displayName);
  const targetDisplayName = String(group.displayName || (existing && existing.displayName) || '').trim();
  if (typeof sdb.lockRowForUpdate === 'function') {
    sdb.lockRowForUpdate(`scim-group-name:${normalizedIdentity(targetDisplayName)}`);
  }
  const current = group.id ? getScimGroup(group.id) : getScimGroupByDisplayName(targetDisplayName);
  assertFreshEntity(current, group);
  const { expectedVersion, version, updatedAt, ...updates } = group;
  const merged = {
    ...(current || {}),
    ...updates,
    id: current ? current.id : (group.id || id('sg')),
    displayName: targetDisplayName,
    members: Array.isArray(updates.members) ? updates.members : ((current && current.members) || []),
    createdAt: current ? current.createdAt : now,
    updatedAt: now,
    version: current ? entityVersion(current) + 1 : 1,
  };
  const row = {
    id: merged.id,
    displayName: merged.displayName,
    updatedAt: merged.updatedAt,
    data: JSON.stringify(merged),
  };
  if (current) scimGroupUpdate.run(row);
  else scimGroupInsert.run({ ...row, createdAt: merged.createdAt });
  if (scimGroupAccessChanged(current, merged)) revokeScimGroupMembers(current, merged);
  return merged;
});

const deleteScimGroup = sdb.transaction((scimId) => {
  const groupId = String(scimId || '').trim();
  if (typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(`scim-group:${groupId}`);
  let existing = getScimGroup(groupId);
  if (!existing) return null;
  if (typeof sdb.lockRowForUpdate === 'function') {
    sdb.lockRowForUpdate(`scim-group-name:${normalizedIdentity(existing.displayName)}`);
  }
  existing = getScimGroup(groupId);
  if (!existing) return null;
  sdb.prepare('DELETE FROM scim_groups WHERE id = ?').run(groupId);
  revokeScimGroupMembers(existing);
  return existing;
});

// ---- Administration users, invites, and licensing ----------------------------
const adminUserInsert = sdb.prepare(
  'INSERT INTO admin_users (id, orgId, userName, displayName, role, active, createdAt, updatedAt, data) VALUES (@id, @orgId, @userName, @displayName, @role, @active, @createdAt, @updatedAt, @data)',
);
const adminUserUpdate = sdb.prepare(
  'UPDATE admin_users SET orgId = @orgId, userName = @userName, displayName = @displayName, role = @role, active = @active, updatedAt = @updatedAt, data = @data WHERE id = @id',
);
const adminUserById = sdb.prepare('SELECT data FROM admin_users WHERE id = ?');
const adminUserByUserName = sdb.prepare('SELECT data FROM admin_users WHERE lower(userName) = lower(?)');
const adminUsersAll = sdb.prepare('SELECT data FROM admin_users ORDER BY lower(userName), seq');

function parseStoredJson(row) {
  return row ? JSON.parse(row.data) : null;
}

function getAdminUser(userId) {
  const record = parseStoredJson(adminUserById.get(userId));
  return record ? { ...record, version: entityVersion(record) } : null;
}

function getAdminUserByUserName(userName) {
  const record = parseStoredJson(adminUserByUserName.get(String(userName || '').trim()));
  return record ? { ...record, version: entityVersion(record) } : null;
}

function listAdminUsers() {
  return adminUsersAll.all().map(parseStoredJson);
}

function adminUserRow(record) {
  return {
    id: record.id,
    orgId: orgColumn(record.orgId),
    userName: String(record.userName || '').trim(),
    displayName: String(record.displayName || record.userName || '').trim(),
    role: String(record.role || '').trim(),
    active: record.active === false ? 0 : 1,
    updatedAt: record.updatedAt,
    data: JSON.stringify(record),
  };
}

const saveAdminUser = sdb.transaction((record) => {
  if (record.id && typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(`admin-user:${record.id}`);
  const now = new Date().toISOString();
  const existing = record.id ? getAdminUser(record.id) : getAdminUserByUserName(record.userName);
  const targetUserName = String(record.userName || (existing && existing.userName) || '').trim();
  if (typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(`identity:${normalizedIdentity(targetUserName)}`);
  const current = record.id ? getAdminUser(record.id) : getAdminUserByUserName(targetUserName);
  assertFreshEntity(current, record);
  const { expectedVersion, version, updatedAt, ...updates } = definedEntries(record);
  const merged = {
    ...(current || {}),
    ...updates,
    id: current ? current.id : (record.id || id('au')),
    orgId: orgColumn(updates.orgId) || orgColumn(current && current.orgId),
    userName: targetUserName,
    displayName: String(updates.displayName || (current && current.displayName) || targetUserName).trim(),
    role: String(updates.role || (current && current.role) || '').trim(),
    active: updates.active !== undefined ? updates.active !== false : !(current && current.active === false),
    createdAt: current ? current.createdAt : now,
    updatedAt: now,
    version: current ? entityVersion(current) + 1 : 1,
  };
  assertCrossSourceIdentityAvailable('local', current, merged);
  const row = adminUserRow(merged);
  if (current) adminUserUpdate.run(row);
  else adminUserInsert.run({ ...row, createdAt: merged.createdAt });
  const wasActive = !current || current.active !== false;
  const roleChanged = !!current && normalizedIdentity(current.role) !== normalizedIdentity(merged.role);
  if (wasActive && (merged.active === false || roleChanged)) revokeIdentity(merged.userName);
  return merged;
});

function disableAdminUser(userId) {
  const existing = getAdminUser(userId);
  if (!existing) return null;
  return saveAdminUser({ ...existing, active: false });
}

function reactivateAdminUser(userId) {
  const existing = getAdminUser(userId);
  if (!existing) return null;
  return saveAdminUser({ ...existing, active: true });
}

const invitationInsert = sdb.prepare(
  'INSERT INTO admin_invitations (id, orgId, userName, tokenHash, status, expiresAt, acceptedAt, createdAt, updatedAt, data) VALUES (@id, @orgId, @userName, @tokenHash, @status, @expiresAt, @acceptedAt, @createdAt, @updatedAt, @data)',
);
const invitationUpdate = sdb.prepare(
  'UPDATE admin_invitations SET orgId = @orgId, userName = @userName, tokenHash = @tokenHash, status = @status, expiresAt = @expiresAt, acceptedAt = @acceptedAt, updatedAt = @updatedAt, data = @data WHERE id = @id',
);
const invitationById = sdb.prepare('SELECT data FROM admin_invitations WHERE id = ?');
const invitationByTokenHash = sdb.prepare('SELECT data FROM admin_invitations WHERE tokenHash = ?');
const invitationsAll = sdb.prepare('SELECT data FROM admin_invitations ORDER BY createdAt DESC, seq DESC');

function invitationRow(record) {
  return {
    id: record.id,
    orgId: orgColumn(record.orgId),
    userName: String(record.userName || '').trim(),
    tokenHash: String(record.tokenHash || '').trim(),
    status: String(record.status || 'pending').trim(),
    expiresAt: record.expiresAt,
    acceptedAt: record.acceptedAt || null,
    updatedAt: record.updatedAt,
    data: JSON.stringify(record),
  };
}

function getAdminInvitation(invitationId) {
  const record = parseStoredJson(invitationById.get(invitationId));
  return record ? { ...record, version: entityVersion(record) } : null;
}

function getAdminInvitationByTokenHash(tokenHash) {
  const record = parseStoredJson(invitationByTokenHash.get(String(tokenHash || '').trim()));
  return record ? { ...record, version: entityVersion(record) } : null;
}

function listAdminInvitations() {
  return invitationsAll.all().map((row) => {
    const record = parseStoredJson(row);
    return { ...record, version: entityVersion(record) };
  });
}

const TERMINAL_INVITATION_STATUSES = new Set(['accepted', 'revoked']);

function assertInvitationCas(existing, record = {}) {
  const hasStateCas = record.expectedStatus !== undefined || record.expectedTokenHash !== undefined;
  if (!existing) {
    if (hasStateCas) {
      throw identityWriteError('IDENTITY_WRITE_CONFLICT', 'invitation changed before this update');
    }
    return;
  }
  if (record.expectedStatus === undefined || record.expectedTokenHash === undefined) {
    throw identityWriteError('IDENTITY_WRITE_CONFLICT', 'invitation status and token compare-and-swap required');
  }
  if (record.expectedStatus !== undefined && String(record.expectedStatus) !== String(existing.status || '')) {
    throw identityWriteError('IDENTITY_WRITE_CONFLICT', 'invitation status changed before this update');
  }
  if (record.expectedTokenHash !== undefined && String(record.expectedTokenHash) !== String(existing.tokenHash || '')) {
    throw identityWriteError('IDENTITY_WRITE_CONFLICT', 'invitation token changed before this update');
  }
  const nextStatus = String(record.status || existing.status || 'pending');
  if (TERMINAL_INVITATION_STATUSES.has(existing.status) && nextStatus !== existing.status) {
    throw identityWriteError('IDENTITY_WRITE_CONFLICT', 'terminal invitation cannot be reopened');
  }
}

const saveAdminInvitation = sdb.transaction((record) => {
  const invitationId = String(record.id || id('inv')).trim();
  if (typeof sdb.lockRowForUpdate === 'function') sdb.lockRowForUpdate(`admin-invitation:${invitationId}`);
  const now = new Date().toISOString();
  const existing = getAdminInvitation(invitationId);
  assertFreshEntity(existing, record);
  assertInvitationCas(existing, record);
  const {
    expectedVersion, version, expectedStatus, expectedTokenHash, updatedAt, ...updates
  } = definedEntries(record);
  const merged = {
    ...(existing || {}),
    ...updates,
    id: invitationId,
    orgId: orgColumn(updates.orgId) || orgColumn(existing && existing.orgId),
    status: String(updates.status || (existing && existing.status) || 'pending'),
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
    version: existing ? entityVersion(existing) + 1 : 1,
  };
  const row = invitationRow(merged);
  if (existing) invitationUpdate.run(row);
  else invitationInsert.run({ ...row, createdAt: merged.createdAt });
  return merged;
});

function inspectAdminInvitationRecord(invitation, tokenHash, nowMs = Date.now()) {
  const expectedTokenHash = String(tokenHash || '').trim();
  if (!invitation || !expectedTokenHash || invitation.tokenHash !== expectedTokenHash) {
    return { ok: false, reason: 'invalid', invitation: null };
  }
  if (invitation.status !== 'pending') return { ok: false, reason: 'status', invitation };
  const expiresAt = Date.parse(invitation.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt <= nowMs) {
    return { ok: false, reason: 'expired', invitation };
  }
  if (normalizedIdentity(invitation.role) === 'security_admin') {
    return { ok: false, reason: 'per_user_mfa_required', invitation };
  }
  if (getAdminUserByUserName(invitation.userName) || getScimUserByUserName(invitation.userName)) {
    return { ok: false, reason: 'identity_exists', invitation };
  }
  return { ok: true, reason: '', invitation };
}

function lockedAdminInvitationForToken(tokenHash) {
  const expectedTokenHash = String(tokenHash || '').trim();
  const candidate = getAdminInvitationByTokenHash(expectedTokenHash);
  if (!candidate) return null;
  if (typeof sdb.lockRowForUpdate === 'function') {
    sdb.lockRowForUpdate(`admin-invitation:${candidate.id}`);
  }
  const current = getAdminInvitation(candidate.id);
  return current && current.tokenHash === expectedTokenHash ? current : null;
}

function inspectAdminInvitation(tokenHash, nowMs = Date.now()) {
  const invitation = getAdminInvitationByTokenHash(tokenHash);
  return inspectAdminInvitationRecord(invitation, tokenHash, nowMs);
}

const expireAdminInvitation = sdb.transaction((tokenHash, nowMs = Date.now()) => {
  const invite = lockedAdminInvitationForToken(tokenHash);
  const inspected = inspectAdminInvitationRecord(invite, tokenHash, nowMs);
  if (inspected.reason !== 'expired') return null;
  return saveAdminInvitation({
    ...invite,
    status: 'expired',
    expectedVersion: invite.version,
    expectedStatus: 'pending',
    expectedTokenHash: tokenHash,
  });
});

const acceptAdminInvitation = sdb.transaction((tokenHash, passwordRecord = {}, displayName) => {
  const invite = lockedAdminInvitationForToken(tokenHash);
  const inspected = inspectAdminInvitationRecord(invite, tokenHash);
  if (!inspected.ok) return null;
  const user = saveAdminUser({
    orgId: invite.orgId,
    userName: invite.userName,
    displayName: String(displayName || invite.displayName || invite.userName).trim(),
    role: invite.role,
    active: true,
    source: 'local_invite',
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    passwordAlgorithm: passwordRecord.algorithm,
    invitedBy: invite.actor || invite.invitedBy || '',
    invitationId: invite.id,
  });
  const acceptedAt = new Date().toISOString();
  const invitation = saveAdminInvitation({
    ...invite,
    status: 'accepted',
    acceptedAt,
    acceptedUserId: user.id,
    expectedVersion: invite.version,
    expectedStatus: 'pending',
    expectedTokenHash: tokenHash,
  });
  return { invitation, user };
});

const seatAssignmentInsert = sdb.prepare(
  'INSERT INTO license_seat_assignments (id, orgId, userKey, userName, status, reason, actor, createdAt, updatedAt, data) VALUES (@id, @orgId, @userKey, @userName, @status, @reason, @actor, @createdAt, @updatedAt, @data)',
);
const seatAssignmentUpdate = sdb.prepare(
  'UPDATE license_seat_assignments SET orgId = @orgId, userName = @userName, status = @status, reason = @reason, actor = @actor, updatedAt = @updatedAt, data = @data WHERE userKey = @userKey',
);
const seatAssignmentByUserKey = sdb.prepare('SELECT data FROM license_seat_assignments WHERE userKey = ?');
const seatAssignmentsAll = sdb.prepare('SELECT data FROM license_seat_assignments ORDER BY lower(userName), seq');

function getLicenseSeatAssignment(userKey) {
  return parseStoredJson(seatAssignmentByUserKey.get(normalizedIdentity(userKey)));
}

function listLicenseSeatAssignments() {
  return seatAssignmentsAll.all().map(parseStoredJson);
}

function saveLicenseSeatAssignment(record) {
  const now = new Date().toISOString();
  const userKey = normalizedIdentity(record.userKey || record.userName);
  const existing = getLicenseSeatAssignment(userKey);
  const merged = {
    ...(existing || {}),
    ...definedEntries(record),
    id: existing ? existing.id : (record.id || id('seat')),
    orgId: orgColumn(record.orgId) || orgColumn(existing && existing.orgId),
    userKey,
    userName: String(record.userName || (existing && existing.userName) || userKey).trim(),
    status: String(record.status || (existing && existing.status) || 'assigned').trim(),
    reason: String(record.reason || '').trim(),
    actor: String(record.actor || '').trim(),
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
  };
  const row = {
    id: merged.id,
    orgId: merged.orgId,
    userKey: merged.userKey,
    userName: merged.userName,
    status: merged.status,
    reason: merged.reason,
    actor: merged.actor,
    updatedAt: merged.updatedAt,
    data: JSON.stringify(merged),
  };
  if (existing) seatAssignmentUpdate.run(row);
  else seatAssignmentInsert.run({ ...row, createdAt: merged.createdAt });
  return merged;
}

const renewalRequestInsert = sdb.prepare(
  'INSERT INTO license_renewal_requests (id, orgId, status, requestedSeats, contactEmail, createdAt, updatedAt, data) VALUES (@id, @orgId, @status, @requestedSeats, @contactEmail, @createdAt, @updatedAt, @data)',
);
const renewalRequestsAll = sdb.prepare('SELECT data FROM license_renewal_requests ORDER BY createdAt DESC, seq DESC');

function createLicenseRenewalRequest(record) {
  const now = new Date().toISOString();
  const request = {
    ...definedEntries(record),
    id: record.id || id('renew'),
    orgId: orgColumn(record.orgId),
    status: record.status || 'requested',
    requestedSeats: Number.isFinite(Number(record.requestedSeats)) ? Math.max(1, Math.trunc(Number(record.requestedSeats))) : null,
    contactEmail: String(record.contactEmail || '').trim(),
    createdAt: now,
    updatedAt: now,
  };
  renewalRequestInsert.run({
    id: request.id,
    orgId: request.orgId,
    status: request.status,
    requestedSeats: request.requestedSeats,
    contactEmail: request.contactEmail || null,
    createdAt: now,
    updatedAt: now,
    data: JSON.stringify(request),
  });
  return request;
}

function listLicenseRenewalRequests() {
  return renewalRequestsAll.all().map(parseStoredJson);
}

/**
 * Verify the chain AND the evidence binding.
 *  - chain: each entry hash == sha256(canonical(entry-minus-hash)), prevHash links.
 *  - evidence: for every query, the most recent audit entry that recorded a
 *    contentHash must still match the query's current content hash.
 */
function verifyAuditChain() {
  return auditAnchor.verifyDatabase(sdb);
}

function auditHealth() {
  const status = auditAnchor.status();
  return {
    ok: status.ok,
    reason: status.reason,
  };
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
  const dataCrypto = opts.dataCrypto || require('./crypto');
  const detector = opts.detector || require('./detector');
  if (env.REDACTWALL_DB_PATH) return; // explicit path: caller owns its data, no legacy auto-import
  const qf = path.join(dataDir, 'queries.json');
  const af = path.join(dataDir, 'audit.json');
  const legacyFiles = [qf, af, `${qf}.migrated`, `${af}.migrated`];
  const removeLegacyPlaintext = () => {
    for (const file of legacyFiles) {
      if (fsModule.existsSync(file)) fsModule.rmSync(file, { force: true });
    }
  };
  if (db.prepare('SELECT COUNT(*) n FROM queries').get().n > 0) {
    removeLegacyPlaintext();
    return;
  }
  const readLegacyArray = (file) => {
    if (!fsModule.existsSync(file)) return [];
    const parsed = JSON.parse(fsModule.readFileSync(file, 'utf8'));
    if (!Array.isArray(parsed)) throw new Error(`legacy ${path.basename(file)} must contain an array`);
    return parsed;
  };
  const protectLegacyQuery = (input) => {
    const row = { ...input };
    const discarded = [];
    for (const field of ['_rawPrompt', '_tokenVault']) {
      if (row[field] == null) continue;
      if (typeof row[field] === 'string' && dataCrypto.isSealed(row[field])) continue;
      let plaintext;
      try { plaintext = typeof row[field] === 'string' ? row[field] : JSON.stringify(row[field]); } catch { plaintext = ''; }
      const sealed = plaintext ? dataCrypto.seal(plaintext) : null;
      if (sealed) row[field] = sealed;
      else { delete row[field]; discarded.push(field); }
    }
    if (discarded.length) row.legacySensitiveFieldsDiscarded = discarded;
    return row;
  };
  const scrubLegacyDetail = (value) => {
    const text = String(value == null ? '' : value);
    const analysis = detector.analyze(text);
    const categories = [...new Set((analysis.categories || []).map((item) => item.category).filter(Boolean))];
    const safe = categories.length
      ? `[REDACTED: ${categories.join(', ')}]`
      : detector.redact(text, analysis.findings || []);
    return String(safe || '').replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 2000);
  };
  let importedQ = 0, importedA = 0;
  const tx = db.transaction(() => {
    const importedIds = [];
    if (fsModule.existsSync(qf)) {
      for (const source of readLegacyArray(qf)) {
        const r = source && typeof source === 'object' && !Array.isArray(source) ? protectLegacyQuery(source) : source;
        if (!r || !r.id) continue;
        queryInsert.run({ id: r.id, createdAt: r.createdAt || new Date().toISOString(), status: r.status || 'pending', user: r.user || null, orgId: orgColumn(r.orgId), data: JSON.stringify(r) });
        importedIds.push(r.id);
        importedQ++;
      }
    }
    if (fsModule.existsSync(af)) {
      const rows = readLegacyArray(af);
      rows.sort((a, b) => (a.ts < b.ts ? -1 : 1));
      for (const e of rows) {
        if (!e || typeof e !== 'object' || Array.isArray(e)) continue;
        append({ action: e.action, queryId: e.queryId, actor: e.actor, detail: scrubLegacyDetail(e.detail) });
        importedA++;
      }
    }
    for (const queryId of importedIds) {
      append({ action: 'LEGACY_QUERY_IMPORTED', queryId, actor: 'system', detail: 'legacy query imported and evidence re-anchored' });
    }
  });
  tx();
  if (importedQ || importedA) {
    append({ action: 'STORE_MIGRATED', actor: 'system', detail: `imported ${importedQ} queries, ${importedA} audit events from JSON store (re-anchored)` });
  }
  removeLegacyPlaintext();
}
migrateFromJson();
const startupAuditIntegrity = verifyAuditChain();
if (!startupAuditIntegrity.ok) {
  const error = new Error(`broken audit integrity: authenticated checkpoint verification failed (${startupAuditIntegrity.reason || 'unknown'})`);
  error.code = 'REDACTWALL_AUDIT_INTEGRITY_FAILED';
  error.integrity = startupAuditIntegrity;
  throw error;
}

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

// The most recent board cybersecurity-training / oversight attestation, read
// back from the tamper-evident audit chain (a BOARD_TRAINING_ATTESTED entry
// whose detail is JSON: { trainingCompletedAt, reference }). Bounded date +
// reference only, no PII. Same structured-read pattern as lastVendorHeartbeat.
function lastBoardTrainingAttestation() {
  const row = sdb.prepare("SELECT ts, entry FROM audit WHERE action = 'BOARD_TRAINING_ATTESTED' ORDER BY seq DESC LIMIT 1").get();
  if (!row) return null;
  try {
    const detail = JSON.parse(JSON.parse(row.entry).detail);
    const trainingCompletedAt = typeof detail.trainingCompletedAt === 'string' ? detail.trainingCompletedAt : null;
    if (!trainingCompletedAt) return null;
    return {
      trainingCompletedAt,
      reference: typeof detail.reference === 'string' ? detail.reference.slice(0, 120) : '',
      attestedAt: row.ts || null,
    };
  } catch (_) { return null; }
}

// Durable, tamper-evident anchors for the connected-mode kill-switch. The
// vendor state file (server/vendor-link.js) is a fast cache but is
// operator-writable/deletable; the hash-chained audit is not (editing it breaks
// verifyAuditChain). A dedicated row supplies the cross-replica CAS while the
// audit supplies the authenticated fallback and detects a rolled-back row.
const vendorStateByCustomer = sdb.prepare(
  'SELECT "customerId", "issuedAt", "contactAt", status FROM vendor_license_state WHERE "customerId" = ?',
);
const latestVendorState = sdb.prepare(
  'SELECT "customerId", "issuedAt", "contactAt", status FROM vendor_license_state ORDER BY "issuedAt" DESC LIMIT 1',
);
const vendorHeartbeatAudits = sdb.prepare(
  "SELECT entry FROM audit WHERE action = 'VENDOR_HEARTBEAT_OK' ORDER BY seq DESC",
);
const vendorStateCas = sdb.prepare(`
  INSERT INTO vendor_license_state ("customerId", "issuedAt", "contactAt", status)
  VALUES (@customerId, @issuedAt, @contactAt, @status)
  ON CONFLICT("customerId") DO UPDATE SET
    "issuedAt" = excluded."issuedAt",
    "contactAt" = excluded."contactAt",
    status = excluded.status
  WHERE excluded."issuedAt" > vendor_license_state."issuedAt"
  RETURNING "customerId", "issuedAt", "contactAt", status
`);
const vendorStateReplace = sdb.prepare(`
  UPDATE vendor_license_state
  SET "issuedAt" = @issuedAt, "contactAt" = @contactAt, status = @status
  WHERE "customerId" = @customerId
`);

function normalizedVendorState(row, fallbackCustomerId = '') {
  if (!row) return null;
  const customerId = String(row.customerId || fallbackCustomerId || '').trim();
  const issuedAt = Number(row.issuedAt);
  const contactAt = Number(row.contactAt);
  const status = String(row.status || '');
  if (!customerId || !Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(contactAt)
      || issuedAt < 0 || contactAt < 0 || !['active', 'revoked'].includes(status)) return null;
  return { customerId, issuedAt, contactAt, status };
}

function earlierDuplicateVendorState(current, candidate) {
  if (!current) return candidate;
  if (candidate.issuedAt > current.issuedAt) return candidate;
  if (candidate.issuedAt < current.issuedAt) return current;
  return {
    ...current,
    contactAt: Math.min(current.contactAt, candidate.contactAt),
    status: current.status === 'revoked' || candidate.status === 'revoked' ? 'revoked' : 'active',
  };
}

function vendorAuditState(customerId = '', customerRef = '') {
  let result = null;
  for (const row of vendorHeartbeatAudits.all()) {
    try {
      const detail = JSON.parse(JSON.parse(row.entry).detail);
      if (detail.customerRef && (!customerRef || String(detail.customerRef) !== customerRef)) continue;
      const eventCustomerId = String(detail.customerId || customerId || '').trim();
      if (customerId && detail.customerId && eventCustomerId !== customerId) continue;
      const candidate = normalizedVendorState({ ...detail, customerId: eventCustomerId });
      if (candidate) result = earlierDuplicateVendorState(result, candidate);
    } catch (_) { /* malformed authenticated evidence is ignored here; chain verification reports it */ }
  }
  return result;
}

function vendorStateIntegrityError() {
  const error = new Error('shared vendor state is not anchored by matching audit evidence');
  error.code = 'VENDOR_STATE_INTEGRITY';
  return error;
}

function sameVendorState(left, right) {
  return !!left && !!right && left.issuedAt === right.issuedAt
    && left.contactAt === right.contactAt && left.status === right.status;
}

function lastVendorHeartbeat(customerId = '', customerRef = '') {
  const wanted = String(customerId || '').trim();
  const row = wanted ? vendorStateByCustomer.get(wanted) : latestVendorState.get();
  const tableState = normalizedVendorState(row, wanted);
  const auditState = vendorAuditState(wanted || (tableState && tableState.customerId) || '', customerRef);
  if (!tableState) {
    return auditState
      ? { issuedAt: auditState.issuedAt, contactAt: auditState.contactAt, status: auditState.status }
      : null;
  }
  if (!auditState || tableState.issuedAt > auditState.issuedAt
      || (tableState.issuedAt === auditState.issuedAt && !sameVendorState(tableState, auditState))) {
    throw vendorStateIntegrityError();
  }
  return { issuedAt: auditState.issuedAt, contactAt: auditState.contactAt, status: auditState.status };
}

function checkedVendorHeartbeat(input = {}) {
  const state = normalizedVendorState(input);
  if (!state) throw new TypeError('applyVendorHeartbeat requires a valid vendor state');
  const customerRef = String(input.customerRef || '');
  if (!/^license_[A-Za-z0-9_-]{24}$/.test(customerRef)) {
    throw new TypeError('applyVendorHeartbeat requires an opaque customer reference');
  }
  if (!Array.isArray(input.audits) || !input.audits.length) {
    throw new TypeError('applyVendorHeartbeat requires audit events');
  }
  const heartbeat = input.audits.find((event) => event && event.action === 'VENDOR_HEARTBEAT_OK');
  if (!heartbeat) throw new TypeError('applyVendorHeartbeat requires heartbeat evidence');
  let detail;
  try { detail = JSON.parse(heartbeat.detail); } catch (_) { detail = null; }
  const evidence = normalizedVendorState(detail, state.customerId);
  if (!evidence || String(detail.customerRef || '') !== customerRef
      || evidence.customerId !== state.customerId || evidence.issuedAt !== state.issuedAt
      || evidence.contactAt !== state.contactAt || evidence.status !== state.status) {
    throw new TypeError('vendor state and heartbeat evidence must match');
  }
  return { ...state, customerRef, audits: input.audits };
}

const applyVendorHeartbeat = sdb.transaction((input) => {
  const candidate = checkedVendorHeartbeat(input);
  const changed = normalizedVendorState(vendorStateCas.get(candidate), candidate.customerId);
  // The row upsert serializes this customer across SQLite processes and
  // Postgres replicas. Hold the audit lock while reconciling pre-v9 evidence
  // and appending. Pre-v9 processes do not read this row and must be drained
  // before migration 9 is enabled (see CONNECTED_DEPLOYMENT.md).
  if (typeof sdb.lockAuditAppend === 'function') sdb.lockAuditAppend();
  const auditState = vendorAuditState(candidate.customerId, candidate.customerRef);
  if (auditState && auditState.issuedAt >= candidate.issuedAt) {
    vendorStateReplace.run({ ...auditState, customerId: candidate.customerId });
    return { applied: false, state: { ...auditState, customerId: candidate.customerId }, audits: [] };
  }
  if (!changed) {
    const tableState = normalizedVendorState(vendorStateByCustomer.get(candidate.customerId), candidate.customerId);
    if (!auditState || !tableState || tableState.issuedAt > auditState.issuedAt
        || (tableState.issuedAt === auditState.issuedAt && !sameVendorState(tableState, auditState))) {
      throw vendorStateIntegrityError();
    }
    if (auditState.issuedAt > tableState.issuedAt) {
      vendorStateReplace.run({ ...auditState, customerId: candidate.customerId });
    }
    return { applied: false, state: { ...auditState, customerId: candidate.customerId }, audits: [] };
  }
  const audits = candidate.audits.map((event) => appendAuditRecord(event));
  return { applied: true, state: changed, audits };
});

function firstAuditAt() {
  const row = sdb.prepare('SELECT ts FROM audit ORDER BY seq ASC LIMIT 1').get();
  return row && row.ts ? (Date.parse(row.ts) || null) : null;
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
  createQuery, createQueryWithAudit, createQueryWithAudits, createQueriesWithAudits,
  getQuery, getIdempotentIngestQuery, getIdempotentIngestReplay,
  listQueries, updateQuery, transitionQueryWithAudit, mutateQueryWithAudit,
  createDetectorFeedback, listDetectorFeedback,
  purgeRetainedSensitiveData,
  appendAudit, appendAudits, mutateWithAudit, listAudit, verifyAuditChain, auditHealth, stats, seatStats, postureActionStates,
  getScimUser, getScimUserByUserName, listScimUsers, saveScimUser, deactivateScimUser,
  revokeIdentity, identityRevokedSince, scimIdentityInactive,
  mfaRecoveryCodeUsed, consumeMfaRecoveryCode, consumeMfaRecoveryCodeWithAudits,
  getScimGroup, getScimGroupByDisplayName, listScimGroups, saveScimGroup, deleteScimGroup,
  getAdminUser, getAdminUserByUserName, listAdminUsers, saveAdminUser, disableAdminUser, reactivateAdminUser,
  getAdminInvitation, getAdminInvitationByTokenHash, listAdminInvitations, saveAdminInvitation,
  inspectAdminInvitation, expireAdminInvitation, acceptAdminInvitation,
  getLicenseSeatAssignment, listLicenseSeatAssignments, saveLicenseSeatAssignment,
  createLicenseRenewalRequest, listLicenseRenewalRequests,
  getAiApp, listAiApps, upsertAiApp,
  listAiUseCases, upsertAiUseCase, reviewAiUseCase,
  listAiIncidents, createAiIncident, setAiIncidentStatus, lastAuditActionAt,
  applyVendorHeartbeat, lastBoardTrainingAttestation, lastVendorHeartbeat, firstAuditAt,
  recordDelivery, listDeliveries, recentDeliverySuccess,
  setTenantContext,
  _canonical: canonical, _db: sdb, _dbPath: DB_PATH, _driverKind: DRIVER_KIND,
  _auditAnchorPaths: auditAnchor.paths,
  _internal: {
    migrateFromJson,
    buildIngestReplaySnapshot,
    normalizedIngestIdempotency,
    validIngestReplaySnapshot,
    parsePostureActionDetail,
    POSTURE_ACTION_AUDIT,
    wireTenantContext,
  },
};
