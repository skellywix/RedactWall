'use strict';

const Database = require('better-sqlite3');
const protocol = require('./vendor-control-protocol');

const POLICY_SQLITE_SCHEMA_VERSION = 1;
const POLICY_SQLITE_MIGRATION = `
CREATE TABLE IF NOT EXISTS vendor_policy_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL
);
INSERT OR IGNORE INTO vendor_policy_meta(singleton, schema_version) VALUES (1, 1);
CREATE TABLE IF NOT EXISTS vendor_policy_records (
  record_type TEXT NOT NULL,
  record_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  document_json TEXT NOT NULL,
  PRIMARY KEY(record_type, record_id)
);
CREATE TABLE IF NOT EXISTS vendor_policy_record_archive (
  record_type TEXT NOT NULL,
  record_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  history_epoch INTEGER NOT NULL,
  document_json TEXT NOT NULL,
  PRIMARY KEY(record_type, record_id)
);
CREATE TABLE IF NOT EXISTS vendor_policy_operations (
  operation_digest TEXT PRIMARY KEY,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vendor_policy_audit_events (
  sequence INTEGER PRIMARY KEY,
  event_digest TEXT NOT NULL UNIQUE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vendor_policy_audit_archive (
  sequence INTEGER PRIMARY KEY,
  history_epoch INTEGER NOT NULL,
  event_digest TEXT NOT NULL UNIQUE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vendor_policy_audit_high_water (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  sequence INTEGER NOT NULL,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vendor_policy_claims (
  claim_type TEXT NOT NULL,
  claim_id TEXT NOT NULL,
  operation_digest TEXT NOT NULL,
  PRIMARY KEY(claim_type, claim_id)
);
`;

function openVendorPolicySqlite(options = {}) {
  if (referenceRuntimeProhibited(options)) {
    throw storeError('policy_reference_storage_unavailable');
  }
  const driver = String(options.driver || 'sqlite').toLowerCase();
  if (driver === 'postgres' || driver === 'postgresql') {
    throw storeError('policy_postgres_adapter_not_implemented');
  }
  if (driver !== 'sqlite') throw storeError('policy_storage_driver_invalid');
  const database = options.database || new Database(checkedPath(options.path));
  database.pragma('foreign_keys = ON');
  database.pragma('journal_mode = WAL');
  database.pragma('synchronous = FULL');
  database.pragma('busy_timeout = 30000');
  database.exec(POLICY_SQLITE_MIGRATION);
  const schema = database.prepare(
    'SELECT schema_version FROM vendor_policy_meta WHERE singleton = 1',
  ).get();
  if (!schema || schema.schema_version !== POLICY_SQLITE_SCHEMA_VERSION) {
    throw storeError('policy_sqlite_schema_unsupported');
  }
  return createStore(database, options.authorityResolver || {});
}

function openVendorPolicyStore(options = {}) {
  if (referenceRuntimeProhibited(options)) {
    throw storeError('policy_reference_storage_unavailable');
  }
  const driver = String(options.driver || 'sqlite').toLowerCase();
  if (driver === 'postgres' || driver === 'postgresql') {
    throw storeError('policy_postgres_adapter_not_implemented');
  }
  if (driver !== 'sqlite') throw storeError('policy_storage_driver_invalid');
  return openVendorPolicySqlite({ ...options, driver: 'sqlite' });
}

function createStore(database, authorityResolver) {
  let closed = false;
  let tail = Promise.resolve();
  const store = {
    kind: 'sqlite',
    productionReady: false,
    runtimeProfile: 'test-reference',
    schemaVersion: POLICY_SQLITE_SCHEMA_VERSION,
    transaction(callback) {
      if (closed) return Promise.reject(storeError('policy_sqlite_closed'));
      const run = async () => {
        database.exec('BEGIN IMMEDIATE');
        try {
          const result = await callback(transactionMethods(database, authorityResolver));
          database.exec('COMMIT');
          return result;
        } catch (error) {
          try { database.exec('ROLLBACK'); } catch {}
          throw error;
        }
      };
      const current = tail.then(run, run);
      tail = current.catch(() => undefined);
      return current;
    },
    async compact(options = {}) {
      const globalRetain = checkedRetain(options.globalRetain, 128);
      const deploymentRetain = checkedRetain(options.deploymentRetain, 128);
      const auditRetain = checkedRetain(options.auditRetain, 4096);
      return store.transaction(() => compactRecords(database, {
        globalRetain, deploymentRetain, auditRetain,
      }));
    },
    readiness() {
      if (closed) return { ready: false, reason: 'closed', productionReady: false };
      const check = database.pragma('quick_check', { simple: true });
      return {
        ready: check === 'ok',
        driver: 'sqlite',
        productionReady: false,
        runtimeProfile: 'test-reference',
        schemaVersion: POLICY_SQLITE_SCHEMA_VERSION,
        postgresSupported: false,
      };
    },
    close() {
      if (!closed) database.close();
      closed = true;
    },
    database,
  };
  return Object.freeze(store);
}

function referenceRuntimeProhibited(options) {
  const actualProduction = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (actualProduction) return true;
  const requestedProduction = String(options?.env?.NODE_ENV || '')
    .trim().toLowerCase() === 'production';
  return requestedProduction || options?.production === true;
}

function transactionMethods(database, authorityResolver) {
  return Object.freeze({
    resolveAuthorization: (id) => resolveAuthority(authorityResolver, 'resolveAuthorization', id),
    resolveConfirmation: (id) => resolveAuthority(authorityResolver, 'resolveConfirmation', id),
    resolveDualApproval: (id) => resolveAuthority(authorityResolver, 'resolveDualApproval', id),
    claimAuthorization: (id, digest) => claim(database, 'authorization', id, digest),
    claimConfirmation: (id, digest) => claim(database, 'confirmation', id, digest),
    claimDualApproval: (id, digest) => claim(database, 'approval', id, digest),
    readPolicyRecord: (type, id) => readRecord(database, type, id),
    insertPolicyRecord: (type, id, wrapped) => insertRecord(database, type, id, wrapped),
    compareAndSetPolicyRecord: (type, id, expectedRevision, wrapped) => compareRecord(
      database, type, id, expectedRevision, wrapped,
    ),
    readPolicyOperation: (digest) => readJson(database.prepare(
      'SELECT document_json FROM vendor_policy_operations WHERE operation_digest = ?',
    ).get(digest)),
    insertPolicyOperation: (digest, wrapped) => insertExact(database,
      'INSERT OR IGNORE INTO vendor_policy_operations(operation_digest, document_json) VALUES (?, ?)',
      [digest, canonical(wrapped)]),
    readPolicyAuditHighWater: () => readJson(database.prepare(
      'SELECT document_json FROM vendor_policy_audit_high_water WHERE singleton = 1',
    ).get()),
    compareAndSetPolicyAuditHighWater: (expectedSequence, wrapped) => compareAuditHighWater(
      database, expectedSequence, wrapped,
    ),
    appendPolicyAuditEvent: (sequence, eventDigest, wrapped) => appendAuditEvent(
      database, sequence, eventDigest, wrapped,
    ),
    readPolicyAuditEvent: (sequence) => readAuditEvent(database, sequence),
  });
}

function readRecord(database, type, id) {
  const active = database.prepare(
    'SELECT document_json FROM vendor_policy_records WHERE record_type = ? AND record_id = ?',
  ).get(type, id);
  if (active) return readJson(active);
  return readJson(database.prepare(
    'SELECT document_json FROM vendor_policy_record_archive WHERE record_type = ? AND record_id = ?',
  ).get(type, id));
}

function insertRecord(database, type, id, wrapped) {
  const revision = wrappedRevision(wrapped);
  if (database.prepare(`
    SELECT 1 FROM vendor_policy_record_archive WHERE record_type = ? AND record_id = ?
  `).get(type, id)) return false;
  return insertExact(database,
    'INSERT OR IGNORE INTO vendor_policy_records(record_type, record_id, revision, document_json) VALUES (?, ?, ?, ?)',
    [type, id, revision, canonical(wrapped)]);
}

function appendAuditEvent(database, sequence, eventDigest, wrapped) {
  const document = canonical(wrapped);
  const existing = database.prepare(`
    SELECT 1 FROM vendor_policy_audit_events WHERE sequence = ? OR event_digest = ?
    UNION ALL
    SELECT 1 FROM vendor_policy_audit_archive WHERE sequence = ? OR event_digest = ?
    LIMIT 1
  `).get(sequence, eventDigest, sequence, eventDigest);
  if (existing) return false;
  return insertExact(database,
    'INSERT INTO vendor_policy_audit_events(sequence, event_digest, document_json) VALUES (?, ?, ?)',
    [sequence, eventDigest, document]);
}

function compareRecord(database, type, id, expectedRevision, wrapped) {
  const revision = wrappedRevision(wrapped);
  if (expectedRevision === 0) return insertRecord(database, type, id, wrapped);
  const result = database.prepare(`
    UPDATE vendor_policy_records SET revision = ?, document_json = ?
    WHERE record_type = ? AND record_id = ? AND revision = ?
  `).run(revision, canonical(wrapped), type, id, expectedRevision);
  return result.changes === 1;
}

function compareAuditHighWater(database, expectedSequence, wrapped) {
  const sequence = wrapped?.payload?.sequence;
  if (!Number.isSafeInteger(sequence) || sequence !== expectedSequence + 1) {
    throw storeError('policy_sqlite_document_invalid');
  }
  if (expectedSequence === 0) {
    return insertExact(database, `
      INSERT OR IGNORE INTO vendor_policy_audit_high_water(singleton, sequence, document_json)
      VALUES (1, ?, ?)
    `, [sequence, canonical(wrapped)]);
  }
  const result = database.prepare(`
    UPDATE vendor_policy_audit_high_water SET sequence = ?, document_json = ?
    WHERE singleton = 1 AND sequence = ?
  `).run(sequence, canonical(wrapped), expectedSequence);
  return result.changes === 1;
}

function readAuditEvent(database, sequence) {
  const active = database.prepare(
    'SELECT document_json FROM vendor_policy_audit_events WHERE sequence = ?',
  ).get(sequence);
  if (active) return readJson(active);
  return readJson(database.prepare(
    'SELECT document_json FROM vendor_policy_audit_archive WHERE sequence = ?',
  ).get(sequence));
}

function compactRecords(database, limits) {
  const moved = { global: 0, distribution: 0, audit: 0 };
  const globalRows = database.prepare(`
    SELECT record_id, revision, document_json FROM vendor_policy_records
    WHERE record_type = 'global_release' ORDER BY revision DESC
  `).all();
  moved.global += archiveRows(database, 'global_release', globalRows.slice(limits.globalRetain));
  const distributionRows = database.prepare(`
    SELECT record_id, revision, document_json FROM vendor_policy_records
    WHERE record_type = 'distribution' ORDER BY record_id
  `).all();
  const groups = new Map();
  for (const row of distributionRows) {
    const scope = String(row.record_id).split(':').slice(0, 2).join(':');
    if (!groups.has(scope)) groups.set(scope, []);
    groups.get(scope).push(row);
  }
  for (const rows of groups.values()) {
    rows.sort((left, right) => right.revision - left.revision);
    moved.distribution += archiveRows(database, 'distribution', rows.slice(limits.deploymentRetain));
  }
  const auditRows = database.prepare(`
    SELECT sequence, event_digest, document_json FROM vendor_policy_audit_events
    ORDER BY sequence DESC
  `).all().slice(limits.auditRetain);
  for (const row of auditRows) {
    const epoch = Math.floor((row.sequence - 1) / limits.auditRetain) + 1;
    const existing = database.prepare(`
      SELECT event_digest, document_json FROM vendor_policy_audit_archive WHERE sequence = ?
    `).get(row.sequence);
    if (existing && (existing.event_digest !== row.event_digest
        || existing.document_json !== row.document_json)) throw storeError('policy_archive_conflict');
    if (!existing) database.prepare(`
        INSERT INTO vendor_policy_audit_archive
          (sequence, history_epoch, event_digest, document_json) VALUES (?, ?, ?, ?)
      `).run(row.sequence, epoch, row.event_digest, row.document_json);
    database.prepare('DELETE FROM vendor_policy_audit_events WHERE sequence = ?').run(row.sequence);
    moved.audit += 1;
  }
  return moved;
}

function archiveRows(database, type, rows) {
  let moved = 0;
  for (const row of rows) {
    const epoch = Math.floor((row.revision - 1) / 128) + 1;
    const existing = database.prepare(`
      SELECT revision, document_json FROM vendor_policy_record_archive
      WHERE record_type = ? AND record_id = ?
    `).get(type, row.record_id);
    if (existing && (existing.revision !== row.revision
        || existing.document_json !== row.document_json)) throw storeError('policy_archive_conflict');
    if (!existing) database.prepare(`
        INSERT INTO vendor_policy_record_archive
          (record_type, record_id, revision, history_epoch, document_json) VALUES (?, ?, ?, ?, ?)
      `).run(type, row.record_id, row.revision, epoch, row.document_json);
    database.prepare(
      'DELETE FROM vendor_policy_records WHERE record_type = ? AND record_id = ?',
    ).run(type, row.record_id);
    moved += 1;
  }
  return moved;
}

function claim(database, type, id, digest) {
  const existing = database.prepare(`
    SELECT operation_digest FROM vendor_policy_claims WHERE claim_type = ? AND claim_id = ?
  `).get(type, id);
  if (existing) return existing.operation_digest === digest ? 'replay' : 'conflict';
  database.prepare(`
    INSERT INTO vendor_policy_claims(claim_type, claim_id, operation_digest) VALUES (?, ?, ?)
  `).run(type, id, digest);
  return 'claimed';
}

function resolveAuthority(resolver, method, id) {
  if (typeof resolver[method] !== 'function') throw storeError('policy_authority_resolver_missing');
  return resolver[method](id);
}

function insertExact(database, sql, values) {
  return database.prepare(sql).run(...values).changes === 1;
}

function wrappedRevision(wrapped) {
  const revision = wrapped?.payload?.revision;
  if (!Number.isSafeInteger(revision) || revision < 1) throw storeError('policy_sqlite_document_invalid');
  return revision;
}

function canonical(value) {
  try { return protocol.canonicalJson(value); }
  catch { throw storeError('policy_sqlite_document_invalid'); }
}

function readJson(row) {
  if (!row) return null;
  let value;
  try { value = JSON.parse(row.document_json); }
  catch { throw storeError('policy_sqlite_document_invalid'); }
  if (canonical(value) !== row.document_json) throw storeError('policy_sqlite_document_invalid');
  return value;
}

function checkedPath(value) {
  if (typeof value !== 'string' || !value || value === ':memory:') return value || ':memory:';
  if (value.includes('\0')) throw storeError('policy_sqlite_path_invalid');
  return value;
}

function checkedRetain(value, fallback) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1 || value > 100_000) {
    throw storeError('policy_compaction_invalid');
  }
  return value;
}

function storeError(code) {
  const error = new Error('vendor policy sqlite rejected');
  error.code = code;
  return error;
}

module.exports = {
  POLICY_SQLITE_MIGRATION,
  POLICY_SQLITE_SCHEMA_VERSION,
  openVendorPolicySqlite,
  openVendorPolicyStore,
};
