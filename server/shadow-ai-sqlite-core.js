'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const Database = require('better-sqlite3');
const protocol = require('./vendor-control-protocol');
const privatePaths = require('./private-path');

const SQLITE_SCHEMA_VERSION = 1;
const MAX_STATE_BYTES = 64 * 1024 * 1024;
const REFERENCE_BLOB_ASSURANCE = 'test_reference_blob';
const STORE_ID_RE = /^[a-z0-9][a-z0-9_.:-]{0,191}$/;
const KEY_ID_RE = /^rw-shadow-storage-[a-z0-9][a-z0-9_.-]{0,63}$/;
const MIGRATION = `
CREATE TABLE IF NOT EXISTS shadow_ai_json_state (
  store_id TEXT PRIMARY KEY,
  state_kind TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  state_json TEXT NOT NULL,
  state_mac TEXT NOT NULL
);
`;

function openStateStore(options, definition) {
  const driver = String(options.driver || 'sqlite').toLowerCase();
  if (driver === 'postgres' || driver === 'postgresql') {
    throw storageError('shadow_ai_postgres_adapter_not_implemented');
  }
  if (driver !== 'sqlite') throw storageError('shadow_ai_storage_driver_invalid');
  const integrity = checkedStorageIntegrity(options.storageIntegrityAuthority);
  const { database, owned } = openDatabase(options);
  let closed = false;
  let active = false;
  let tail = Promise.resolve();

  const run = (callback) => {
    if (closed) throw storageError('shadow_ai_sqlite_closed');
    if (active) throw storageError('shadow_ai_sqlite_reentrant_transaction');
    active = true;
    database.exec('BEGIN IMMEDIATE');
    let loaded;
    try {
      loaded = loadState(database, definition, integrity);
      const result = callback(definition.transactionMethods(loaded.state));
      if (result && typeof result.then === 'function') {
        throw storageError('shadow_ai_sqlite_async_transaction_invalid');
      }
      persistState(database, definition, integrity, loaded);
      database.exec('COMMIT');
      active = false;
      return result;
    } catch (error) {
      try { database.exec('ROLLBACK'); } catch {}
      active = false;
      throw error;
    }
  };

  const runAsync = (callback) => {
    if (closed) return Promise.reject(storageError('shadow_ai_sqlite_closed'));
    const task = tail.then(async () => {
      if (active) throw storageError('shadow_ai_sqlite_reentrant_transaction');
      active = true;
      database.exec('BEGIN IMMEDIATE');
      try {
        const loaded = loadState(database, definition, integrity);
        const result = await callback(definition.transactionMethods(loaded.state));
        persistState(database, definition, integrity, loaded);
        database.exec('COMMIT');
        active = false;
        return result;
      } catch (error) {
        try { database.exec('ROLLBACK'); } catch {}
        active = false;
        throw error;
      }
    });
    tail = task.catch(() => undefined);
    return task;
  };

  const storage = Object.freeze({
    kind: 'sqlite',
    ...(definition.assurance ? { assurance: definition.assurance } : {}),
    ...(definition.productionReady === false ? { productionReady: false } : {}),
    stateKind: definition.kind,
    schemaVersion: SQLITE_SCHEMA_VERSION,
    transaction: definition.asyncTransactions ? runAsync : run,
    readiness() {
      const production = definition.productionReady === false ? { productionReady: false } : {};
      if (closed) return {
        ready: false, reason: 'closed', postgresSupported: false, ...production,
      };
      try {
        const quickCheck = database.pragma('quick_check', { simple: true });
        loadState(database, definition, integrity);
        return { ready: quickCheck === 'ok', reason: quickCheck === 'ok' ? 'ready' : 'sqlite_failed',
          postgresSupported: false, ...production };
      } catch (error) {
        return { ready: false, reason: error.code || 'shadow_ai_storage_invalid',
          postgresSupported: false, ...production };
      }
    },
    close() {
      if (!closed && owned) database.close();
      closed = true;
    },
    database,
  });
  if (typeof definition.onOpen === 'function') {
    definition.onOpen(storage, Object.freeze({ owned, options }));
  }
  return storage;
}

function openDatabase(options) {
  if (options.database) {
    if (options.testOnlyExternalDatabase !== true || productionMode(options)) {
      throw storageError('shadow_ai_sqlite_external_database_test_only');
    }
    if (typeof options.database.exec !== 'function'
        || typeof options.database.prepare !== 'function') {
      throw storageError('shadow_ai_sqlite_database_invalid');
    }
    configureDatabase(options.database);
    options.database.exec(MIGRATION);
    return { database: options.database, owned: false };
  }
  if (typeof options.path !== 'string' || !path.isAbsolute(options.path)) {
    throw storageError('shadow_ai_sqlite_path_required');
  }
  let database;
  const directory = path.dirname(options.path);
  const previousUmask = process.umask(0o077);
  try {
    privatePaths.withPrivateDirectoryMutationLockSync(directory, () => {
      database = new Database(options.path);
      configureDatabase(database);
      database.exec(MIGRATION);
      privatePaths.protectInheritedPrivateFile(options.path, {
        ...(options.security || {}), label: 'Shadow AI SQLite database',
      });
    }, {
      ...(options.security || {}),
      label: 'Shadow AI SQLite directory',
      ownerLabel: 'Shadow AI SQLite store',
      lockTimeoutMs: 60_000,
      lockTimeoutMaximumMs: 60_000,
    });
    return { database, owned: true };
  } catch (error) {
    try { database?.close(); } catch {}
    throw storageError('shadow_ai_sqlite_open_failed', error);
  } finally {
    process.umask(previousUmask);
  }
}

function productionMode(options) {
  const env = options.env || process.env;
  return options.production === true
    || String(env.NODE_ENV || '').trim().toLowerCase() === 'production';
}

function configureDatabase(database) {
  database.pragma('foreign_keys = ON');
  database.pragma('journal_mode = DELETE');
  database.pragma('synchronous = FULL');
  database.pragma('busy_timeout = 30000');
}

function loadState(database, definition, integrity) {
  const row = database.prepare(`
    SELECT state_kind, schema_version, revision, state_json, state_mac
    FROM shadow_ai_json_state WHERE store_id = ?
  `).get(definition.storeId);
  if (!row) {
    const state = definition.createState();
    return { state, revision: 0, before: encodeState(state) };
  }
  if (row.state_kind !== definition.kind || row.schema_version !== SQLITE_SCHEMA_VERSION
      || !Number.isSafeInteger(row.revision) || row.revision < 1
      || typeof row.state_json !== 'string'
      || Buffer.byteLength(row.state_json, 'utf8') > MAX_STATE_BYTES) {
    throw storageError('shadow_ai_sqlite_state_invalid');
  }
  verifyStateMac(integrity, definition, row.revision, row.state_json, row.state_mac);
  const state = decodeState(row.state_json);
  return { state, revision: row.revision, before: row.state_json };
}

function persistState(database, definition, integrity, loaded) {
  const stateJson = encodeState(loaded.state);
  if (stateJson === loaded.before) return;
  const revision = loaded.revision + 1;
  const stateMac = stateMacFor(integrity, definition, revision, stateJson);
  if (loaded.revision === 0) {
    const result = database.prepare(`
      INSERT OR IGNORE INTO shadow_ai_json_state
        (store_id, state_kind, schema_version, revision, state_json, state_mac)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(definition.storeId, definition.kind, SQLITE_SCHEMA_VERSION,
      revision, stateJson, stateMac);
    if (result.changes !== 1) throw storageError('shadow_ai_sqlite_serialization_conflict');
    return;
  }
  const result = database.prepare(`
    UPDATE shadow_ai_json_state SET revision = ?, state_json = ?, state_mac = ?
    WHERE store_id = ? AND state_kind = ? AND schema_version = ? AND revision = ?
  `).run(revision, stateJson, stateMac, definition.storeId, definition.kind,
    SQLITE_SCHEMA_VERSION, loaded.revision);
  if (result.changes !== 1) throw storageError('shadow_ai_sqlite_serialization_conflict');
}

function checkedStorageIntegrity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'keyId,secret'
      || !KEY_ID_RE.test(String(value.keyId || ''))
      || !Buffer.isBuffer(value.secret) || value.secret.length !== 32) {
    throw storageError('shadow_ai_storage_integrity_invalid');
  }
  return Object.freeze({ keyId: value.keyId, secret: Buffer.from(value.secret) });
}

function stateMacFor(integrity, definition, revision, stateJson) {
  return crypto.createHmac('sha256', integrity.secret)
    .update(`redactwall.shadow-ai-sqlite.v1\0${integrity.keyId}\0${definition.kind}\0`
      + `${definition.storeId}\0${revision}\0${stateJson}`, 'utf8').digest('hex');
}

function verifyStateMac(integrity, definition, revision, stateJson, supplied) {
  if (!/^[a-f0-9]{64}$/.test(String(supplied || ''))) {
    throw storageError('shadow_ai_sqlite_state_invalid');
  }
  const expected = Buffer.from(stateMacFor(integrity, definition, revision, stateJson), 'hex');
  const actual = Buffer.from(supplied, 'hex');
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    throw storageError('shadow_ai_sqlite_state_invalid');
  }
}

function encodeState(value) {
  let encoded;
  try { encoded = JSON.stringify(toJsonValue(value)); }
  catch { throw storageError('shadow_ai_sqlite_state_invalid'); }
  if (!encoded || Buffer.byteLength(encoded, 'utf8') > MAX_STATE_BYTES) {
    throw storageError('shadow_ai_sqlite_state_invalid');
  }
  return encoded;
}

function decodeState(value) {
  try { return fromJsonValue(JSON.parse(value)); }
  catch { throw storageError('shadow_ai_sqlite_state_invalid'); }
}

function toJsonValue(value) {
  if (value instanceof Map) {
    return { __redactwallMapV1: [...value].map(([key, item]) => [key, toJsonValue(item)]) };
  }
  if (Array.isArray(value)) return value.map(toJsonValue);
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype
      || Object.hasOwn(value, '__redactwallMapV1')) {
    throw storageError('shadow_ai_sqlite_state_invalid');
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, toJsonValue(item)]));
}

function fromJsonValue(value) {
  if (Array.isArray(value)) return value.map(fromJsonValue);
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw storageError('shadow_ai_sqlite_state_invalid');
  }
  if (Object.hasOwn(value, '__redactwallMapV1')) {
    if (Object.keys(value).length !== 1 || !Array.isArray(value.__redactwallMapV1)) {
      throw storageError('shadow_ai_sqlite_state_invalid');
    }
    const output = new Map();
    for (const entry of value.__redactwallMapV1) {
      if (!Array.isArray(entry) || entry.length !== 2
          || !['string', 'number'].includes(typeof entry[0]) || output.has(entry[0])) {
        throw storageError('shadow_ai_sqlite_state_invalid');
      }
      output.set(entry[0], fromJsonValue(entry[1]));
    }
    return output;
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fromJsonValue(item)]));
}

function checkedStorePart(value, label) {
  if (!/^[a-z0-9][a-z0-9_-]{1,95}$/.test(String(value || ''))) {
    throw storageError('shadow_ai_sqlite_scope_invalid', new Error(`${label} invalid`));
  }
  return value;
}

function checkedStoreId(value) {
  if (!STORE_ID_RE.test(String(value || ''))) throw storageError('shadow_ai_sqlite_store_id_invalid');
  return value;
}

function digest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function clone(value) {
  if (value === undefined) return undefined;
  try { return JSON.parse(JSON.stringify(value)); }
  catch { throw storageError('shadow_ai_sqlite_state_invalid'); }
}

function storageError(code, cause) {
  const error = new Error('Shadow AI durable storage rejected');
  error.code = code;
  if (cause) error.cause = cause;
  return error;
}

module.exports = Object.freeze({
  MAX_STATE_BYTES,
  REFERENCE_BLOB_ASSURANCE,
  SQLITE_SCHEMA_VERSION,
  checkedStoreId,
  checkedStorePart,
  clone,
  digest,
  openStateStore,
  productionMode,
  storageError,
});
