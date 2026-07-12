'use strict';
/**
 * Storage driver selection + schema migrations for the control plane.
 *
 * Default driver is better-sqlite3 on local disk (single-node, WAL). Setting
 * REDACTWALL_DB_DRIVER=postgres with REDACTWALL_DATABASE_URL routes the same
 * synchronous db.js interface onto Postgres via a worker-thread bridge —
 * the scale-out path for a shared multi-tenant control plane.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { MIGRATIONS } = require('./migrations');
const { parsePostgresConnectionUrl, validPostgresTlsUrl } = require('../postgres-url');
const privatePaths = require('../private-path');

const SQLITE_SIDECAR_SUFFIXES = ['-wal', '-shm', '-journal'];
const SQLITE_INITIALIZATION_LOCK_TIMEOUT_MS = 60_000;
const POSTGRES_MIGRATION_LOCK = 4021989;

function restrictPrivatePath(target, options = {}) {
  return privatePaths.restrictPrivatePath(target, {
    ownerLabel: 'SQLite store',
    ...options,
  });
}

function sqliteArtifactPaths(dbPath) {
  return [dbPath, ...SQLITE_SIDECAR_SUFFIXES.map((suffix) => `${dbPath}${suffix}`)];
}

function restrictSqliteArtifacts(dbPath, security = {}) {
  for (const file of sqliteArtifactPaths(dbPath)) {
    if (!fs.existsSync(file)) continue;
    restrictPrivatePath(file, { ...security, directory: false });
  }
}

function resolvedSqliteSecurity(security = {}) {
  const platform = security.platform || process.platform;
  if (platform !== 'win32' || security.principal) return { ...security, platform };
  const spawn = security.spawn;
  return {
    ...security,
    platform,
    ...(spawn ? { spawn } : {}),
    principal: privatePaths.windowsPrincipal(spawn, 'SQLite store'),
  };
}

function sqliteInitializationSecurity(security = {}) {
  const nested = security.lockOptions || {};
  const lockTimeoutMs = security.lockTimeoutMs
    ?? nested.lockTimeoutMs
    ?? SQLITE_INITIALIZATION_LOCK_TIMEOUT_MS;
  const lockTimeoutMaximumMs = security.lockTimeoutMaximumMs
    ?? nested.lockTimeoutMaximumMs
    ?? SQLITE_INITIALIZATION_LOCK_TIMEOUT_MS;
  return {
    ...security,
    lockTimeoutMs,
    lockTimeoutMaximumMs,
    lockOptions: { ...nested, lockTimeoutMs, lockTimeoutMaximumMs },
  };
}

function openConfiguredSqlite(dbPath) {
  const Database = require('better-sqlite3');
  const driver = new Database(dbPath);
  try {
    try { driver.pragma('busy_timeout = 5000'); } catch {}
    try { driver.pragma('journal_mode = WAL'); } catch { try { driver.pragma('journal_mode = DELETE'); } catch {} }
    try { driver.pragma('synchronous = NORMAL'); } catch {}
    try { driver.pragma('foreign_keys = ON'); } catch {}
    const probeTable = `_redactwall_probe_${process.pid}_${crypto.randomBytes(8).toString('hex')}`;
    const probe = driver.transaction(() => {
      driver.exec(`CREATE TABLE "${probeTable}" (x); DROP TABLE "${probeTable}";`);
    });
    if (typeof probe.immediate === 'function') probe.immediate();
    else probe();
    return driver;
  } catch (error) {
    try { driver.close(); } catch {}
    throw error;
  }
}

function sqliteDriverAt(dbPath, security = {}) {
  const previousUmask = process.umask(0o077);
  let privatePathSecurity;
  let d;
  try {
    const inMemory = dbPath === ':memory:';
    if (!inMemory) {
      privatePathSecurity = resolvedSqliteSecurity(security);
      const dbDir = path.dirname(dbPath);
      const openInPrivateDirectory = () => {
        d = openConfiguredSqlite(dbPath);
        restrictSqliteArtifacts(dbPath, privatePathSecurity);
        return d;
      };
      if (security.requirePrivateDirectory) {
        return privatePaths.withPrivateDirectoryMutationLockSync(dbDir, openInPrivateDirectory, {
          ...privatePathSecurity,
          fs,
          directory: true,
          label: 'SQLite data directory',
          ownerLabel: 'SQLite store',
        });
      }
      const dbDirExisted = fs.existsSync(dbDir);
      fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });
      if (!dbDirExisted) {
        restrictPrivatePath(dbDir, { ...privatePathSecurity, directory: true });
      }
      return openInPrivateDirectory();
    }
    d = openConfiguredSqlite(dbPath);
    return d;
  } catch (error) {
    try { d?.close(); } catch {}
    throw error;
  } finally {
    process.umask(previousUmask);
  }
}

function defaultSqlitePath(dataDir) {
  const preferred = path.join(dataDir, 'redactwall.db');
  const legacy = path.join(dataDir, 'sentinel.db');
  // Installs created before the RedactWall rebrand keep their existing store.
  if (!fs.existsSync(preferred) && fs.existsSync(legacy)) return legacy;
  return preferred;
}

function openSqlite(env, dataDir, security) {
  let dbPath = env.REDACTWALL_DB_PATH || defaultSqlitePath(dataDir);
  let driver;
  const production = String(env.NODE_ENV || '').trim().toLowerCase() === 'production';
  try {
    if (production && dbPath === ':memory:') throw new Error('in-memory SQLite is not durable');
    const requirePrivateDirectory = production || security?.requirePrivateDirectory === true;
    driver = sqliteDriverAt(dbPath, {
      ...(requirePrivateDirectory ? sqliteInitializationSecurity(security) : security),
      requirePrivateDirectory,
    });
  } catch (e) {
    if (production) {
      const error = new Error(
        `configured SQLite store at ${dbPath} is unusable (${e.code || e.message}); ` +
        'production startup aborted to preserve audit durability',
      );
      error.code = 'REDACTWALL_SQLITE_UNUSABLE';
      error.cause = e;
      throw error;
    }
    const fallback = path.join(os.tmpdir(), 'redactwall', 'redactwall.db');
    console.error(`[db] store at ${dbPath} unusable (${e.code || e.message}); falling back to ${fallback}. ` +
      'This fallback is disabled in production; set REDACTWALL_DB_PATH to a durable local-disk path.');
    dbPath = fallback;
    driver = sqliteDriverAt(dbPath, security);
  }
  return { driver, kind: 'sqlite', dbPath };
}

function openPostgres(env, createDriver) {
  const connectionString = env.REDACTWALL_DATABASE_URL || env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('REDACTWALL_DB_DRIVER=postgres requires REDACTWALL_DATABASE_URL');
  }
  try {
    parsePostgresConnectionUrl(connectionString);
  } catch {
    const error = new Error('Postgres connection URL is invalid, ambiguous, or uses unsupported parameters');
    error.code = 'REDACTWALL_POSTGRES_URL_INVALID';
    throw error;
  }
  const production = String(env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (!validPostgresTlsUrl(connectionString, { allowLoopbackPlaintext: !production })) {
    const error = new Error('production Postgres requires sslmode=require, verify-ca, or verify-full');
    error.code = 'REDACTWALL_POSTGRES_TLS_REQUIRED';
    throw error;
  }
  const factory = createDriver || require('./pg-driver').createPgDriver;
  return { driver: factory(connectionString), kind: 'postgres', dbPath: 'postgres' };
}

function openStore({ env = process.env, dataDir, createPgDriver, sqliteSecurity } = {}) {
  const requested = String(env.REDACTWALL_DB_DRIVER || '').trim().toLowerCase() || 'sqlite';
  if (requested === 'postgres' || requested === 'postgresql' || requested === 'pg') {
    return openPostgres(env, createPgDriver);
  }
  if (requested === 'sqlite' || requested === 'sqlite3') return openSqlite(env, dataDir, sqliteSecurity);
  throw new Error('unsupported REDACTWALL_DB_DRIVER; expected sqlite or postgres');
}

function tableExists(driver, kind, table) {
  if (kind === 'postgres') {
    const row = driver.prepare('SELECT to_regclass(?) AS reg').get(table);
    return !!(row && row.reg);
  }
  const row = driver.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
  return !!row;
}

function baselineTables(kind) {
  return [...MIGRATIONS[0][kind].matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map((m) => m[1]);
}

function migrationApplied(driver, kind, version) {
  if (!tableExists(driver, kind, 'schema_migrations')) return false;
  return !!driver.prepare('SELECT version FROM schema_migrations WHERE version = ?').get(version);
}

/**
 * Apply pending migrations in order. A store created before this framework
 * existed (has `queries`, no migration rows) is stamped at the baseline
 * version instead of re-running it.
 */
function runMigrationsUnlocked(driver, kind, options = {}) {
  driver.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version   INTEGER PRIMARY KEY,
      name      TEXT NOT NULL,
      appliedAt TEXT NOT NULL
    );
  `);
  const appliedRows = driver.prepare('SELECT version FROM schema_migrations').all();
  const applied = new Set(appliedRows.map((row) => Number(row.version)));
  const record = driver.prepare('INSERT INTO schema_migrations (version, name, appliedAt) VALUES (?, ?, ?)');

  if (!applied.size && tableExists(driver, kind, 'queries')) {
    record.run(1, 'baseline', new Date().toISOString());
    applied.add(1);
  }

  const results = [];
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    const sql = migration[kind];
    if (!sql) throw new Error(`migration ${migration.version} has no ${kind} variant`);
    if (typeof options.beforeMigration === 'function') {
      options.beforeMigration({ driver, kind, migration });
    }
    driver.transaction(() => {
      driver.exec(sql);
      record.run(migration.version, migration.name, new Date().toISOString());
    })();
    results.push({ version: migration.version, name: migration.name });
  }

  // Self-heal stores whose baseline stamp predates some baseline tables:
  // pre-framework databases were stamped at v1 without executing it, so a DB
  // from an older lineage can claim the baseline while missing tables added to
  // it later. The baseline is pure IF NOT EXISTS DDL, so re-running it fills
  // exactly the gaps and never touches existing data.
  const missing = baselineTables(kind).filter((table) => !tableExists(driver, kind, table));
  if (missing.length) {
    driver.exec(MIGRATIONS[0][kind]);
    results.push({ version: 1, name: `baseline-heal:${missing.join(',')}` });
  }
  return results;
}

function runMigrations(driver, kind, options = {}) {
  if (kind !== 'postgres') return runMigrationsUnlocked(driver, kind, options);
  return driver.transaction(() => {
    driver.prepare('SELECT pg_advisory_xact_lock(?)').get(POSTGRES_MIGRATION_LOCK);
    return runMigrationsUnlocked(driver, kind, options);
  })();
}

/**
 * Bind audit-sidecar publication to the driver's outermost transaction.
 *
 * Both better-sqlite3 and the synchronous Postgres bridge expose the same
 * transaction(fn) surface.  Keeping this adapter here makes the ordering
 * explicit for both drivers: the anchor prepares its durable commit intent
 * after the callback has finished, but before COMMIT; a failed COMMIT restores
 * that intent after the database has rolled back.  Nested transactions merge
 * only the audit entries whose savepoint actually released successfully.
 */
function installAuditTransactionProtocol(driver, anchor) {
  if (!driver || typeof driver.transaction !== 'function') {
    throw new TypeError('audit transaction protocol requires a transactional driver');
  }
  if (!anchor || typeof anchor.prepareTransactionCommit !== 'function') {
    throw new TypeError('audit transaction protocol requires an audit anchor');
  }
  const originalTransaction = driver.transaction.bind(driver);
  const frames = [];

  driver.transaction = function auditAwareTransaction(fn) {
    if (typeof fn !== 'function') throw new TypeError('transaction callback must be a function');
    const nativeTransaction = originalTransaction((...args) => {
      const frame = frames[frames.length - 1];
      if (!frame) throw new Error('audit transaction frame is unavailable');
      const result = fn(...args);
      if (frame.outer && frame.entries.length) {
        anchor.prepareTransactionCommit(driver, frame.entries);
        frame.prepared = true;
      }
      return result;
    });

    return (...args) => {
      const frame = { outer: frames.length === 0, entries: [], prepared: false };
      frames.push(frame);
      try {
        // SQLite's deferred BEGIN lets two processes read the same audit head,
        // after which the loser cannot upgrade its stale snapshot to a writer.
        // BEGIN IMMEDIATE obtains the single-writer slot before that read and
        // respects busy_timeout. The Postgres bridge has no variant and keeps
        // using its transaction-scoped advisory audit lock.
        const runner = frame.outer && typeof nativeTransaction.immediate === 'function'
          ? nativeTransaction.immediate
          : nativeTransaction;
        const result = runner(...args);
        frames.pop();
        if (frame.outer) {
          if (frame.prepared) anchor.transactionCommitted(driver);
        } else {
          frames[frames.length - 1].entries.push(...frame.entries);
        }
        return result;
      } catch (error) {
        frames.pop();
        if (frame.outer && frame.prepared) {
          // The transaction callback already completed and its durable pending
          // record was published. A later error is a COMMIT-phase outcome
          // ambiguity: the server may have applied COMMIT and lost only the
          // response. Never erase the high-water without conclusive rollback
          // proof, or a deleted committed tail could be hidden on restart.
          try { anchor.transactionCommitUncertain(driver); }
          catch (uncertainError) { error.auditCommitUncertainError = uncertainError; }
        }
        throw error;
      }
    };
  };

  return function recordAuditEntry(entry) {
    const frame = frames[frames.length - 1];
    if (!frame) throw new Error('audit entry was appended outside a database transaction');
    frame.entries.push(entry);
  };
}

module.exports = {
  openStore,
  runMigrations,
  migrationApplied,
  installAuditTransactionProtocol,
  MIGRATIONS,
  _internal: {
    SQLITE_INITIALIZATION_LOCK_TIMEOUT_MS,
    POSTGRES_MIGRATION_LOCK,
    restrictPrivatePath,
    restrictSqliteArtifacts,
    sqliteArtifactPaths,
    installAuditTransactionProtocol,
  },
};
