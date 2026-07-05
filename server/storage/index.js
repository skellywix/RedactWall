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
const { MIGRATIONS } = require('./migrations');

function sqliteDriverAt(dbPath) {
  const Database = require('better-sqlite3');
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const d = new Database(dbPath);
  try { d.pragma('journal_mode = WAL'); } catch { try { d.pragma('journal_mode = DELETE'); } catch {} }
  try { d.pragma('synchronous = NORMAL'); } catch {}
  try { d.pragma('foreign_keys = ON'); } catch {}
  d.exec('CREATE TABLE IF NOT EXISTS _probe (x); DROP TABLE _probe;'); // throws on a bad FS
  return d;
}

function defaultSqlitePath(dataDir) {
  const preferred = path.join(dataDir, 'redactwall.db');
  const legacy = path.join(dataDir, 'sentinel.db');
  // Installs created before the RedactWall rebrand keep their existing store.
  if (!fs.existsSync(preferred) && fs.existsSync(legacy)) return legacy;
  return preferred;
}

function openSqlite(env, dataDir) {
  let dbPath = env.REDACTWALL_DB_PATH || defaultSqlitePath(dataDir);
  let driver;
  try {
    driver = sqliteDriverAt(dbPath);
  } catch (e) {
    const fallback = path.join(os.tmpdir(), 'redactwall', 'redactwall.db');
    console.error(`[db] store at ${dbPath} unusable (${e.code || e.message}); falling back to ${fallback}. ` +
      'Set REDACTWALL_DB_PATH to a local-disk path in production (never a cloud-synced folder).');
    dbPath = fallback;
    driver = sqliteDriverAt(dbPath);
  }
  return { driver, kind: 'sqlite', dbPath };
}

function openPostgres(env) {
  const connectionString = env.REDACTWALL_DATABASE_URL || env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('REDACTWALL_DB_DRIVER=postgres requires REDACTWALL_DATABASE_URL');
  }
  const { createPgDriver } = require('./pg-driver');
  return { driver: createPgDriver(connectionString), kind: 'postgres', dbPath: 'postgres' };
}

function openStore({ env = process.env, dataDir } = {}) {
  const requested = String(env.REDACTWALL_DB_DRIVER || 'sqlite').trim().toLowerCase();
  if (requested === 'postgres' || requested === 'postgresql' || requested === 'pg') {
    return openPostgres(env);
  }
  return openSqlite(env, dataDir);
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

/**
 * Apply pending migrations in order. A store created before this framework
 * existed (has `queries`, no migration rows) is stamped at the baseline
 * version instead of re-running it.
 */
function runMigrations(driver, kind) {
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

module.exports = { openStore, runMigrations, MIGRATIONS };
