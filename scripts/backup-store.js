'use strict';
/**
 * Backup, verify, and offline-restore the evidence store.
 *
 * SQLite (default driver): online `.backup()` copy plus a manifest.
 * Postgres (REDACTWALL_DB_DRIVER=postgres): drives pg_dump/pg_restore (custom
 * format); credentials travel via libpq environment variables so the
 * connection string never appears in argv, output, or the manifest.
 *
 * Either way the manifest intentionally contains only metadata, hashes,
 * counts, and audit verification results. The backup artifact itself is
 * sensitive runtime state.
 */
require('../server/env').loadEnv();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const Database = require('better-sqlite3');
const auditIntegrity = require('../server/audit-integrity');

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      out._.push(arg);
      continue;
    }
    const key = arg.slice(2);
    if (key === 'force') {
      out.force = true;
      continue;
    }
    out[key] = argv[++i];
  }
  return out;
}

function sha256File(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}

function nowStamp(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function ensureParent(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
}

function assertWritable(file, force) {
  ensureParent(file);
  if (fs.existsSync(file) && !force) throw new Error(`${file} already exists; pass --force to overwrite`);
}

function resolveCreateTargets({ outDir, file, manifestFile, extension = '.db' } = {}) {
  const backupDir = path.resolve(outDir || path.join(process.cwd(), 'backups'));
  const backupFile = path.resolve(file || path.join(backupDir, `redactwall-${nowStamp()}${extension}`));
  const manifestPath = path.resolve(manifestFile || `${backupFile}.manifest.json`);
  return { backupFile, manifestPath };
}

function assertBackupSource(db) {
  const sourceIntegrity = db.verifyAuditChain();
  if (!sourceIntegrity.ok) {
    throw new Error(`refusing to back up a database with broken audit integrity: ${sourceIntegrity.reason || 'unknown'}`);
  }
  return sourceIntegrity;
}

function readManifest(file) {
  const manifestPath = file.endsWith('.json') ? file : `${file}.manifest.json`;
  if (!fs.existsSync(manifestPath)) return null;
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
}

// ---- Postgres mode -----------------------------------------------------------

const PG_TOOL_INSTALL_HINT = 'install the PostgreSQL client tools (Debian/Ubuntu: apt-get install postgresql-client; ' +
  'RHEL/Amazon Linux: dnf install postgresql16; macOS: brew install libpq) with a major version >= the server\'s';

function pgConnectionString(explicit) {
  const connectionString = explicit || process.env.REDACTWALL_DATABASE_URL || process.env.DATABASE_URL;
  if (!connectionString) throw new Error('postgres backups require REDACTWALL_DATABASE_URL');
  return connectionString;
}

/** Custom-format pg_dump archives start with the "PGDMP" magic bytes. */
function isPgDumpFile(file) {
  let fd;
  try { fd = fs.openSync(file, 'r'); } catch { return false; }
  try {
    const head = Buffer.alloc(5);
    fs.readSync(fd, head, 0, 5, 0);
    return head.toString('latin1') === 'PGDMP';
  } finally {
    fs.closeSync(fd);
  }
}

/** libpq environment for pg_dump/pg_restore: credentials via env, never argv. */
function pgConnectionEnv(connectionString) {
  const url = new URL(connectionString);
  const env = { ...process.env };
  const host = url.hostname || url.searchParams.get('host');
  if (host) env.PGHOST = host;
  if (url.port) env.PGPORT = url.port;
  if (url.username) env.PGUSER = decodeURIComponent(url.username);
  if (url.password) env.PGPASSWORD = decodeURIComponent(url.password);
  const database = pgDatabaseName(connectionString);
  if (database) env.PGDATABASE = database;
  const sslmode = url.searchParams.get('sslmode');
  if (sslmode) env.PGSSLMODE = sslmode;
  return env;
}

function pgDatabaseName(connectionString) {
  return decodeURIComponent(new URL(connectionString).pathname.replace(/^\//, ''));
}

/** `to` is either a bare database name (same server) or a full postgres:// URL. */
function deriveDatabaseUrl(baseConnectionString, to) {
  if (/^[A-Za-z_][A-Za-z0-9_$]*$/.test(to)) {
    const url = new URL(baseConnectionString);
    url.pathname = '/' + to;
    return url.toString();
  }
  return new URL(to).toString();
}

/** Credential-free form for output: user and host stay, the password goes. */
function sanitizeDatabaseUrl(connectionString) {
  const url = new URL(connectionString);
  url.password = '';
  return url.toString();
}

function runPgTool(tool, args, connectionString) {
  const result = spawnSync(tool, [...args, '--no-password'], {
    env: pgConnectionEnv(connectionString),
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error && result.error.code === 'ENOENT') {
    throw new Error(`${tool} not found on PATH; ${PG_TOOL_INSTALL_HINT}`);
  }
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const stderr = String(result.stderr || '').trim().split(/\r?\n/).slice(-4).join(' | ');
    throw new Error(`${tool} exited with status ${result.status}: ${stderr || 'no error output'}`);
  }
  return result;
}

function buildPgManifest({ db, connectionString, backupFile, backupSha256, sourceIntegrity }) {
  return {
    schemaVersion: 1,
    driver: 'postgres',
    format: 'pg_dump-custom',
    createdAt: new Date().toISOString(),
    service: { name: 'RedactWall', version: require('../package.json').version },
    sourceDatabase: pgDatabaseName(connectionString),
    backupFile: path.basename(backupFile),
    backupBytes: fs.statSync(backupFile).size,
    backupSha256,
    sourceIntegrity,
    backupIntegrity: null,
    stats: db.stats(),
    rawPromptBodiesIncluded: false,
    note: 'The .dump archive is sensitive runtime state. This manifest contains no prompt bodies and no connection credentials; verify restores with backup-drill.',
  };
}

/**
 * Postgres backup: pg_dump custom format. backupIntegrity stays null in the
 * manifest because verifying a dump's audit chain requires a restore — that is
 * backup-drill's job (restore into a scratch database, verify, drop).
 */
async function createPgBackup({ outDir, file, manifestFile, dbModule, connectionString, force = false } = {}) {
  const db = dbModule || require('../server/db');
  const connString = pgConnectionString(connectionString);
  const sourceIntegrity = assertBackupSource(db);
  const { backupFile, manifestPath } = resolveCreateTargets({ outDir, file, manifestFile, extension: '.dump' });
  assertWritable(backupFile, force);
  assertWritable(manifestPath, force);
  if (fs.existsSync(backupFile)) fs.rmSync(backupFile, { force: true });

  // --enable-row-security: queries has FORCE ROW LEVEL SECURITY, which pg_dump
  // otherwise refuses as a non-BYPASSRLS role. A fresh session has a blank
  // redactwall.org_id (operator mode), so every tenant row is visible and the
  // dump is complete; the drill's count checks would expose a partial dump.
  runPgTool('pg_dump', ['--format=custom', '--enable-row-security', `--dbname=${pgDatabaseName(connString)}`, `--file=${backupFile}`], connString);
  const backupSha256 = sha256File(backupFile);
  const manifest = buildPgManifest({ db, connectionString: connString, backupFile, backupSha256, sourceIntegrity });
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  return {
    ok: true, driver: 'postgres', file: backupFile, bytes: manifest.backupBytes,
    backupSha256, auditIntegrity: sourceIntegrity, manifestOk: true,
    manifestFile: manifestPath, manifest,
  };
}

/** A dump cannot be opened in place; verification here is the manifest hash. */
function verifyPgBackup({ file, manifestFile } = {}) {
  const dumpPath = path.resolve(file);
  const backupSha256 = sha256File(dumpPath);
  const manifest = manifestFile
    ? JSON.parse(fs.readFileSync(path.resolve(manifestFile), 'utf8'))
    : readManifest(dumpPath);
  // A missing manifest is not a pass: without it the dump is unverifiable, so
  // restorePgBackup must refuse (or require an explicit override) rather than
  // load a possibly-tampered archive over the target database.
  const unverifiable = !manifest;
  const manifestOk = !unverifiable && manifest.backupSha256 === backupSha256;
  return {
    ok: manifestOk,
    driver: 'postgres',
    file: dumpPath,
    bytes: fs.statSync(dumpPath).size,
    backupSha256,
    manifestOk,
    unverifiable,
    note: unverifiable
      ? 'no manifest found next to the dump; integrity cannot be verified — pass --manifest <file> or --force to override'
      : 'pg_dump archive verified by manifest hash; run backup:drill (or a restore) to verify the audit chain end to end',
  };
}

/** Open the restored database through the production driver and measure it. */
function verifyRestoredPgDatabase(targetUrl) {
  const { createPgDriver } = require('../server/storage/pg-driver');
  const driver = createPgDriver(targetUrl);
  try {
    return {
      auditIntegrity: auditIntegrity.verifyAuditChainForDatabase(driver),
      queryCount: driver.prepare('SELECT COUNT(*) n FROM queries').get().n,
      auditCount: driver.prepare('SELECT COUNT(*) n FROM audit').get().n,
    };
  } finally {
    driver.close();
  }
}

/** Verifier-first: the manifest hash must match before pg_restore runs. */
function restorePgBackup({ file, to, manifestFile, force = false } = {}) {
  const verification = verifyPgBackup({ file, manifestFile });
  if (!verification.ok) {
    // A present-but-mismatched manifest signals tampering and is never
    // bypassable. A missing manifest is merely unverifiable and may be
    // overridden with --force (or by supplying an explicit --manifest).
    if (!(verification.unverifiable && force)) {
      throw new Error(verification.unverifiable
        ? 'refusing to restore a backup with no manifest to verify against; pass --manifest <file> or --force to override'
        : 'refusing to restore a backup that does not verify');
    }
  }
  const targetUrl = deriveDatabaseUrl(pgConnectionString(), to);
  const flags = ['--no-owner', '--no-privileges', '--exit-on-error'];
  if (force) flags.push('--clean', '--if-exists');
  runPgTool('pg_restore', [...flags, `--dbname=${pgDatabaseName(targetUrl)}`, path.resolve(file)], targetUrl);
  const inspection = verifyRestoredPgDatabase(targetUrl);
  return {
    ok: inspection.auditIntegrity.ok,
    driver: 'postgres',
    file: verification.file,
    backupSha256: verification.backupSha256,
    manifestOk: verification.manifestOk,
    auditIntegrity: inspection.auditIntegrity,
    queryCount: inspection.queryCount,
    auditCount: inspection.auditCount,
    restoredTo: sanitizeDatabaseUrl(targetUrl),
  };
}

// ---- SQLite mode + driver dispatch --------------------------------------------

function verifyBackup({ file, manifestFile } = {}) {
  if (!file) throw new Error('--file is required');
  const dbPath = path.resolve(file);
  if (isPgDumpFile(dbPath)) return verifyPgBackup({ file: dbPath, manifestFile });
  const dbFile = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    const auditIntegrityResult = auditIntegrity.verifyAuditChainForDatabase(dbFile);
    const backupSha256 = sha256File(dbPath);
    const manifest = manifestFile
      ? JSON.parse(fs.readFileSync(path.resolve(manifestFile), 'utf8'))
      : readManifest(dbPath);
    // A missing manifest is NOT a pass: without it the artifact hash is
    // unverifiable, so a hand-crafted or swapped .db must not restore as
    // "verified". Mirrors the Postgres path (unverifiable + --force override).
    const unverifiable = !manifest;
    const manifestOk = !unverifiable && manifest.backupSha256 === backupSha256;
    return {
      ok: auditIntegrityResult.ok && manifestOk,
      file: dbPath,
      bytes: fs.statSync(dbPath).size,
      backupSha256,
      auditIntegrity: auditIntegrityResult,
      manifestOk,
      unverifiable,
    };
  } finally {
    dbFile.close();
  }
}

async function createBackup(opts = {}) {
  const db = opts.dbModule || require('../server/db');
  const kind = db._driverKind || 'sqlite';
  if (kind === 'postgres') return createPgBackup({ ...opts, dbModule: db });
  if (kind !== 'sqlite') {
    throw new Error(`this backup tool covers the SQLite and Postgres stores; unsupported driver: ${kind}`);
  }
  return createSqliteBackup({ ...opts, dbModule: db });
}

async function createSqliteBackup({ outDir, file, manifestFile, dbModule: db, force = false } = {}) {
  const sourceIntegrity = assertBackupSource(db);
  const { backupFile, manifestPath } = resolveCreateTargets({ outDir, file, manifestFile });
  assertWritable(backupFile, force);
  assertWritable(manifestPath, force);
  if (fs.existsSync(backupFile)) fs.rmSync(backupFile, { force: true });

  await db._db.backup(backupFile);
  const verification = verifyBackup({ file: backupFile });
  const manifest = {
    schemaVersion: 1,
    createdAt: new Date().toISOString(),
    service: { name: 'RedactWall', version: require('../package.json').version },
    sourceDbFile: path.basename(db._dbPath || 'redactwall.db'),
    sourceDbPathHash: crypto.createHash('sha256').update(String(db._dbPath || '')).digest('hex'),
    backupFile: path.basename(backupFile),
    backupBytes: verification.bytes,
    backupSha256: verification.backupSha256,
    sourceIntegrity,
    backupIntegrity: verification.auditIntegrity,
    stats: db.stats(),
    rawPromptBodiesIncluded: false,
    note: 'The backup .db is sensitive runtime state. This manifest contains no prompt bodies.',
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  // Re-verify WITH the manifest just written so the create result reflects the
  // hash-bound state (the first pass ran before the manifest existed, which is
  // now correctly reported as unverifiable).
  const verified = verifyBackup({ file: backupFile, manifestFile: manifestPath });
  return { ...verified, manifestFile: manifestPath, manifest };
}

function restoreBackup({ file, to, manifestFile, force = false } = {}) {
  if (!to) throw new Error('--to is required');
  if (file && isPgDumpFile(path.resolve(file))) return restorePgBackup({ file, to, manifestFile, force });
  const verification = verifyBackup({ file, manifestFile });
  if (!verification.ok) {
    // A present-but-mismatched manifest signals tampering and is never
    // bypassable. A missing manifest is merely unverifiable and may be
    // overridden with --force (or by supplying an explicit --manifest).
    if (!(verification.unverifiable && force)) {
      throw new Error(verification.unverifiable
        ? 'refusing to restore a backup with no manifest to verify against; pass --manifest <file> or --force to override'
        : 'refusing to restore a backup that does not verify');
    }
  }
  const target = path.resolve(to);
  if (fs.existsSync(target) && !force) throw new Error(`${target} already exists; pass --force to overwrite`);
  ensureParent(target);
  fs.copyFileSync(path.resolve(file), target);
  // The restored .db has no sibling manifest; verify the audit chain end to end.
  const restoredDb = new Database(target, { readonly: true, fileMustExist: true });
  let auditIntegrityResult;
  try { auditIntegrityResult = auditIntegrity.verifyAuditChainForDatabase(restoredDb); } finally { restoredDb.close(); }
  return { ok: auditIntegrityResult.ok, restoredTo: target, file: target, backupSha256: sha256File(target), auditIntegrity: auditIntegrityResult, unverifiable: true };
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const create = deps.createBackup || createBackup;
  const verify = deps.verifyBackup || verifyBackup;
  const restore = deps.restoreBackup || restoreBackup;
  const args = parseArgs(argv);
  const command = args._[0] || 'create';
  const positional = args._.slice(1);
  let result;
  if (command === 'create') {
    result = await create({
      outDir: args.out || positional[0],
      file: args.file,
      manifestFile: args.manifest,
      force: args.force,
    });
  } else if (command === 'verify') {
    result = verify({ file: args.file || positional[0], manifestFile: args.manifest });
  } else if (command === 'restore') {
    result = restore({ file: args.file || positional[0], to: args.to || positional[1], manifestFile: args.manifest, force: args.force });
  }
  else throw new Error(`unknown command: ${command}`);
  io.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) main().catch((e) => { console.error(e.message); process.exit(1); });

module.exports = {
  parseArgs,
  createBackup,
  main,
  verifyBackup,
  restoreBackup,
  isPgDumpFile,
  pgConnectionEnv,
  deriveDatabaseUrl,
  sanitizeDatabaseUrl,
  runPgTool,
  verifyRestoredPgDatabase,
};
