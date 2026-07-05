'use strict';
/**
 * One-command disaster-recovery drill for the evidence store.
 *
 * SQLite (default driver): creates a backup with scripts/backup-store.js,
 * verifies the manifest, restores to a scratch path, re-opens the restored
 * database read-only, and proves the audit hash-chain plus row counts
 * survived the round trip.
 *
 * Postgres (SENTINEL_DB_DRIVER=postgres): dumps with pg_dump, restores into a
 * uniquely named scratch database on the same server, verifies the audit
 * chain and counts there, and always drops the scratch database afterwards
 * (--keep retains only the dump + manifest). The connected role needs
 * CREATEDB for the scratch restore.
 *
 * Either way the report contains only hashes, counts, and check results —
 * never prompt text or connection credentials.
 */
require('../server/env').loadEnv();
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const auditIntegrity = require('../server/audit-integrity');
const backup = require('./backup-store');

function parseArgs(argv) {
  const out = { keep: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--keep') out.keep = true;
    else if (arg === '--backup-dir') out.backupDir = argv[++i];
    else throw new Error(`unknown argument: ${arg} (expected --backup-dir <dir> and/or --keep)`);
  }
  return out;
}

function sha256File(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}

function resolveWorkDir(backupDir) {
  if (backupDir) {
    const dir = path.resolve(backupDir);
    fs.mkdirSync(dir, { recursive: true });
    return { dir, owned: false };
  }
  return { dir: fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-drill-')), owned: true };
}

/** Open the restored copy read-only and measure it independently. */
function inspectRestoredDb(file) {
  const restoredDb = new Database(file, { readonly: true, fileMustExist: true });
  try {
    return {
      auditIntegrity: auditIntegrity.verifyAuditChainForDatabase(restoredDb),
      queryCount: restoredDb.prepare('SELECT COUNT(*) n FROM queries').get().n,
      auditCount: restoredDb.prepare('SELECT COUNT(*) n FROM audit').get().n,
      sha256: sha256File(file),
    };
  } finally {
    restoredDb.close();
  }
}

function drillChecks({ created, verified, restored, inspection }) {
  const manifest = created.manifest || {};
  const stats = manifest.stats || {};
  return [
    { id: 'source_audit_chain_ok', ok: !!(manifest.sourceIntegrity && manifest.sourceIntegrity.ok) },
    { id: 'backup_verified', ok: !!verified.ok },
    { id: 'manifest_hash_matches', ok: !!verified.manifestOk },
    { id: 'restore_verified', ok: !!(restored && restored.ok) },
    { id: 'restored_audit_chain_ok', ok: !!(inspection && inspection.auditIntegrity.ok) },
    { id: 'restored_sha256_matches_manifest', ok: !!(inspection && inspection.sha256 === manifest.backupSha256) },
    { id: 'restored_query_count_matches_manifest', ok: !!(inspection && inspection.queryCount === stats.total) },
    { id: 'restored_audit_count_matches_backup', ok: !!(inspection && manifest.backupIntegrity && inspection.auditCount === manifest.backupIntegrity.count) },
  ];
}

function buildReport({ created, verified, restored, inspection, workDir, keep }) {
  const checks = drillChecks({ created, verified, restored, inspection });
  const pass = checks.every((c) => c.ok);
  return {
    drill: 'backup-restore',
    result: pass ? 'PASS' : 'FAIL',
    pass,
    completedAt: new Date().toISOString(),
    backup: {
      file: path.basename(created.file),
      bytes: created.bytes,
      sha256: created.backupSha256,
    },
    restored: inspection ? {
      sha256: inspection.sha256,
      queryCount: inspection.queryCount,
      auditCount: inspection.auditCount,
      auditChainOk: inspection.auditIntegrity.ok,
    } : null,
    checks,
    artifacts: keep ? { keptAt: workDir } : { cleanedUp: true },
    rawPromptBodiesIncluded: false,
  };
}

function cleanupArtifacts(workDir, created, restoredPath) {
  fs.rmSync(path.dirname(restoredPath), { recursive: true, force: true });
  if (workDir.owned) {
    fs.rmSync(workDir.dir, { recursive: true, force: true });
    return;
  }
  // Verifying a WAL-mode backup creates -wal/-shm sidecars next to it.
  for (const suffix of ['', '-wal', '-shm']) fs.rmSync(created.file + suffix, { force: true });
  fs.rmSync(created.manifestFile, { force: true });
}

// ---- Postgres drill ----------------------------------------------------------

async function withPgClient(connectionString, fn) {
  const { Client } = require('pg');
  const client = new Client({ connectionString });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

function pgDrillChecks({ created, verified, restored }) {
  const manifest = created.manifest || {};
  const stats = manifest.stats || {};
  const source = manifest.sourceIntegrity || {};
  return [
    { id: 'source_audit_chain_ok', ok: !!source.ok },
    { id: 'backup_verified', ok: !!verified.ok },
    { id: 'manifest_hash_matches', ok: !!verified.manifestOk },
    { id: 'restore_verified', ok: !!(restored && restored.ok) },
    { id: 'restored_audit_chain_ok', ok: !!(restored && restored.auditIntegrity && restored.auditIntegrity.ok) },
    { id: 'restored_query_count_matches_manifest', ok: !!(restored && restored.queryCount === stats.total) },
    { id: 'restored_audit_count_matches_source', ok: !!(restored && restored.auditIntegrity && restored.auditIntegrity.count === source.count) },
  ];
}

function buildPgReport({ created, verified, restored, scratchDb, workDir, keep }) {
  const checks = pgDrillChecks({ created, verified, restored });
  const pass = checks.every((c) => c.ok);
  return {
    drill: 'backup-restore',
    driver: 'postgres',
    result: pass ? 'PASS' : 'FAIL',
    pass,
    completedAt: new Date().toISOString(),
    backup: {
      file: path.basename(created.file),
      bytes: created.bytes,
      sha256: created.backupSha256,
    },
    restored: restored ? {
      scratchDatabase: scratchDb,
      queryCount: restored.queryCount,
      auditCount: restored.auditCount,
      auditChainOk: !!(restored.auditIntegrity && restored.auditIntegrity.ok),
    } : null,
    checks,
    artifacts: keep ? { keptAt: workDir } : { cleanedUp: true },
    rawPromptBodiesIncluded: false,
  };
}

function cleanupPgArtifacts(workDir, created) {
  if (workDir.owned) {
    fs.rmSync(workDir.dir, { recursive: true, force: true });
    return;
  }
  fs.rmSync(created.file, { force: true });
  fs.rmSync(created.manifestFile, { force: true });
}

/** Dump → restore into a scratch database → verify there → drop it (always). */
async function runPgDrill(opts, db, create) {
  const connectionString = process.env.SENTINEL_DATABASE_URL || process.env.DATABASE_URL;
  if (!connectionString) throw new Error('postgres drill requires SENTINEL_DATABASE_URL');
  const workDir = resolveWorkDir(opts.backupDir);
  const scratchDb = 'promptwall_drill_' + crypto.randomBytes(5).toString('hex');
  const created = await create({ outDir: workDir.dir, dbModule: db });
  const verified = backup.verifyBackup({ file: created.file, manifestFile: created.manifestFile });
  let restored = null;
  if (verified.ok) {
    await withPgClient(connectionString, (client) => client.query(`CREATE DATABASE ${scratchDb}`));
    try {
      restored = backup.restoreBackup({ file: created.file, to: scratchDb });
    } finally {
      await withPgClient(connectionString, (client) => client.query(`DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`));
    }
  }
  const report = buildPgReport({ created, verified, restored, scratchDb, workDir: workDir.dir, keep: !!opts.keep });
  if (!opts.keep) cleanupPgArtifacts(workDir, created);
  return report;
}

async function runDrill(opts = {}) {
  const db = opts.dbModule || require('../server/db');
  const create = opts.createBackup || backup.createBackup;
  if ((db._driverKind || 'sqlite') === 'postgres') return runPgDrill(opts, db, create);
  const workDir = resolveWorkDir(opts.backupDir);
  const restoredPath = path.join(workDir.dir, 'drill-restore', 'restored-sentinel.db');
  const created = await create({ outDir: workDir.dir, dbModule: db });
  const verified = backup.verifyBackup({ file: created.file, manifestFile: created.manifestFile });
  const restored = verified.ok
    ? backup.restoreBackup({ file: created.file, to: restoredPath, force: true })
    : null;
  const inspection = restored ? inspectRestoredDb(restoredPath) : null;
  const report = buildReport({ created, verified, restored, inspection, workDir: workDir.dir, keep: !!opts.keep });
  if (!opts.keep) cleanupArtifacts(workDir, created, restoredPath);
  return report;
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const drill = deps.runDrill || runDrill;
  const args = parseArgs(argv);
  const report = await drill({ backupDir: args.backupDir, keep: args.keep });
  io.log(JSON.stringify(report, null, 2));
  return report;
}

if (require.main === module) {
  main()
    .then((report) => { if (!report.pass) process.exit(1); })
    .catch((e) => { console.error(e.message); process.exit(1); });
}

module.exports = {
  parseArgs,
  runDrill,
  inspectRestoredDb,
  main,
};
