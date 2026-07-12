'use strict';
/**
 * One-command disaster-recovery drill for the evidence store.
 *
 * SQLite (default driver): creates a backup with scripts/backup-store.js,
 * verifies the complete manifest, restores to a scratch path, authenticates
 * the restored database through its runtime state/checkpoint sidecars, and
 * proves the audit chain plus row counts survived the round trip.
 *
 * Postgres (REDACTWALL_DB_DRIVER=postgres): dumps with pg_dump, restores into a
 * uniquely named absent scratch database through backup-store's guarded
 * restore protocol, verifies the audit chain and counts there, and removes
 * only the exact database identity returned by that restore. --keep retains
 * the unique private drill workspace. The connected role must be a
 * non-superuser with CREATEDB for the scratch restore.
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
const backup = require('./backup-store');
const privatePaths = require('../server/private-path');

function parseArgs(argv) {
  const out = { keep: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--keep') out.keep = true;
    else if (arg === '--backup-dir') {
      if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) {
        throw new Error('--backup-dir requires a value');
      }
      out.backupDir = argv[++i];
    }
    else throw new Error(`unknown argument: ${arg} (expected --backup-dir <dir> and/or --keep)`);
  }
  return out;
}

function exactArtifactStat(target, directory, label) {
  const stat = fs.lstatSync(target, { bigint: true });
  if (stat.isSymbolicLink?.() || stat.dev === 0n || stat.ino === 0n
      || (directory ? !stat.isDirectory() : !stat.isFile())
      || (!directory && stat.nlink !== 1n)) {
    throw new Error(`${label} has no stable filesystem identity: ${target}`);
  }
  return stat;
}

function sameArtifactIdentity(expected, actual) {
  return expected.dev === actual.dev && expected.ino === actual.ino
    && expected.birthtimeNs === actual.birthtimeNs;
}

function privateDirectoryOptions(security, label) {
  return {
    ...(security.privatePathSecurity || security),
    fs,
    directory: true,
    fresh: true,
    label,
    ownerLabel: label,
  };
}

function securePrivateDirectory(target, security, label, expected) {
  const options = privateDirectoryOptions(security, label);
  privatePaths.restrictPrivatePath(target, options);
  privatePaths.assertPrivatePath(target, options);
  const current = exactArtifactStat(target, true, label);
  if (!sameArtifactIdentity(expected, current)) throw new Error(`${label} changed while securing it`);
}

function createWorkDir(backupDir, security = {}) {
  const parent = path.resolve(backupDir || os.tmpdir());
  fs.mkdirSync(parent, { recursive: true });
  const dir = fs.mkdtempSync(path.join(parent, '.redactwall-drill-'));
  const workDir = {
    dir,
    parent,
    identity: exactArtifactStat(dir, true, 'backup drill workspace'),
    artifacts: new Map(),
  };
  try {
    securePrivateDirectory(dir, security, 'backup drill workspace', workDir.identity);
    return workDir;
  } catch (error) {
    try { cleanupWorkDir(workDir); } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], `failed to secure backup drill workspace; ${cleanupError.message}`);
    }
    throw error;
  }
}

function childRelativePath(workDir, target) {
  const resolved = path.resolve(target);
  const relative = path.relative(workDir.dir, resolved);
  if (!relative || relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) {
    throw new Error(`backup drill artifact escaped its private workspace: ${resolved}`);
  }
  return relative;
}

function trackArtifact(workDir, target, directory, label) {
  if (!target) return;
  const relative = childRelativePath(workDir, target);
  const identity = exactArtifactStat(path.resolve(target), directory, label);
  workDir.artifacts.set(relative, { directory, identity, label });
}

function trackCreatedArtifacts(workDir, created) {
  if (!created) return;
  for (const [field, target] of Object.entries({
    file: created.file,
    auditStateFile: created.auditStateFile,
    auditCheckpointFile: created.auditCheckpointFile,
    manifestFile: created.manifestFile,
  })) trackArtifact(workDir, target, false, `backup drill ${field}`);
}

function createPrivateChildDirectory(workDir, target, security, label) {
  fs.mkdirSync(target, { mode: 0o700 });
  trackArtifact(workDir, target, true, label);
  const expected = workDir.artifacts.get(childRelativePath(workDir, target)).identity;
  securePrivateDirectory(target, security, label, expected);
}

function trackRestoredArtifacts(workDir, restored) {
  if (!restored) return;
  const files = [restored.file, restored.manifestFile, restored.auditStateFile, restored.auditCheckpointFile];
  const directories = new Set(files.filter(Boolean).map((file) => path.dirname(path.resolve(file))));
  for (const directory of directories) {
    if (directory !== workDir.dir) trackArtifact(workDir, directory, true, 'backup drill restored directory');
  }
  for (const file of files) trackArtifact(workDir, file, false, 'backup drill restored artifact');
}

function pathEntryExists(target) {
  try { fs.lstatSync(target); return true; } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

function retainedWorkspacePath(quarantine, original) {
  if (!pathEntryExists(original) && pathEntryExists(quarantine)) {
    try { fs.renameSync(quarantine, original); return original; } catch {}
  }
  return quarantine;
}

function assertQuarantinedWorkspace(workDir, quarantine) {
  const current = exactArtifactStat(quarantine, true, 'quarantined backup drill workspace');
  if (!sameArtifactIdentity(workDir.identity, current)) {
    throw new Error('backup drill workspace identity changed before cleanup');
  }
  for (const [relative, artifact] of workDir.artifacts) {
    const target = path.join(quarantine, relative);
    const stat = exactArtifactStat(target, artifact.directory, artifact.label);
    if (!sameArtifactIdentity(artifact.identity, stat)) {
      throw new Error(`${artifact.label} identity changed before cleanup: ${target}`);
    }
  }
}

function cleanupWorkDir(workDir) {
  const quarantine = path.join(
    workDir.parent,
    `.${path.basename(workDir.dir)}.cleanup-${process.pid}-${crypto.randomBytes(12).toString('hex')}`,
  );
  try {
    fs.renameSync(workDir.dir, quarantine);
  } catch (error) {
    throw new Error(`backup drill cleanup refused; workspace retained at ${workDir.dir}`, { cause: error });
  }
  try {
    assertQuarantinedWorkspace(workDir, quarantine);
  } catch (error) {
    const retainedAt = retainedWorkspacePath(quarantine, workDir.dir);
    throw new Error(`backup drill cleanup refused; changed workspace or artifacts retained at ${retainedAt}`, { cause: error });
  }
  fs.rmSync(quarantine, { recursive: true, force: true });
  privatePaths.fsyncDirectory(workDir.parent, { fs });
}

/** Open the restored copy read-only and measure it independently. */
function inspectRestoredDb(file) {
  const authenticated = backup.verifyBackup({ file });
  const restoredDb = new Database(file, { readonly: true, fileMustExist: true });
  try {
    return {
      auditIntegrity: authenticated.auditIntegrity,
      queryCount: restoredDb.prepare('SELECT COUNT(*) n FROM queries').get().n,
      auditCount: restoredDb.prepare('SELECT COUNT(*) n FROM audit').get().n,
      sha256: authenticated.backupSha256,
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

// ---- Postgres drill ----------------------------------------------------------

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

async function captureCleanupFailure(failures, label, action) {
  try { await action(); } catch (error) { failures.push({ label, error }); }
}

function throwPgDrillFailure(primaryError, cleanupFailures, recoveryWorkspace = null) {
  if (primaryError && cleanupFailures.length === 0 && !recoveryWorkspace) throw primaryError;
  if (!primaryError && cleanupFailures.length === 0 && !recoveryWorkspace) return;
  const details = cleanupFailures
    .map((failure) => `${failure.label}: ${failure.error.message}`)
    .join('; ');
  const recovery = recoveryWorkspace
    ? `; private recovery workspace retained at ${recoveryWorkspace}` : '';
  const message = primaryError
    ? `Postgres backup drill failed: ${primaryError.message}${details ? `; cleanup also failed: ${details}` : ''}${recovery}`
    : `Postgres backup drill cleanup failed: ${details}${recovery}`;
  const errors = [primaryError, ...cleanupFailures.map((failure) => failure.error)].filter(Boolean);
  throw new AggregateError(errors, message);
}

function exactPgRestoreIdentity(restored, scratchDb) {
  const identity = restored && restored.databaseIdentity;
  const oid = String(identity && identity.oid || '');
  const ownerOid = String(identity && identity.ownerOid || '');
  if (!restored || restored.ok !== true || !identity || identity.name !== scratchDb
      || !/^[1-9][0-9]*$/.test(oid) || !/^[1-9][0-9]*$/.test(ownerOid)) {
    throw new Error(
      `Postgres guarded restore did not return the exact identity for ${scratchDb}; automatic database cleanup was skipped`,
    );
  }
  return { name: scratchDb, oid, ownerOid };
}

async function performPgDrill(context, state) {
  const created = await context.create({ outDir: context.workDir.dir, dbModule: context.db });
  trackCreatedArtifacts(context.workDir, created);
  const verified = context.verify({ file: created.file, manifestFile: created.manifestFile });
  let restored = null;
  if (verified.ok) {
    createPrivateChildDirectory(context.workDir, context.runtimeRoot, context.opts.security || {}, 'Postgres drill runtime directory');
    state.restoreAttempted = true;
    restored = await context.restore({
      file: created.file,
      to: context.scratchDb,
      manifestFile: created.manifestFile,
      auditDir: context.auditDir,
    });
    state.databaseIdentity = exactPgRestoreIdentity(restored, context.scratchDb);
    trackRestoredArtifacts(context.workDir, restored);
  }
  return buildPgReport({
    created, verified, restored, scratchDb: context.scratchDb,
    workDir: context.workDir.dir, keep: !!context.opts.keep,
  });
}

async function cleanupPgDrill(context, state, primaryError) {
  const cleanupFailures = [];
  if (state.databaseIdentity) {
    await captureCleanupFailure(cleanupFailures, 'guarded scratch database cleanup', async () => {
      const result = await context.cleanupDatabase({
        connectionString: context.connectionString,
        databaseIdentity: state.databaseIdentity,
        env: context.env,
      });
      if (!result || result.ok !== true) {
        throw new Error('guarded restore cleanup did not confirm removal');
      }
    });
  }
  const databaseCleanupFailed = cleanupFailures.length > 0;
  const ownershipUnknown = !!primaryError && state.restoreAttempted && !state.databaseIdentity;
  const recoveryWorkspace = databaseCleanupFailed || ownershipUnknown ? context.workDir.dir : null;
  if (!context.opts.keep && !recoveryWorkspace) {
    await captureCleanupFailure(cleanupFailures, 'workspace cleanup hook', async () => {
      if (context.opts.beforeWorkspaceCleanup) await context.opts.beforeWorkspaceCleanup(context);
    });
    await captureCleanupFailure(cleanupFailures, 'private drill workspace', () => cleanupWorkDir(context.workDir));
  }
  return { cleanupFailures, recoveryWorkspace };
}

/** Dump → guarded restore into an absent scratch name → exact-identity cleanup. */
async function runPgDrill(opts, db, create) {
  const connectionString = process.env.REDACTWALL_DATABASE_URL || process.env.DATABASE_URL;
  if (!connectionString) throw new Error('postgres drill requires REDACTWALL_DATABASE_URL');
  backup.assertPostgresConnectionUrl(connectionString);
  const workDir = createWorkDir(opts.backupDir, opts.security);
  const scratchDb = 'redactwall_drill_' + crypto.randomBytes(5).toString('hex');
  const runtimeRoot = path.join(workDir.dir, `${scratchDb}-runtime`);
  const context = {
    opts, db, create, connectionString, workDir, scratchDb, runtimeRoot,
    auditDir: path.join(runtimeRoot, 'audit'),
    env: opts.env || process.env,
    verify: opts.verifyBackup || backup.verifyBackup,
    restore: opts.restoreBackup || backup.restoreBackup,
    cleanupDatabase: opts.cleanupPgRestoreDatabase || backup.cleanupPgRestoreDatabase,
  };
  const state = { databaseIdentity: null, restoreAttempted: false };
  let report;
  let primaryError = null;
  try { report = await performPgDrill(context, state); } catch (error) { primaryError = error; }
  const cleanup = await cleanupPgDrill(context, state, primaryError);
  throwPgDrillFailure(primaryError, cleanup.cleanupFailures, cleanup.recoveryWorkspace);
  return report;
}

async function performSqliteDrill(context) {
  const created = await context.create({ outDir: context.workDir.dir, dbModule: context.db });
  trackCreatedArtifacts(context.workDir, created);
  const verified = context.verify({ file: created.file, manifestFile: created.manifestFile });
  const restored = verified.ok
    ? context.restore({ file: created.file, to: context.restoredPath, force: true })
    : null;
  trackRestoredArtifacts(context.workDir, restored);
  const inspection = restored ? context.inspect(context.restoredPath) : null;
  return buildReport({
    created, verified, restored, inspection,
    workDir: context.workDir.dir, keep: !!context.opts.keep,
  });
}

function throwSqliteDrillFailure(primaryError, cleanupFailures) {
  if (!primaryError && cleanupFailures.length === 0) return;
  const errors = [primaryError, ...cleanupFailures.map((failure) => failure.error)].filter(Boolean);
  if (errors.length === 1) throw errors[0];
  const details = cleanupFailures.map((failure) => `${failure.label}: ${failure.error.message}`).join('; ');
  const message = primaryError
    ? `SQLite backup drill failed: ${primaryError.message}; cleanup also failed: ${details}`
    : `SQLite backup drill cleanup failed: ${details}`;
  throw new AggregateError(errors, message);
}

async function runSqliteDrill(opts, db, create) {
  const workDir = createWorkDir(opts.backupDir, opts.security);
  const context = {
    opts, db, create, workDir,
    restoredPath: path.join(workDir.dir, 'restored-redactwall.db'),
    verify: opts.verifyBackup || backup.verifyBackup,
    restore: opts.restoreBackup || backup.restoreBackup,
    inspect: opts.inspectRestoredDb || inspectRestoredDb,
  };
  let report;
  let primaryError = null;
  try { report = await performSqliteDrill(context); } catch (error) { primaryError = error; }
  const cleanupFailures = [];
  if (!opts.keep) {
    await captureCleanupFailure(cleanupFailures, 'workspace cleanup hook', async () => {
      if (opts.beforeWorkspaceCleanup) await opts.beforeWorkspaceCleanup(context);
    });
    await captureCleanupFailure(cleanupFailures, 'private drill workspace', () => cleanupWorkDir(workDir));
  }
  throwSqliteDrillFailure(primaryError, cleanupFailures);
  return report;
}

async function runDrill(opts = {}) {
  const driver = String(process.env.REDACTWALL_DB_DRIVER || '').trim().toLowerCase();
  const postgresConfigured = ['postgres', 'postgresql', 'pg'].includes(driver);
  if (!opts.dbModule && postgresConfigured) {
    const connectionString = process.env.REDACTWALL_DATABASE_URL || process.env.DATABASE_URL;
    if (!connectionString) throw new Error('postgres drill requires REDACTWALL_DATABASE_URL');
    backup.assertPostgresConnectionUrl(connectionString);
  }
  const db = opts.dbModule || require('../server/db');
  const create = opts.createBackup || backup.createBackup;
  if ((db._driverKind || 'sqlite') === 'postgres') return runPgDrill(opts, db, create);
  return runSqliteDrill(opts, db, create);
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
  _internal: {
    cleanupWorkDir,
    createWorkDir,
    exactArtifactStat,
    sameArtifactIdentity,
    exactPgRestoreIdentity,
  },
};
