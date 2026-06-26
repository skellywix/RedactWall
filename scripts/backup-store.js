'use strict';
/**
 * Backup, verify, and offline-restore the SQLite evidence store.
 * The manifest intentionally contains only metadata, hashes, counts, and audit
 * verification results. The `.db` backup itself is sensitive runtime state.
 */
require('../src/env').loadEnv();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const auditIntegrity = require('../src/audit-integrity');

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

function resolveCreateTargets({ outDir, file, manifestFile } = {}) {
  const backupDir = path.resolve(outDir || path.join(process.cwd(), 'backups'));
  const backupFile = path.resolve(file || path.join(backupDir, `sentinel-${nowStamp()}.db`));
  const manifestPath = path.resolve(manifestFile || `${backupFile}.manifest.json`);
  return { backupFile, manifestPath };
}

function readManifest(file) {
  const manifestPath = file.endsWith('.json') ? file : `${file}.manifest.json`;
  if (!fs.existsSync(manifestPath)) return null;
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
}

function verifyBackup({ file, manifestFile } = {}) {
  if (!file) throw new Error('--file is required');
  const dbPath = path.resolve(file);
  const dbFile = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    const auditIntegrityResult = auditIntegrity.verifyAuditChainForDatabase(dbFile);
    const backupSha256 = sha256File(dbPath);
    const manifest = manifestFile
      ? JSON.parse(fs.readFileSync(path.resolve(manifestFile), 'utf8'))
      : readManifest(dbPath);
    const manifestOk = !manifest || manifest.backupSha256 === backupSha256;
    return {
      ok: auditIntegrityResult.ok && manifestOk,
      file: dbPath,
      bytes: fs.statSync(dbPath).size,
      backupSha256,
      auditIntegrity: auditIntegrityResult,
      manifestOk,
    };
  } finally {
    dbFile.close();
  }
}

async function createBackup({ outDir, file, manifestFile, dbModule, force = false } = {}) {
  const db = dbModule || require('../src/db');
  const sourceIntegrity = db.verifyAuditChain();
  if (!sourceIntegrity.ok) {
    throw new Error(`refusing to back up a database with broken audit integrity: ${sourceIntegrity.reason || 'unknown'}`);
  }
  const { backupFile, manifestPath } = resolveCreateTargets({ outDir, file, manifestFile });
  assertWritable(backupFile, force);
  assertWritable(manifestPath, force);
  if (fs.existsSync(backupFile)) fs.rmSync(backupFile, { force: true });

  await db._db.backup(backupFile);
  const verification = verifyBackup({ file: backupFile });
  const manifest = {
    schemaVersion: 1,
    createdAt: new Date().toISOString(),
    service: { name: 'PromptSentinel', version: require('../package.json').version },
    sourceDbFile: path.basename(db._dbPath || 'sentinel.db'),
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
  return { ...verification, manifestFile: manifestPath, manifest };
}

function restoreBackup({ file, to, force = false } = {}) {
  if (!to) throw new Error('--to is required');
  const verification = verifyBackup({ file });
  if (!verification.ok) throw new Error('refusing to restore a backup that does not verify');
  const target = path.resolve(to);
  if (fs.existsSync(target) && !force) throw new Error(`${target} already exists; pass --force to overwrite`);
  ensureParent(target);
  fs.copyFileSync(path.resolve(file), target);
  const restored = verifyBackup({ file: target });
  return { ...restored, restoredTo: target };
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const command = args._[0] || 'create';
  const positional = args._.slice(1);
  let result;
  if (command === 'create') {
    result = await createBackup({
      outDir: args.out || positional[0],
      file: args.file,
      manifestFile: args.manifest,
      force: args.force,
    });
  } else if (command === 'verify') {
    result = verifyBackup({ file: args.file || positional[0], manifestFile: args.manifest });
  } else if (command === 'restore') {
    result = restoreBackup({ file: args.file || positional[0], to: args.to || positional[1], force: args.force });
  }
  else throw new Error(`unknown command: ${command}`);
  console.log(JSON.stringify(result, null, 2));
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}

module.exports = {
  parseArgs,
  createBackup,
  verifyBackup,
  restoreBackup,
};
