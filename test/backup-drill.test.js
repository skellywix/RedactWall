'use strict';
/** Disaster-recovery drill over the backup/verify/restore workflow. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-drill-test-'));
process.env.SENTINEL_ENV_PATH = path.join(tempRoot, 'no.env');
process.env.SENTINEL_DB_PATH = path.join(tempRoot, 'sentinel.db');
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';

const db = require('../server/db');
const backup = require('../scripts/backup-store');
const drill = require('../scripts/backup-drill');

const REPO_ROOT = path.join(__dirname, '..');
const SECRET = '524-71-9043';

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(message); },
  };
}

function childEnv(dbPath) {
  return {
    ...process.env,
    SENTINEL_ENV_PATH: path.join(tempRoot, 'no.env'),
    SENTINEL_DB_PATH: dbPath,
    SENTINEL_SECRET: 'unit-secret-stable',
    SENTINEL_DATA_KEY: 'unit-data-key-stable',
  };
}

test('drill passes end-to-end and prints a prompt-free PASS report', async () => {
  const q = db.createQuery({
    status: 'pending',
    user: 'analyst@example.test',
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'Member SSN ' + SECRET,
    findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
  });
  db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'analyst@example.test', detail: 'structured pii detected' });

  const io = captureConsole();
  const drillDir = path.join(tempRoot, 'drill-backups');
  const report = await drill.main(['--backup-dir', drillDir, '--keep'], { console: io });

  assert.strictEqual(report.pass, true);
  assert.strictEqual(report.result, 'PASS');
  assert.strictEqual(report.drill, 'backup-restore');
  assert.ok(report.checks.length >= 7);
  assert.ok(report.checks.every((c) => c.ok === true));
  assert.match(report.backup.sha256, /^[a-f0-9]{64}$/);
  assert.strictEqual(report.restored.sha256, report.backup.sha256);
  assert.strictEqual(report.restored.queryCount, db.stats().total);
  assert.strictEqual(report.restored.auditChainOk, true);
  assert.strictEqual(report.rawPromptBodiesIncluded, false);
  assert.deepStrictEqual(report.artifacts, { keptAt: drillDir });

  const output = io.lines.join('\n');
  assert.ok(!output.includes(SECRET));
  assert.ok(!output.includes('Member SSN'));
  assert.ok(fs.readdirSync(drillDir).some((name) => name.endsWith('.db')));
  assert.ok(fs.existsSync(path.join(drillDir, 'drill-restore', 'restored-sentinel.db')));
});

test('drill without --keep cleans up every artifact it created', async () => {
  const drillDir = path.join(tempRoot, 'drill-cleanup');
  const report = await drill.runDrill({ backupDir: drillDir, dbModule: db });
  assert.strictEqual(report.pass, true);
  assert.deepStrictEqual(report.artifacts, { cleanedUp: true });
  assert.deepStrictEqual(fs.readdirSync(drillDir), []);
});

test('a corrupted backup file fails the drill', async () => {
  const createCorrupted = async (opts) => {
    const result = await backup.createBackup(opts);
    fs.appendFileSync(result.file, 'corrupted-trailing-bytes');
    return result;
  };
  const report = await drill.runDrill({
    backupDir: path.join(tempRoot, 'drill-corrupt'),
    keep: true,
    dbModule: db,
    createBackup: createCorrupted,
  });
  assert.strictEqual(report.pass, false);
  assert.strictEqual(report.result, 'FAIL');
  assert.strictEqual(report.restored, null);
  assert.strictEqual(report.checks.find((c) => c.id === 'backup_verified').ok, false);
  assert.strictEqual(report.checks.find((c) => c.id === 'restore_verified').ok, false);
});

test('drill CLI exits zero on PASS and non-zero on a tampered store', () => {
  const pass = spawnSync(process.execPath, [
    path.join(REPO_ROOT, 'scripts', 'backup-drill.js'),
    '--backup-dir', path.join(tempRoot, 'cli-pass'),
  ], { cwd: REPO_ROOT, env: childEnv(process.env.SENTINEL_DB_PATH), encoding: 'utf8' });
  assert.strictEqual(pass.status, 0, pass.stderr);
  const cliReport = JSON.parse(pass.stdout);
  assert.strictEqual(cliReport.result, 'PASS');
  assert.ok(!pass.stdout.includes(SECRET));

  const tamperedDb = path.join(tempRoot, 'tampered', 'sentinel.db');
  const seed = spawnSync(process.execPath, ['-e', `
    const db = require('./server/db');
    const q = db.createQuery({ status: 'allowed', redactedPrompt: 'benign', findings: [] });
    db.appendAudit({ action: 'ALLOWED', queryId: q.id, actor: 'drill-test' });
    // Editing evidence after the fact must break the chain's content binding.
    db._db.prepare("UPDATE queries SET data = replace(data, 'benign', 'tampered') WHERE id = ?").run(q.id);
  `], { cwd: REPO_ROOT, env: childEnv(tamperedDb), encoding: 'utf8' });
  assert.strictEqual(seed.status, 0, seed.stderr);

  const fail = spawnSync(process.execPath, [
    path.join(REPO_ROOT, 'scripts', 'backup-drill.js'),
    '--backup-dir', path.join(tempRoot, 'cli-fail'),
  ], { cwd: REPO_ROOT, env: childEnv(tamperedDb), encoding: 'utf8' });
  assert.notStrictEqual(fail.status, 0);
  assert.match(fail.stderr, /broken audit integrity/);
});

test('argument parser accepts only the documented drill flags', () => {
  assert.deepStrictEqual(drill.parseArgs([]), { keep: false });
  assert.deepStrictEqual(drill.parseArgs(['--backup-dir', 'backups', '--keep']), { keep: true, backupDir: 'backups' });
  assert.throws(() => drill.parseArgs(['--bogus']), /unknown argument/);
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
