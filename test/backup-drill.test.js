'use strict';
/** Disaster-recovery drill over the backup/verify/restore workflow. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-drill-test-'));
process.env.REDACTWALL_ENV_PATH = path.join(tempRoot, 'no.env');
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'redactwall.db');
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';

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
    REDACTWALL_ENV_PATH: path.join(tempRoot, 'no.env'),
    REDACTWALL_DB_PATH: dbPath,
    REDACTWALL_SECRET: 'unit-secret-stable',
    REDACTWALL_DATA_KEY: 'unit-data-key-stable',
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
  assert.match(path.basename(report.artifacts.keptAt), /^\.redactwall-drill-/);
  assert.strictEqual(path.dirname(report.artifacts.keptAt), drillDir);

  const output = io.lines.join('\n');
  assert.ok(!output.includes(SECRET));
  assert.ok(!output.includes('Member SSN'));
  const keptAt = report.artifacts.keptAt;
  assert.ok(fs.readdirSync(keptAt).some((name) => name.endsWith('.db')));
  assert.ok(fs.readdirSync(keptAt).some((name) => name.endsWith('.db.audit-state.json')));
  assert.ok(fs.readdirSync(keptAt).some((name) => name.endsWith('.db.audit-checkpoint.json')));
  const restoredPath = path.join(keptAt, 'restored-redactwall.db');
  assert.ok(fs.existsSync(restoredPath));
  assert.deepStrictEqual(fs.readdirSync(`${restoredPath}.audit-integrity`).sort(), [
    '.audit-integrity-checkpoint.json',
    '.audit-integrity-state.json',
  ]);
});

test('drill without --keep cleans up every artifact it created', async () => {
  const drillDir = path.join(tempRoot, 'drill-cleanup');
  const report = await drill.runDrill({ backupDir: drillDir, dbModule: db });
  assert.strictEqual(report.pass, true);
  assert.deepStrictEqual(report.artifacts, { cleanedUp: true });
  assert.deepStrictEqual(fs.readdirSync(drillDir), []);
});

test('drill never reuses or removes an operator preplanted drill-restore directory', async () => {
  const drillDir = path.join(tempRoot, 'drill-preplanted');
  const sentinel = path.join(drillDir, 'drill-restore', 'operator-owned.txt');
  fs.mkdirSync(path.dirname(sentinel), { recursive: true });
  fs.writeFileSync(sentinel, 'preserve operator data');

  const report = await drill.runDrill({ backupDir: drillDir, dbModule: db });

  assert.strictEqual(report.pass, true);
  assert.strictEqual(fs.readFileSync(sentinel, 'utf8'), 'preserve operator data');
  assert.deepStrictEqual(fs.readdirSync(drillDir), ['drill-restore']);
});

test('SQLite restore and inspection failures clean the owned private workspace', async (t) => {
  for (const failurePoint of ['restore', 'inspection']) {
    await t.test(failurePoint, async () => {
      const drillDir = path.join(tempRoot, `drill-${failurePoint}-failure`);
      let workspace;
      await assert.rejects(() => drill.runDrill({
        backupDir: drillDir,
        dbModule: db,
        createBackup: async (options) => {
          workspace = options.outDir;
          return backup.createBackup(options);
        },
        restoreBackup: failurePoint === 'restore'
          ? ({ to }) => {
              fs.writeFileSync(to, 'sensitive partial restore');
              fs.mkdirSync(`${to}.audit-integrity`);
              fs.writeFileSync(path.join(`${to}.audit-integrity`, 'partial'), 'sensitive');
              throw new Error('synthetic SQLite restore failure');
            }
          : backup.restoreBackup,
        inspectRestoredDb: failurePoint === 'inspection'
          ? () => { throw new Error('synthetic SQLite inspection failure'); }
          : drill.inspectRestoredDb,
      }), new RegExp(`synthetic SQLite ${failurePoint} failure`));
      assert.strictEqual(fs.existsSync(workspace), false);
      assert.deepStrictEqual(fs.readdirSync(drillDir), []);
    });
  }
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
  ], { cwd: REPO_ROOT, env: childEnv(process.env.REDACTWALL_DB_PATH), encoding: 'utf8' });
  assert.strictEqual(pass.status, 0, pass.stderr);
  const cliReport = JSON.parse(pass.stdout);
  assert.strictEqual(cliReport.result, 'PASS');
  assert.ok(!pass.stdout.includes(SECRET));

  const tamperedDb = path.join(tempRoot, 'tampered', 'redactwall.db');
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
  assert.throws(() => drill.parseArgs(['--backup-dir']), /requires a value/);
  assert.throws(() => drill.parseArgs(['--backup-dir', '--keep']), /requires a value/);
});

test('drill cleanup identity comparison does not round distinct filesystem ids', () => {
  const shared = { dev: 7n, birthtimeNs: 11n };
  const left = { ...shared, ino: 9007199254740992n };
  const right = { ...shared, ino: 9007199254740993n };
  assert.strictEqual(Number(left.ino), Number(right.ino), 'fixture collides after unsafe Number coercion');
  assert.strictEqual(drill._internal.sameArtifactIdentity(left, right), false);
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
