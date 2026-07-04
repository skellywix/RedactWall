'use strict';
/** Backup/verify/restore workflow for the SQLite evidence store. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-backup-test-'));
process.env.SENTINEL_DB_PATH = path.join(tempRoot, 'sentinel.db');
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';

const db = require('../server/db');
const backup = require('../scripts/backup-store');

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(message); },
  };
}

test('backup workflow verifies and restores audit evidence without leaking manifest prompt data', async () => {
  const secret = '524-71-9043';
  const q = db.createQuery({
    status: 'pending',
    user: 'analyst@example.test',
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'Member SSN ' + secret,
    findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
  });
  db.appendAudit({ action: 'BLOCKED', queryId: q.id, actor: 'analyst@example.test', detail: 'structured pii detected' });

  const result = await backup.createBackup({ outDir: path.join(tempRoot, 'backups'), dbModule: db });
  assert.strictEqual(result.ok, true);
  assert.ok(fs.existsSync(result.file));
  assert.ok(fs.existsSync(result.manifestFile));
  assert.strictEqual(result.auditIntegrity.ok, true);
  assert.strictEqual(result.manifest.backupSha256, result.backupSha256);
  assert.ok(!JSON.stringify(result.manifest).includes(secret));
  assert.ok(!JSON.stringify(result.manifest).includes(tempRoot));
  assert.strictEqual(result.manifest.sourceDbFile, 'sentinel.db');
  assert.match(result.manifest.sourceDbPathHash, /^[a-f0-9]{64}$/);

  const verified = backup.verifyBackup({ file: result.file, manifestFile: result.manifestFile });
  assert.strictEqual(verified.ok, true);
  assert.strictEqual(verified.backupSha256, result.backupSha256);

  const restoredPath = path.join(tempRoot, 'restored', 'sentinel.db');
  const restored = backup.restoreBackup({ file: result.file, to: restoredPath });
  assert.strictEqual(restored.ok, true);
  assert.strictEqual(restored.restoredTo, restoredPath);
  assert.strictEqual(backup.verifyBackup({ file: restoredPath }).ok, true);
});

test('manifest hash mismatch makes verification fail and blocks restore', async () => {
  const result = await backup.createBackup({ outDir: path.join(tempRoot, 'manifest-mismatch'), dbModule: db });
  const manifest = JSON.parse(fs.readFileSync(result.manifestFile, 'utf8'));
  manifest.backupSha256 = '0'.repeat(64);
  fs.writeFileSync(result.manifestFile, JSON.stringify(manifest, null, 2));

  const verified = backup.verifyBackup({ file: result.file });
  assert.strictEqual(verified.auditIntegrity.ok, true);
  assert.strictEqual(verified.manifestOk, false);
  assert.strictEqual(verified.ok, false);
  assert.throws(
    () => backup.restoreBackup({ file: result.file, to: path.join(tempRoot, 'mismatched-restore', 'sentinel.db') }),
    /does not verify/,
  );
});

test('restore refuses to overwrite an existing target unless forced', async () => {
  const result = await backup.createBackup({ outDir: path.join(tempRoot, 'overwrite'), dbModule: db });
  const target = path.join(tempRoot, 'existing.db');
  fs.writeFileSync(target, 'already here');
  assert.throws(() => backup.restoreBackup({ file: result.file, to: target }), /already exists/);
  assert.strictEqual(backup.restoreBackup({ file: result.file, to: target, force: true }).ok, true);
});

test('create refuses to overwrite an explicit backup target unless forced', async () => {
  const target = path.join(tempRoot, 'explicit', 'sentinel.db');
  await backup.createBackup({ file: target, dbModule: db });
  await assert.rejects(() => backup.createBackup({ file: target, dbModule: db }), /already exists/);
  const forced = await backup.createBackup({ file: target, dbModule: db, force: true });
  assert.strictEqual(forced.ok, true);
});

test('create refuses existing manifest before writing a backup file', async () => {
  const target = path.join(tempRoot, 'manifest-collision', 'sentinel.db');
  const manifest = `${target}.manifest.json`;
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(manifest, '{"reserved":true}');

  await assert.rejects(
    () => backup.createBackup({ file: target, manifestFile: manifest, dbModule: db }),
    /already exists/,
  );
  assert.strictEqual(fs.existsSync(target), false);
});

test('create refuses to back up a database with broken audit integrity', async () => {
  await assert.rejects(() => backup.createBackup({
    dbModule: {
      verifyAuditChain() {
        return { ok: false, reason: 'hash_mismatch' };
      },
    },
  }), /broken audit integrity: hash_mismatch/);
});

test('argument parser preserves positional paths for npm-run portability', () => {
  assert.deepStrictEqual(
    backup.parseArgs(['create', 'backups']),
    { _: ['create', 'backups'] },
  );
  assert.deepStrictEqual(
    backup.parseArgs(['verify', '--file', 'backups/sentinel.db', '--manifest', 'manifest.json']),
    { _: ['verify'], file: 'backups/sentinel.db', manifest: 'manifest.json' },
  );
  assert.deepStrictEqual(
    backup.parseArgs(['restore', 'backups/sentinel.db', 'data/restored.db', '--force']),
    { _: ['restore', 'backups/sentinel.db', 'data/restored.db'], force: true },
  );
});

test('main dispatches create, verify, and restore commands with JSON output', async () => {
  const io = captureConsole();
  const calls = [];
  const deps = {
    console: io,
    async createBackup(opts) {
      calls.push(['create', opts]);
      return { ok: true, command: 'create' };
    },
    verifyBackup(opts) {
      calls.push(['verify', opts]);
      return { ok: true, command: 'verify' };
    },
    restoreBackup(opts) {
      calls.push(['restore', opts]);
      return { ok: true, command: 'restore' };
    },
  };

  assert.deepStrictEqual(await backup.main(['create', 'out-dir', '--file', 'backup.db', '--manifest', 'manifest.json', '--force'], deps), { ok: true, command: 'create' });
  assert.deepStrictEqual(await backup.main(['verify', 'backup.db', '--manifest', 'manifest.json'], deps), { ok: true, command: 'verify' });
  assert.deepStrictEqual(await backup.main(['restore', 'backup.db', 'restore.db', '--force'], deps), { ok: true, command: 'restore' });
  await assert.rejects(() => backup.main(['unknown'], deps), /unknown command/);

  assert.deepStrictEqual(calls, [
    ['create', { outDir: 'out-dir', file: 'backup.db', manifestFile: 'manifest.json', force: true }],
    ['verify', { file: 'backup.db', manifestFile: 'manifest.json' }],
    ['restore', { file: 'backup.db', to: 'restore.db', force: true }],
  ]);
  assert.strictEqual(JSON.parse(io.lines[0]).command, 'create');
  assert.strictEqual(JSON.parse(io.lines[1]).command, 'verify');
  assert.strictEqual(JSON.parse(io.lines[2]).command, 'restore');
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
