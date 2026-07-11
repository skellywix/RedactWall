'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const Database = require('better-sqlite3');

const REPO_ROOT = path.join(__dirname, '..');
const WORKER = path.join(__dirname, 'support', 'audit-crash-worker.js');

function environment(root, extra = {}) {
  const data = path.join(root, 'data');
  fs.mkdirSync(data, { recursive: true, mode: 0o700 });
  const policy = path.join(root, 'policy.json');
  if (!fs.existsSync(policy)) fs.writeFileSync(policy, JSON.stringify({ enforcementMode: 'block' }));
  return {
    ...process.env,
    NODE_ENV: 'test',
    REDACTWALL_ENV_PATH: path.join(root, 'missing.env'),
    REDACTWALL_DB_PATH: path.join(data, 'redactwall.db'),
    REDACTWALL_AUDIT_DIR: path.join(root, 'audit-integrity'),
    REDACTWALL_AUDIT_STATE_PATH: '',
    REDACTWALL_AUDIT_CHECKPOINT_PATH: '',
    REDACTWALL_AUDIT_PENDING_PATH: '',
    REDACTWALL_SECRET: 'unit-audit-crash-secret',
    REDACTWALL_DATA_KEY: 'unit-audit-crash-data-key',
    INGEST_API_KEY: 'unit-audit-crash-ingest-key',
    ADMIN_PASSWORD: 'unit-pass',
    REDACTWALL_POLICY_PATH: policy,
    ...extra,
  };
}

function runWorker(root, mode, extra = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [WORKER], {
      cwd: REPO_ROOT,
      env: environment(root, { AUDIT_WORKER_MODE: mode, ...extra }),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code) => {
      let value;
      try { value = stdout ? JSON.parse(stdout) : null; } catch {}
      resolve({ code, value, stdout, stderr });
    });
  });
}

function tempRoot(t, label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `redactwall-${label}-`));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function databasePath(root) {
  return path.join(root, 'data', 'redactwall.db');
}

test('crash after a multi-row commit retains exact high-water and restart reconciles it', { timeout: 120_000 }, async (t) => {
  const root = tempRoot(t, 'audit-commit-crash');
  const crashed = await runWorker(root, 'append-crash', { AUDIT_BATCH_SIZE: '3' });
  assert.strictEqual(crashed.code, 73, crashed.stderr);
  assert.strictEqual(crashed.value.entries.length, 3);
  assert.strictEqual(crashed.value.pending.count, 3);
  assert.strictEqual(crashed.value.pending.entryId, crashed.value.entries[2].id);
  assert.strictEqual(crashed.value.pending.head, crashed.value.entries[2].hash);

  const raw = new Database(databasePath(root), { readonly: true });
  const last = raw.prepare('SELECT seq, entry FROM audit ORDER BY seq DESC LIMIT 1').get();
  raw.close();
  assert.strictEqual(Number(last.seq), crashed.value.pending.seq);
  assert.strictEqual(JSON.parse(last.entry).id, crashed.value.pending.entryId);

  const restarted = await runWorker(root, 'verify');
  assert.strictEqual(restarted.code, 0, restarted.stderr);
  assert.deepStrictEqual(restarted.value.result, { ok: true, count: 3 });
  assert.strictEqual(restarted.value.pending, null);
  assert.strictEqual(restarted.value.health.ok, true);
});

test('deleting a committed tail after crash is rejected at the restart boundary', { timeout: 180_000 }, async (t) => {
  const root = tempRoot(t, 'audit-tail-delete');
  const baseline = await runWorker(root, 'append-crash', { AUDIT_BATCH_SIZE: '2' });
  assert.strictEqual(baseline.code, 73, baseline.stderr);
  const baselineRestart = await runWorker(root, 'verify');
  assert.strictEqual(baselineRestart.code, 0, baselineRestart.stderr);

  const crashed = await runWorker(root, 'append-crash', { AUDIT_BATCH_SIZE: '1' });
  assert.strictEqual(crashed.code, 73, crashed.stderr);
  const pending = crashed.value.pending;
  const raw = new Database(databasePath(root));
  raw.exec('DROP TRIGGER IF EXISTS audit_append_only_delete');
  assert.strictEqual(raw.prepare('DELETE FROM audit WHERE seq = ?').run(pending.seq).changes, 1);
  raw.close();

  const rejected = await runWorker(root, 'verify');
  assert.notStrictEqual(rejected.code, 0, 'startup must not accept the older checkpoint');
  assert.match(rejected.stderr, /checkpoint-truncated|pending high-water no longer exists/);
});

test('callback rollback leaves the exact prior pending high-water and restart recovers', { timeout: 120_000 }, async (t) => {
  const root = tempRoot(t, 'audit-rollback');
  const rolledBack = await runWorker(root, 'rollback');
  assert.strictEqual(rolledBack.code, 0, rolledBack.stderr);
  assert.match(rolledBack.value.failure, /synthetic callback rollback/i);
  assert.deepStrictEqual(rolledBack.value.rows.map((entry) => entry.action), ['ROLLBACK_RETAINED']);
  assert.strictEqual(rolledBack.value.pending.entryId, rolledBack.value.retained.id);
  assert.strictEqual(rolledBack.value.pending.head, rolledBack.value.retained.hash);

  const restarted = await runWorker(root, 'verify');
  assert.strictEqual(restarted.code, 0, restarted.stderr);
  assert.deepStrictEqual(restarted.value.result, { ok: true, count: 1 });
  assert.strictEqual(restarted.value.pending, null);
});

test('concurrent processes serialize committed batches and shared pending publication', { timeout: 180_000 }, async (t) => {
  const root = tempRoot(t, 'audit-process-race');
  const coordination = path.join(root, 'coordination');
  fs.mkdirSync(coordination);
  const count = 4;
  const workers = Array.from({ length: count }, (_, index) => runWorker(root, 'concurrent', {
    AUDIT_COORDINATION_DIRECTORY: coordination,
    AUDIT_WORKER_ID: String(index),
  }));
  const deadline = Date.now() + 90_000;
  while (fs.readdirSync(coordination).filter((name) => name.startsWith('ready-')).length < count) {
    if (Date.now() > deadline) throw new Error('audit workers did not reach the barrier');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  fs.writeFileSync(path.join(coordination, 'go'), crypto.randomBytes(8));
  const results = await Promise.all(workers);
  assert.deepStrictEqual(results.map((result) => result.code), Array(count).fill(0),
    results.map((result) => result.stderr).filter(Boolean).join('\n'));

  const verified = await runWorker(root, 'verify');
  assert.strictEqual(verified.code, 0, verified.stderr);
  assert.deepStrictEqual(verified.value.result, { ok: true, count: count * 2 });
});
