'use strict';
/** Admin API wiring for application updates. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-update-api-'));
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'redactwall.db');
process.env.REDACTWALL_UPDATE_CONFIG_PATH = path.join(tempRoot, 'update-settings.json');
process.env.REDACTWALL_UPDATE_STATE_PATH = path.join(tempRoot, 'update-state.json');
process.env.REDACTWALL_UPDATE_DATA_ROOT = tempRoot;
process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_DATA_KEY = 'unit-update-api-data-key-stable-value-32';

const currentBranch = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
  cwd: path.join(__dirname, '..'),
  encoding: 'utf8',
}).trim() || 'main';
fs.writeFileSync(process.env.REDACTWALL_UPDATE_CONFIG_PATH, JSON.stringify({
  remoteName: 'origin',
  branch: currentBranch,
  installMode: 'npm-ci-omit-dev',
  restartCommand: '',
  restartAfterUpdate: false,
}));

const app = require('../server/app');
const db = require('../server/db');
const updater = require('../server/updater');
const { listen } = require('./support/listen');

test.after(() => {
  try { require('../server/db')._db.close(); } catch {}
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

async function login(base) {
  const loginRes = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'admin', password: 'unit-pass' }),
  });
  assert.strictEqual(loginRes.status, 200);
  const cookie = String(loginRes.headers.get('set-cookie') || '').split(';')[0];
  assert.match(cookie, /^redactwall_session=/);
  const csrfRes = await fetch(`${base}/api/csrf`, { headers: { cookie } });
  assert.strictEqual(csrfRes.status, 200);
  const csrf = await csrfRes.json();
  return { cookie, csrfToken: csrf.csrfToken };
}

test('admin update config endpoint saves settings and records audit metadata', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  const unauth = await fetch(`${base}/api/update/status`);
  assert.strictEqual(unauth.status, 401);

  const { cookie, csrfToken } = await login(base);
  const statusRes = await fetch(`${base}/api/update/status`, { headers: { cookie } });
  assert.strictEqual(statusRes.status, 200);
  const status = await statusRes.json();
  assert.strictEqual(status.config.remoteName, 'origin');
  assert.strictEqual(status.safety.configuredBranch, true);

  const saveRes = await fetch(`${base}/api/update/config`, {
    method: 'PUT',
    headers: {
      cookie,
      'content-type': 'application/json',
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify({
      remoteName: 'origin',
      branch: currentBranch,
      installMode: 'skip',
      restartCommand: '',
      restartAfterUpdate: false,
    }),
  });
  assert.strictEqual(saveRes.status, 200);
  const saved = await saveRes.json();
  assert.strictEqual(saved.config.installMode, 'skip');
  assert.strictEqual(saved.safety.configuredBranch, true);
  assert.strictEqual(JSON.parse(fs.readFileSync(process.env.REDACTWALL_UPDATE_CONFIG_PATH, 'utf8')).installMode, 'skip');

  const auditRes = await fetch(`${base}/api/audit?limit=20`, { headers: { cookie } });
  assert.strictEqual(auditRes.status, 200);
  const audit = await auditRes.json();
  assert.ok(audit.entries.some((entry) => entry.action === 'APP_UPDATE_CONFIGURED'
    && /remote=origin/.test(entry.detail)
    && /install=skip/.test(entry.detail)));
});

test('update config audit failure leaves the exact prior file and no temporary artifact', async (t) => {
  const baseline = Buffer.from(JSON.stringify({
    remoteName: 'origin',
    branch: currentBranch,
    installMode: 'npm-ci-omit-dev',
    restartCommand: '',
    restartAfterUpdate: false,
  }, null, 2));
  fs.writeFileSync(process.env.REDACTWALL_UPDATE_CONFIG_PATH, baseline);
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const { cookie, csrfToken } = await login(base);
  const originalAppendAudit = db.appendAudit;
  db.appendAudit = () => { throw new Error('synthetic update audit outage'); };
  try {
    const response = await fetch(`${base}/api/update/config`, {
      method: 'PUT',
      headers: {
        cookie,
        'content-type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({
        remoteName: 'origin',
        branch: currentBranch,
        installMode: 'skip',
        restartCommand: '',
        restartAfterUpdate: false,
      }),
    });
    assert.strictEqual(response.status, 500);
    assert.deepStrictEqual(fs.readFileSync(process.env.REDACTWALL_UPDATE_CONFIG_PATH), baseline);
    assert.deepStrictEqual(
      fs.readdirSync(tempRoot).filter((name) => name.startsWith('update-settings.json.')),
      [],
    );
  } finally {
    db.appendAudit = originalAppendAudit;
  }
});

test('apply and restart audit failures preserve truthful ordering around irreversible effects', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const { cookie, csrfToken } = await login(base);
  const originalAppendAudit = db.appendAudit;
  const originalApplyUpdate = updater.applyUpdate;
  const originalScheduleRestart = updater.scheduleRestart;
  let applyCalls = 0;
  let restartCalls = 0;
  try {
    updater.applyUpdate = async () => {
      applyCalls += 1;
      return { ok: true, updated: true, restartScheduled: false, check: {} };
    };
    db.appendAudit = (event) => {
      if (event.action === 'APP_UPDATE_APPLIED') throw new Error('synthetic terminal audit outage');
      return originalAppendAudit(event);
    };
    const apply = await fetch(`${base}/api/update/apply`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': csrfToken },
      body: JSON.stringify({ confirmBackup: true }),
    });
    assert.strictEqual(apply.status, 500);
    assert.deepStrictEqual(await apply.json(), {
      error: 'update completed but audit confirmation failed; inspect update status before retry',
    });
    assert.strictEqual(applyCalls, 1);
    const updateActions = db.listAudit(100).map((entry) => entry.action);
    assert.ok(updateActions.includes('APP_UPDATE_STARTED'));
    assert.ok(updateActions.includes('APP_UPDATE_AUDIT_FAILED'));
    assert.ok(!updateActions.includes('APP_UPDATE_FAILED'), 'a completed update is never mislabeled as an update failure');

    updater.scheduleRestart = () => {
      restartCalls += 1;
      return { ok: true, scheduled: true };
    };
    db.appendAudit = (event) => {
      if (event.action === 'APP_UPDATE_RESTART_SCHEDULED') throw new Error('synthetic restart audit outage');
      return originalAppendAudit(event);
    };
    const restart = await fetch(`${base}/api/update/restart`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': csrfToken },
      body: '{}',
    });
    assert.strictEqual(restart.status, 500);
    assert.deepStrictEqual(await restart.json(), {
      error: 'restart could not be audited and was not scheduled',
    });
    assert.strictEqual(restartCalls, 0, 'restart side effect stays behind the durable audit boundary');
    assert.ok(db.listAudit(100).some((entry) => entry.action === 'APP_UPDATE_RESTART_FAILED'));
  } finally {
    db.appendAudit = originalAppendAudit;
    updater.applyUpdate = originalApplyUpdate;
    updater.scheduleRestart = originalScheduleRestart;
  }
});
