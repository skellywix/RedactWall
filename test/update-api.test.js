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
