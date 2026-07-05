'use strict';
/** Four fixed roles: admin owns, approver decides, operator maintains, auditor exports. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.APPROVER_USER = 'approver@example.test';
process.env.APPROVER_PASSWORD = 'approver-pass';
process.env.AUDITOR_USER = 'auditor@example.test';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.OPERATOR_USER = 'operator@example.test';
process.env.OPERATOR_PASSWORD = 'operator-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-roles-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const auth = require('../server/auth');
const { listen } = require('./support/listen');

function cookieFor(user, role) {
  return `${auth.SESSION_COOKIE_NAME}=${auth.createSession(user, role)}`;
}

const SESSIONS = {
  admin: cookieFor('admin', 'security_admin'),
  approver: cookieFor('approver@example.test', 'approver'),
  operator: cookieFor('operator@example.test', 'operator'),
  auditor: cookieFor('auditor@example.test', 'auditor'),
};

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function get(port, route, who) {
  return fetch(`http://127.0.0.1:${port}${route}`, { headers: { cookie: SESSIONS[who] } });
}

async function post(port, route, who, body = {}) {
  const session = SESSIONS[who];
  const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie: session } });
  const { csrfToken } = await csrfRes.json();
  return fetch(`http://127.0.0.1:${port}${route}`, {
    method: 'POST',
    headers: { cookie: session, 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
    body: JSON.stringify(body),
  });
}

test('all four local role accounts authenticate with their role', () => {
  assert.strictEqual(auth.authenticate('operator@example.test', 'operator-pass').role, 'operator');
  assert.strictEqual(auth.authenticate('auditor@example.test', 'auditor-pass').role, 'auditor');
  assert.strictEqual(auth.authenticate('approver@example.test', 'approver-pass').role, 'approver');
  assert.strictEqual(auth.OPERATOR_ENABLED, true);
});

test('every role can view the console; power routes are gated by job', async () => withServer(async (port) => {
  for (const who of ['admin', 'approver', 'operator', 'auditor']) {
    assert.strictEqual((await get(port, '/api/queries', who)).status, 200, `${who} views queries`);
    assert.strictEqual((await get(port, '/api/audit', who)).status, 200, `${who} views audit`);
  }
}));

test('auditor exports evidence but changes nothing', async () => withServer(async (port) => {
  assert.strictEqual((await get(port, '/api/export/evidence', 'auditor')).status, 200);
  assert.strictEqual((await get(port, '/api/security/package', 'auditor')).status, 200);
  assert.strictEqual((await get(port, '/api/integrations/siem/package', 'auditor')).status, 200);
  assert.strictEqual((await post(port, '/api/update/check', 'auditor')).status, 403);
  assert.strictEqual((await post(port, '/api/posture/actions', 'auditor', { id: 'x', status: 'resolved' })).status, 403);
}));

test('operator maintains the fleet but cannot export evidence or touch policy', async () => withServer(async (port) => {
  assert.strictEqual((await get(port, '/api/update/status', 'operator')).status, 200);
  assert.strictEqual((await get(port, '/api/subscriptions/deliveries', 'operator')).status, 200);
  const posture = await post(port, '/api/posture/actions', 'operator', { id: 'unit_action', status: 'resolved' });
  assert.ok([200, 400].includes(posture.status), 'operator reaches the posture action route');
  assert.notStrictEqual(posture.status, 403);
  assert.strictEqual((await get(port, '/api/export/evidence', 'operator')).status, 403);
  assert.strictEqual((await get(port, '/api/security/package', 'operator')).status, 403);
}));

test('approver decides but neither exports nor operates', async () => withServer(async (port) => {
  assert.strictEqual((await get(port, '/api/export/evidence', 'approver')).status, 403);
  assert.strictEqual((await get(port, '/api/update/status', 'approver')).status, 403);
  assert.strictEqual((await post(port, '/api/update/check', 'approver')).status, 403);
}));

test('security_admin retains every capability', async () => withServer(async (port) => {
  assert.strictEqual((await get(port, '/api/export/evidence', 'admin')).status, 200);
  assert.strictEqual((await get(port, '/api/update/status', 'admin')).status, 200);
  assert.strictEqual((await get(port, '/api/subscriptions', 'admin')).status, 200);
}));

test('deploy downloads serve audited sensor packages to operators, not approvers', async () => withServer(async (port) => {
  const list = await get(port, '/api/deploy/artifacts', 'operator');
  assert.strictEqual(list.status, 200, 'artifacts list: ' + (list.status === 200 ? 'ok' : await list.text()));
  const { artifacts, version } = await list.json();
  assert.ok(typeof version === 'string' && version.length > 0);
  for (const id of ['extension-chrome', 'extension-edge', 'extension-firefox', 'endpoint-agent', 'mcp-guard']) {
    const artifact = artifacts.find((a) => a.id === id);
    assert.ok(artifact, `${id} listed`);
    assert.ok(artifact.fileName.endsWith('.zip'), `${id} names its file`);
    assert.strictEqual(artifact.fileType, 'application/zip');
    assert.ok(Number.isFinite(artifact.sizeBytes) && artifact.sizeBytes > 0, `${id} has a size`);
    assert.match(artifact.sha256, /^[0-9a-f]{64}$/, `${id} has a checksum`);
    assert.ok(artifact.guide.startsWith('docs/'), `${id} points at its guide`);
    assert.ok(artifact.requires && artifact.install, `${id} states requirements and rollout path`);
  }

  const download = await get(port, '/api/deploy/download/mcp-guard', 'operator');
  assert.strictEqual(download.status, 200);
  const body = Buffer.from(await download.arrayBuffer());
  assert.strictEqual(body.slice(0, 2).toString(), 'PK', 'download is a real zip');

  const after = await (await get(port, '/api/deploy/artifacts', 'admin')).json();
  const entry = after.history.find((h) => h.detail && h.detail.includes('mcp-guard'));
  assert.ok(entry, 'download lands in the audited history');
  assert.strictEqual(entry.actor, 'operator@example.test');

  assert.strictEqual((await get(port, '/api/deploy/download/extension-chrome', 'approver')).status, 403);
  assert.strictEqual((await get(port, '/api/deploy/download/nope', 'admin')).status, 404);
}));
