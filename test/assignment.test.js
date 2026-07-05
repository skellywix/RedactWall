'use strict';
/** Inline reassignment of held decisions: admin-only, audited, metadata only. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.APPROVER_USER = 'approver';
process.env.APPROVER_PASSWORD = 'approver-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-assignment-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-assignment-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
  rawRetentionDays: 30,
}, null, 2));

const app = require('../server/app');
const { listen } = require('./support/listen');
const db = require('../server/db');

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
  }
}

async function jsonFetch(port, apiPath, { method = 'POST', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function login(port, user, password) {
  const res = await jsonFetch(port, '/api/login', { body: { user, password } });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } });
  assert.strictEqual(csrfRes.status, 200);
  const csrf = await csrfRes.json();
  return { cookie, csrfToken: csrf.csrfToken };
}

async function createHeldPrompt(port) {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Please review member SSN 524-71-9043 before release.',
      user: 'teller@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'pending');
  return body;
}

function assign(port, session, id, body) {
  return jsonFetch(port, `/api/queries/${id}/assign`, {
    headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken },
    body,
  });
}

test('admin reassigns a held item inline; approver is refused; audit records metadata only', async () => withServer(async (port) => {
  const held = await createHeldPrompt(port);
  const admin = await login(port, 'admin', 'unit-pass');
  const approver = await login(port, 'approver', 'approver-pass');

  const forbidden = await assign(port, approver, held.id, { assignedUser: 'approver' });
  assert.strictEqual(forbidden.status, 403);

  const res = await assign(port, admin, held.id, {
    assignedUser: 'Approver',
    assignedGroup: 'compliance',
    assignedRole: 'approver',
  });
  assert.strictEqual(res.status, 200);
  const updated = await res.json();
  assert.strictEqual(updated.assignedUser, 'Approver');
  assert.strictEqual(updated.assignedGroup, 'compliance');
  assert.strictEqual(updated.assignedRole, 'approver');
  assert.strictEqual(updated.rawPrompt, undefined);

  const entry = db.listAudit(50).find((a) => a.action === 'APPROVAL_REASSIGNED' && a.queryId === held.id);
  assert.ok(entry, 'reassignment is audited');
  assert.strictEqual(entry.actor, 'admin');
  assert.ok(!entry.detail.includes('524-71-9043'));

  // Reassignment makes the item decidable by the named approver.
  const approved = await jsonFetch(port, `/api/queries/${held.id}/approve`, {
    headers: { cookie: approver.cookie, 'x-csrf-token': approver.csrfToken },
    body: { note: 'assigned to me inline', password: 'approver-pass' },
  });
  assert.strictEqual(approved.status, 200);
  assert.strictEqual(db.getQuery(held.id).status, 'approved');
  assert.strictEqual(db.verifyAuditChain().ok, true);
}));

test('assignment validates fields, clears with empty strings, and refuses decided items', async () => withServer(async (port) => {
  const held = await createHeldPrompt(port);
  const admin = await login(port, 'admin', 'unit-pass');

  const badRole = await assign(port, admin, held.id, { assignedRole: 'superuser' });
  assert.strictEqual(badRole.status, 400);
  assert.deepStrictEqual((await badRole.json()).fields, ['assignedRole']);

  const empty = await assign(port, admin, held.id, {});
  assert.strictEqual(empty.status, 400);

  const missing = await assign(port, admin, 'q_does_not_exist', { assignedUser: 'x' });
  assert.strictEqual(missing.status, 404);

  const partial = await assign(port, admin, held.id, { assignedUser: ' reviewer@example.test ' });
  assert.strictEqual(partial.status, 200);
  const afterPartial = db.getQuery(held.id);
  assert.strictEqual(afterPartial.assignedUser, 'reviewer@example.test');
  assert.ok(afterPartial.assignedGroup, 'omitted fields keep their routed value');

  const cleared = await assign(port, admin, held.id, { assignedUser: '', assignedGroup: '', assignedRole: '' });
  assert.strictEqual(cleared.status, 200);
  const afterClear = db.getQuery(held.id);
  assert.strictEqual(afterClear.assignedUser, null);
  assert.strictEqual(afterClear.assignedGroup, null);
  assert.strictEqual(afterClear.assignedRole, null);

  const deny = await jsonFetch(port, `/api/queries/${held.id}/deny`, {
    headers: { cookie: admin.cookie, 'x-csrf-token': admin.csrfToken },
    body: { note: 'deny before reassign attempt' },
  });
  assert.strictEqual(deny.status, 200);
  const decided = await assign(port, admin, held.id, { assignedUser: 'late@example.test' });
  assert.strictEqual(decided.status, 409);
  assert.strictEqual(db.verifyAuditChain().ok, true);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
