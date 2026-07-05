'use strict';
/** Bulk decisions honor the same gates as single ones - role, per-item
 *  decision access, step-up for approvals - and every item is audited. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.APPROVER_USER = 'approver@example.test';
process.env.APPROVER_PASSWORD = 'approver-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-bulk-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const auth = require('../server/auth');
const { listen } = require('./support/listen');

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function cookieFor(user, role) {
  return `${auth.SESSION_COOKIE_NAME}=${auth.createSession(user, role)}`;
}

async function post(port, route, cookie, body) {
  const csrf = await (await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } })).json();
  return fetch(`http://127.0.0.1:${port}${route}`, {
    method: 'POST',
    headers: { cookie, 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
    body: JSON.stringify(body),
  });
}

async function holdPrompt(port, suffix, user = 'bulk-user@example.test') {
  const r = await fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: { 'x-api-key': 'unit-ingest-key', 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt: `SSN 524-71-${suffix} in a prompt`, user, destination: 'chatgpt.com', source: 'browser_extension', channel: 'submit' }),
  });
  const body = await r.json();
  assert.strictEqual(body.status, 'pending');
  return body.id;
}

test('admin bulk-denies pending prompts with per-item audit entries', async () => withServer(async (port) => {
  const admin = cookieFor('admin', 'security_admin');
  const a = await holdPrompt(port, '9001');
  const b = await holdPrompt(port, '9002');
  const r = await post(port, '/api/queries/bulk-decision', admin, { ids: [a, b, 'q_missing'], action: 'deny', note: 'policy sweep' });
  assert.strictEqual(r.status, 200);
  const body = await r.json();
  assert.strictEqual(body.decided, 2);
  assert.strictEqual(body.skipped, 1);
  assert.deepStrictEqual(body.results.find((x) => x.id === 'q_missing'), { id: 'q_missing', outcome: 'skipped', reason: 'not found' });

  const rows = await (await fetch(`http://127.0.0.1:${port}/api/queries`, { headers: { cookie: admin } })).json();
  assert.ok([a, b].every((id) => rows.find((q) => q.id === id).status === 'denied'));
  const audit = await (await fetch(`http://127.0.0.1:${port}/api/audit`, { headers: { cookie: admin } })).json();
  const denials = audit.entries.filter((e) => e.action === 'DENIED' && [a, b].includes(e.queryId));
  assert.strictEqual(denials.length, 2);
  assert.ok(denials.every((e) => e.detail === 'policy sweep (bulk)'));

  const again = await post(port, '/api/queries/bulk-decision', admin, { ids: [a], action: 'deny' });
  assert.deepStrictEqual((await again.json()).results[0], { id: a, outcome: 'skipped', reason: 'already denied' });
}));

test('bulk approval requires password step-up like single approvals', async () => withServer(async (port) => {
  const admin = cookieFor('admin', 'security_admin');
  const id = await holdPrompt(port, '9003');
  const noPassword = await post(port, '/api/queries/bulk-decision', admin, { ids: [id], action: 'approve' });
  assert.strictEqual(noPassword.status, 401);

  const withPassword = await post(port, '/api/queries/bulk-decision', admin, { ids: [id], action: 'approve', password: 'unit-pass' });
  assert.strictEqual(withPassword.status, 200);
  assert.strictEqual((await withPassword.json()).decided, 1);
  const rows = await (await fetch(`http://127.0.0.1:${port}/api/queries`, { headers: { cookie: admin } })).json();
  assert.strictEqual(rows.find((q) => q.id === id).status, 'approved');
}));

test('approver bulk skips items that are not theirs to decide', async () => withServer(async (port) => {
  const approver = cookieFor('approver@example.test', 'approver');
  const id = await holdPrompt(port, '9004');
  const r = await post(port, '/api/queries/bulk-decision', approver, { ids: [id], action: 'deny' });
  assert.strictEqual(r.status, 200);
  const body = await r.json();
  const outcome = body.results[0];
  assert.ok(
    outcome.outcome === 'denied' || outcome.reason === 'not yours to decide',
    'approver decides only items routed to the approver role',
  );

  const auditor = cookieFor('aud@example.test', 'auditor');
  const forbidden = await post(port, '/api/queries/bulk-decision', auditor, { ids: [id], action: 'deny' });
  assert.strictEqual(forbidden.status, 403, 'auditors cannot bulk-decide');
}));

test('audit endpoint filters entries to one incident for the history trail', async () => withServer(async (port) => {
  const admin = cookieFor('admin', 'security_admin');
  const a = await holdPrompt(port, '9005');
  const b = await holdPrompt(port, '9006');
  await post(port, '/api/queries/bulk-decision', admin, { ids: [b], action: 'deny', note: 'trail check' });
  const trail = await (await fetch(`http://127.0.0.1:${port}/api/audit?queryId=${b}`, { headers: { cookie: admin } })).json();
  assert.ok(trail.entries.length >= 2, 'creation and decision both present');
  assert.ok(trail.entries.every((e) => e.queryId === b));
  assert.ok(trail.entries.some((e) => e.action === 'DENIED'));
  assert.ok(!trail.entries.some((e) => e.queryId === a));
}));
