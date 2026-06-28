'use strict';
/** Response scanning policy controls flag, redact, or block AI outputs. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-response-policy-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-response-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

const basePolicy = {
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
};
fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({ ...basePolicy, responseScanMode: 'flag' }, null, 2));

const app = require('../server/app');
const db = require('../server/db');
const { listen } = require('./support/listen');

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

function writePolicy(responseScanMode) {
  fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({ ...basePolicy, responseScanMode }, null, 2));
}

async function scanResponse(port, text = 'The answer includes member SSN 524-71-9043 in the draft.') {
  return fetch(`http://127.0.0.1:${port}/api/v1/scan-response`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      text,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'mcp_guard',
    }),
  });
}

test('response scan defaults to flag-only evidence for leaked output', async () => withServer(async (port) => {
  writePolicy('flag');
  const res = await scanResponse(port);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.leaked, true);
  assert.strictEqual(body.decision, 'flag');
  assert.strictEqual(body.status, 'response_flagged');
  assert.strictEqual(body.blocked, false);
  assert.ok(!JSON.stringify(body).includes('524-71-9043'));
  const stored = db.getQuery(db.listQueries({ status: 'response_flagged', limit: 1 })[0].id);
  assert.strictEqual(stored.status, 'response_flagged');
  assert.ok(stored.assignedGroup, 'flagged responses remain routeable workflow evidence');
  assert.ok(db.listAudit(20).some((entry) => entry.action === 'RESPONSE_FLAGGED' && entry.queryId === stored.id));
}));

test('response scan can redact leaked output before display', async () => withServer(async (port) => {
  writePolicy('redact');
  const res = await scanResponse(port);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.leaked, true);
  assert.strictEqual(body.decision, 'redact');
  assert.strictEqual(body.status, 'response_redacted');
  assert.strictEqual(body.blocked, false);
  assert.ok(body.redacted);
  assert.ok(!JSON.stringify(body).includes('524-71-9043'));
  const stored = db.getQuery(db.listQueries({ status: 'response_redacted', limit: 1 })[0].id);
  assert.strictEqual(stored.status, 'response_redacted');
  assert.strictEqual(stored.assignedGroup, undefined);
  assert.ok(!JSON.stringify(stored).includes('524-71-9043'));
  assert.ok(db.listAudit(20).some((entry) => entry.action === 'RESPONSE_REDACTED' && entry.queryId === stored.id));
}));

test('response scan can block leaked output display as a routeable incident', async () => withServer(async (port) => {
  writePolicy('block');
  const res = await scanResponse(port);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.leaked, true);
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'response_blocked');
  assert.strictEqual(body.blocked, true);
  assert.ok(!JSON.stringify(body).includes('524-71-9043'));
  const stored = db.getQuery(db.listQueries({ status: 'response_blocked', limit: 1 })[0].id);
  assert.strictEqual(stored.status, 'response_blocked');
  assert.ok(stored.assignedGroup, 'blocked responses enter the reviewer workflow');
  assert.ok(db.listAudit(20).some((entry) => entry.action === 'RESPONSE_BLOCKED' && entry.queryId === stored.id));
}));

test('safe response output stays allowed and does not create incident evidence', async () => withServer(async (port) => {
  const before = db.stats().total;
  writePolicy('block');
  const res = await scanResponse(port, 'Here is a generic explanation of password rotation policy.');

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.leaked, false);
  assert.strictEqual(body.decision, 'allow');
  assert.strictEqual(body.status, 'allowed');
  assert.strictEqual(body.blocked, false);
  assert.strictEqual(db.stats().total, before);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
