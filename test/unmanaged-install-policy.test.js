'use strict';
/** Unmanaged browser installs can be allowed, flagged, or blocked by policy. */
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
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-unmanaged-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-unmanaged-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

const basePolicy = {
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  governedDestinations: ['chatgpt.com'],
};
fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify(basePolicy, null, 2));

const app = require('../server/app');
const db = require('../server/db');
const policy = require('../server/policy');
const coverage = require('../server/coverage');
const posture = require('../server/posture');
const { policyUpdateSchema } = require('../server/validation');
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

function writePolicy(unmanagedInstalls) {
  fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({ ...basePolicy, unmanagedInstalls }, null, 2));
}

async function gate(port, user) {
  return fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': 'unit-ingest-key' },
    body: JSON.stringify({
      prompt: 'Summarize the quarterly town hall agenda.',
      user,
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    }),
  });
}

test('unmanagedInstalls policy option normalizes, validates, and defaults to allow', () => {
  assert.strictEqual(policy.DEFAULT_POLICY.unmanagedInstalls, 'allow');
  assert.strictEqual(policy.normalizeUnmanagedInstalls('BLOCK'), 'block');
  assert.strictEqual(policy.normalizeUnmanagedInstalls('bogus'), 'allow');
  assert.strictEqual(policy.normalizePolicy({}).unmanagedInstalls, 'allow');
  assert.ok(policyUpdateSchema.safeParse({ unmanagedInstalls: 'flag' }).success);
  assert.ok(!policyUpdateSchema.safeParse({ unmanagedInstalls: 'never' }).success);
  assert.strictEqual(policy.unmanagedInstallBlocked('Unattributed@Unmanaged', { unmanagedInstalls: 'block' }), true);
  assert.strictEqual(policy.unmanagedInstallBlocked('analyst@example.test', { unmanagedInstalls: 'block' }), false);
  assert.strictEqual(policy.unmanagedInstallBlocked('unattributed@unmanaged', { unmanagedInstalls: 'flag' }), false);
});

test('gate blocks unattributed sensors when unmanaged installs are blocked', async () => withServer(async (port) => {
  writePolicy('block');
  const res = await gate(port, 'unattributed@unmanaged');
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'destination_blocked');
  assert.match(body.reasons.join(' '), /Unmanaged browser install/);
  assert.ok(!JSON.stringify(body).includes('town hall'), 'refusal carries no prompt text');
  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.status, 'destination_blocked');
  assert.ok(!JSON.stringify(stored).includes('town hall'), 'evidence carries no prompt text');
}));

test('gate keeps attributed users and flag/allow modes unblocked', async () => withServer(async (port) => {
  writePolicy('block');
  const managed = await (await gate(port, 'analyst@example.test')).json();
  assert.notStrictEqual(managed.status, 'destination_blocked');

  writePolicy('flag');
  const flagged = await (await gate(port, 'unattributed@unmanaged')).json();
  assert.notStrictEqual(flagged.status, 'destination_blocked');
}));

test('coverage and posture surface the unattributed rate as a gap', () => {
  const rows = [
    { user: 'analyst@example.test', destination: 'chatgpt.com', source: 'browser_extension', status: 'allowed', createdAt: '2026-07-04T00:00:00.000Z' },
    { user: 'unattributed@unmanaged', destination: 'chatgpt.com', source: 'browser_extension', status: 'allowed', createdAt: '2026-07-04T00:00:01.000Z' },
  ];
  const report = coverage.summarize(rows, { ...basePolicy, unmanagedInstalls: 'allow' });
  assert.strictEqual(report.totals.unattributedEvents, 1);
  assert.strictEqual(report.totals.unattributedRate, 0.5);
  assert.strictEqual(report.totals.unmanagedInstallMode, 'allow');
  const lane = report.posture.find((item) => item.id === 'identity_attribution');
  assert.strictEqual(lane.state, 'attention');
  assert.match(lane.detail, /1 unattributed events \/ policy allow/);
  assert.ok(!JSON.stringify(report.posture).includes('town hall'));

  const clean = coverage.summarize([rows[0]], { ...basePolicy, unmanagedInstalls: 'block' });
  assert.strictEqual(clean.posture.find((item) => item.id === 'identity_attribution').state, 'covered');

  const summary = posture.summarize({ rows, policy: basePolicy, coverageReport: report, now: new Date('2026-07-04T01:00:00Z') });
  const objective = summary.objectives.find((item) => item.id === 'guarantee_user_attribution');
  assert.ok(objective, 'posture exposes the attribution objective');
  assert.ok(objective.score < 100, 'unattributed events degrade the score');
  assert.match(objective.detail, /1 unattributed events/);
});
