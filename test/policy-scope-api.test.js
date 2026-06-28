'use strict';
/** Gate policy scopes can use SCIM-provisioned group membership without prompt leakage. */
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
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-policy-scope-api-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-policy-scope-api-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'warn',
  blockMinSeverity: 4,
  blockRiskScore: 90,
  alwaysBlock: ['US_SSN'],
  storeRawForApproval: false,
  policyScopes: [{
    id: 'legal_contract_review',
    groups: ['PromptWall Legal'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 10,
  }],
}, null, 2));

const app = require('../server/app');
const db = require('../server/db');

function listen(appUnderTest) {
  return new Promise((resolve, reject) => {
    const server = appUnderTest.listen(0, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

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

async function gate(port, body) {
  return fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.INGEST_API_KEY,
    },
    body: JSON.stringify({
      prompt: '[REDACTED:LEGAL_CONTRACT]',
      user: 'counsel@example.test',
      destination: 'https://claude.ai/chat/unit',
      source: 'browser_extension',
      channel: 'submit',
      clientPreRedacted: true,
      clientCategories: ['LEGAL_CONTRACT'],
      clientFindings: [],
      clientEntityCounts: { LEGAL_CONTRACT: 1 },
      clientRiskScore: 20,
      clientMaxSeverity: 2,
      clientMaxSeverityLabel: 'medium',
      ...body,
    }),
  });
}

function provisionLegalUser() {
  const user = db.saveScimUser({
    userName: 'counsel@example.test',
    displayName: 'Counsel User',
    active: true,
  });
  db.saveScimGroup({
    displayName: 'PromptWall Legal',
    members: [{ value: user.id, display: user.userName }],
  });
}

test('gate applies scoped policy from SCIM group membership', async () => withServer(async (port) => {
  provisionLegalUser();
  const res = await gate(port);
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'pending');

  const stored = db.getQuery(body.id);
  assert.deepStrictEqual(stored.policyScopeIds, ['legal_contract_review']);
  assert.strictEqual(stored.policyExceptionId, undefined);
  assert.ok(stored.reasons.some((reason) => reason.includes('Policy scope matched: legal_contract_review')));
  assert.ok(!JSON.stringify(stored).includes('524-71-9043'));
}));

test('gate records a time-bound exception id for matched non-hard-stop content', async () => withServer(async (port) => {
  provisionLegalUser();
  const current = JSON.parse(fs.readFileSync(process.env.SENTINEL_POLICY_PATH, 'utf8'));
  fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
    ...current,
    policyExceptions: [{
      id: 'legal_vendor_24h',
      users: ['counsel@example.test'],
      destinations: ['claude.ai'],
      categories: ['LEGAL_CONTRACT'],
      expiresAt: '2030-01-01T00:00:00.000Z',
    }],
  }, null, 2));

  const res = await gate(port);
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'allow');

  const stored = db.getQuery(body.id);
  assert.deepStrictEqual(stored.policyScopeIds, ['legal_contract_review']);
  assert.strictEqual(stored.policyExceptionId, 'legal_vendor_24h');
  assert.deepStrictEqual(stored.reasons, ['Time-bound exception matched: legal_vendor_24h']);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
