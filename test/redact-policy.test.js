'use strict';
/** Redact mode must not send semantic-only or mixed semantic content raw. */
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
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-redact-policy-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-redact-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(process.env.SENTINEL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'redact',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  storeRawForApproval: true,
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

async function gate(port, prompt) {
  return fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      prompt,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'api',
      channel: 'submit',
    }),
  });
}

test('redact mode tokenizes structured-only prompt findings', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const prompt = 'Please summarize member SSN ' + secret + ' for the secured case note.';
  const res = await gate(port, prompt);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'redact');
  assert.strictEqual(body.status, 'redacted');
  assert.strictEqual(body.mode, 'redact');
  assert.match(body.tokenizedPrompt, /\[\[US_SSN_1\]\]/);
  assert.ok(!JSON.stringify(body).includes(secret));
}));

test('redact mode holds mixed structured and semantic prompt findings', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const confidentialPhrase = 'our largest commercial relationship is about to walk';
  const prompt = 'Strictly confidential: ' + confidentialPhrase + '; draft retention options before the board hears. Member SSN ' + secret + '.';
  const res = await gate(port, prompt);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  const stored = db.getQuery(body.id);
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'pending');
  assert.strictEqual(body.mode, 'redact');
  assert.ok(body.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(body.categories.includes('CONFIDENTIAL_BUSINESS'));
  assert.strictEqual(body.tokenizedPrompt, undefined);
  assert.strictEqual(stored.redactedPrompt, '[REDACTED: CONFIDENTIAL_BUSINESS]');
  assert.ok(!JSON.stringify(body).includes(secret));
  assert.ok(!JSON.stringify(body).includes(prompt));
  assert.ok(!JSON.stringify(stored).includes(secret));
  assert.ok(!JSON.stringify(stored).includes(confidentialPhrase));
}));

test('redact mode accepts whole-chunk client redaction for semantic evidence', async () => withServer(async (port) => {
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      prompt: '[REDACTED: CONFIDENTIAL_BUSINESS]',
      user: 'mcp-agent',
      destination: 'sharepoint.fetchDoc',
      source: 'mcp_guard',
      channel: 'mcp_doc',
      clientOutcome: 'redacted_sent',
      clientPreRedacted: true,
      clientFindings: [],
      clientCategories: ['CONFIDENTIAL_BUSINESS'],
      clientEntityCounts: { CONFIDENTIAL_BUSINESS: 1 },
      clientRiskScore: 15,
      clientMaxSeverity: 3,
      clientMaxSeverityLabel: 'high',
    }),
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'redact');
  assert.strictEqual(body.status, 'redacted');
  assert.deepStrictEqual(body.categories, ['CONFIDENTIAL_BUSINESS']);
  assert.strictEqual(body.tokenizedPrompt, '[REDACTED: CONFIDENTIAL_BUSINESS]');
}));

test('redact mode accepts endpoint redacted companion evidence without a vault', async () => withServer(async (port) => {
  const prompt = '[file:loan.txt] [[US_SSN_1]]';
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      prompt,
      user: 'endpoint-user',
      destination: 'desktop-ai-app',
      source: 'endpoint_agent',
      channel: 'file_upload',
      clientOutcome: 'redacted_available',
      clientPreRedacted: true,
      clientFindings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '**** 9043' }],
      clientCategories: [],
      clientEntityCounts: { US_SSN: 1 },
      clientRiskScore: 30,
      clientMaxSeverity: 4,
      clientMaxSeverityLabel: 'critical',
      note: 'endpoint agent inspected loan.txt locally; redacted companion .promptsentinel-redacted/loan.promptsentinel-redacted.txt',
    }),
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  const stored = db.getQuery(body.id);
  assert.strictEqual(body.decision, 'redact');
  assert.strictEqual(body.status, 'redacted');
  assert.strictEqual(body.tokenizedPrompt, prompt);
  assert.strictEqual(stored.redactedPrompt, prompt);
  assert.strictEqual(stored._tokenVault, undefined);
}));

test('scan-response stores category hits as whole-chunk redacted previews', async () => withServer(async (port) => {
  const confidentialPhrase = 'our largest commercial relationship is about to walk';
  const text = 'Strictly confidential: ' + confidentialPhrase + '; draft retention options before the board hears.';
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/scan-response`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      text,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'api',
    }),
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.leaked, true);
  assert.deepStrictEqual(body.categories, ['CONFIDENTIAL_BUSINESS']);
  assert.strictEqual(body.redacted, '[REDACTED: CONFIDENTIAL_BUSINESS]');
  const stored = db.listQueries({ status: 'response_flagged', limit: 1 })[0];
  assert.ok(stored);
  assert.strictEqual(stored.redactedPrompt, '[AI response] [REDACTED: CONFIDENTIAL_BUSINESS]');
  assert.ok(!JSON.stringify(body).includes(confidentialPhrase));
  assert.ok(!JSON.stringify(stored).includes(confidentialPhrase));
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
