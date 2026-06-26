'use strict';
/** API request validation: reject bad bodies without leaking submitted values. */
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
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-validation-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server');
const policyPath = path.join(__dirname, '..', 'config', 'policy.json');

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

async function jsonFetch(port, apiPath, { method = 'POST', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function login(port) {
  const res = await jsonFetch(port, '/api/login', {
    body: { user: 'admin', password: 'unit-pass' },
  });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  assert.ok(cookie.includes('sentinel_session='));
  const csrfRes = await fetch(`http://127.0.0.1:${port}/api/csrf`, {
    headers: { cookie },
  });
  assert.strictEqual(csrfRes.status, 200);
  const csrf = await csrfRes.json();
  return { cookie, csrfToken: csrf.csrfToken };
}

test('gate rejects invalid client analysis without echoing prompt values', async () => withServer(async (port) => {
  const sensitiveValue = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Please review this member SSN ' + sensitiveValue,
      clientOutcome: 'teleport_to_model',
      clientFindings: [{ type: 'US_SSN', score: 'high', masked: sensitiveValue }],
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.strictEqual(body.error, 'invalid request body');
  assert.ok(body.fields.includes('clientFindings.0.score'));
  assert.ok(body.fields.includes('clientOutcome'));
  assert.ok(!JSON.stringify(body).includes(sensitiveValue));
}));

test('valid gate payload from sensors still evaluates normally', async () => withServer(async (port) => {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Draft a generic branch lobby announcement.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
      clientOutcome: 'allowed',
      clientFindings: [],
      clientCategories: [],
      clientEntityCounts: {},
      clientRiskScore: 0,
      clientMaxSeverity: 0,
      clientMaxSeverityLabel: 'none',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'allow');
  assert.strictEqual(body.riskScore, 0);
}));

test('scan-file rejects invalid base64 without echoing file content', async () => withServer(async (port) => {
  const secretFilePayload = 'loan file SSN 524-71-9043';
  const res = await jsonFetch(port, '/api/v1/scan-file', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      filename: 'member-loan.pdf',
      contentBase64: secretFilePayload,
      destination: 'desktop-ai-app',
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body.fields, ['contentBase64']);
  assert.ok(!JSON.stringify(body).includes(secretFilePayload));
}));

test('malformed json returns sanitized json error', async () => withServer(async (port) => {
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: '{"prompt":',
  });

  assert.strictEqual(res.status, 400);
  assert.match(res.headers.get('content-type') || '', /application\/json/);
  assert.deepStrictEqual(await res.json(), { error: 'invalid json' });
}));

test('admin policy rejects unknown settings without changing policy file', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  const res = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: {
      cookie,
      'x-csrf-token': csrfToken,
    },
    body: {
      enforcementMode: 'block',
      rawPromptRetention: 'store-everything',
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: ['rawPromptRetention'],
  });
  assert.strictEqual(fs.readFileSync(policyPath, 'utf8'), originalPolicy);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
});
