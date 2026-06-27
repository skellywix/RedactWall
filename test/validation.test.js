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

const app = require('../server/app');
const db = require('../server/db');
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

async function waitFor(fn, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail('timed out waiting for condition');
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
      sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'allow');
  assert.strictEqual(body.riskScore, 0);
  assert.deepStrictEqual(db.getQuery(body.id).sensor, { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' });
}));

test('gate preserves pre-redacted endpoint file findings without raw file text', async () => withServer(async (port) => {
  const rawSecret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[file:loan.txt] [US_SSN]',
      user: 'endpoint-user',
      destination: 'desktop-ai-app',
      source: 'endpoint_agent',
      channel: 'file_upload',
      clientPreRedacted: true,
      clientFindings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '**** 9043' }],
      clientCategories: [],
      clientEntityCounts: { US_SSN: 1 },
      clientRiskScore: 30,
      clientMaxSeverity: 4,
      clientMaxSeverityLabel: 'critical',
      note: 'endpoint agent inspected loan.txt locally',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  const stored = db.getQuery(body.id);
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'pending');
  assert.ok(body.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(stored.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(!JSON.stringify(body).includes(rawSecret));
  assert.ok(!JSON.stringify(stored).includes(rawSecret));
}));

test('gate records endpoint redacted companion availability as redacted without a vault', async () => withServer(async (port) => {
  const rawSecret = '524-71-9043';
  const prompt = '[file:loan.txt] [[US_SSN_1]]';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
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
      note: 'endpoint agent wrote a redacted companion',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  const stored = db.getQuery(body.id);
  assert.strictEqual(body.decision, 'redact');
  assert.strictEqual(body.status, 'redacted');
  assert.strictEqual(body.tokenizedPrompt, prompt);
  assert.strictEqual(stored.status, 'redacted');
  assert.strictEqual(stored.tokenizedPrompt, prompt);
  assert.strictEqual(stored._tokenVault, undefined);
  assert.strictEqual(stored._rawPrompt, undefined);
  assert.ok(!JSON.stringify(body).includes(rawSecret));
  assert.ok(!JSON.stringify(stored).includes(rawSecret));
}));

test('sensor metadata validation rejects oversized values without echoing them', async () => withServer(async (port) => {
  const tooLong = 'x'.repeat(600);
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Draft a generic branch announcement.',
      source: 'browser_extension',
      sensor: { name: 'browser_extension', version: tooLong, platform: 'chrome_mv3' },
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.ok(body.fields.includes('sensor.version'));
  assert.ok(!JSON.stringify(body).includes(tooLong));
}));

test('sensor metadata validation rejects unknown fields without echoing them', async () => withServer(async (port) => {
  const secret = 'unit-ingest-key';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Draft a generic branch announcement.',
      source: 'browser_extension',
      sensor: { name: 'browser_extension', version: '0.3.0', token: secret },
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: ['sensor.token'],
  });
  assert.ok(!JSON.stringify(body).includes(secret));
}));

test('mixed sensor versions emit sanitized SIEM version-gap alert', async () => withServer(async (port) => {
  const originalFetch = global.fetch;
  const originalWebhook = process.env.SIEM_WEBHOOK_URL;
  const sent = [];
  process.env.SIEM_WEBHOOK_URL = 'https://siem.example.test/hook';
  global.fetch = async (url, opts) => {
    if (String(url) === process.env.SIEM_WEBHOOK_URL) {
      sent.push(JSON.parse(opts.body));
      return { ok: true, status: 202, json: async () => ({ ok: true }) };
    }
    return originalFetch(url, opts);
  };

  try {
    for (const version of ['0.3.0', '0.2.9']) {
      const res = await jsonFetch(port, '/api/v1/gate', {
        headers: { 'x-api-key': 'unit-ingest-key' },
        body: {
          prompt: 'Draft a generic branch lobby update with no member details.',
          user: 'pilot@example.test',
          destination: 'chatgpt.com',
          source: 'browser_extension',
          channel: 'submit',
          clientOutcome: 'allowed',
          note: 'ps_ingest_should_not_leave',
          sensor: {
            name: 'browser_extension',
            version,
            platform: 'chrome_mv3',
          },
        },
      });
      assert.strictEqual(res.status, 200);
    }

    await waitFor(() => sent.some((alert) => alert.action === 'SENSOR_VERSION_GAP'));
    const gap = sent.find((alert) => alert.action === 'SENSOR_VERSION_GAP');
    const wire = JSON.stringify(gap);
    assert.strictEqual(gap.source, 'browser_extension');
    assert.strictEqual(gap.sensorVersionGap.versionHealth, 'mixed');
    assert.ok(gap.sensorVersionGap.versions.some((v) => v.version === '0.3.0'));
    assert.ok(gap.sensorVersionGap.versions.some((v) => v.version === '0.2.9'));
    assert.ok(!wire.includes('ps_ingest_should_not_leave'));
    assert.ok(!wire.includes('member details'));
  } finally {
    global.fetch = originalFetch;
    if (originalWebhook === undefined) delete process.env.SIEM_WEBHOOK_URL;
    else process.env.SIEM_WEBHOOK_URL = originalWebhook;
  }
}));

test('api-only events do not emit sensor version-gap alerts', async () => withServer(async (port) => {
  const originalFetch = global.fetch;
  const originalWebhook = process.env.SIEM_WEBHOOK_URL;
  const sent = [];
  process.env.SIEM_WEBHOOK_URL = 'https://siem.example.test/hook';
  global.fetch = async (url, opts) => {
    if (String(url) === process.env.SIEM_WEBHOOK_URL) {
      sent.push(JSON.parse(opts.body));
      return { ok: true, status: 202, json: async () => ({ ok: true }) };
    }
    return originalFetch(url, opts);
  };

  try {
    const res = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Draft a generic branch lobby update.',
        user: 'api@example.test',
        destination: 'chatgpt.com',
        source: 'api',
        channel: 'submit',
      },
    });
    assert.strictEqual(res.status, 200);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.ok(!sent.some((alert) => alert.action === 'SENSOR_VERSION_GAP'));
  } finally {
    global.fetch = originalFetch;
    if (originalWebhook === undefined) delete process.env.SIEM_WEBHOOK_URL;
    else process.env.SIEM_WEBHOOK_URL = originalWebhook;
  }
}));

test('client redaction evidence rejects unknown detector ids', async () => withServer(async (port) => {
  const tokenized = 'Member data was replaced with [[NOT_REAL_DETECTOR_1]].';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: tokenized,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
      clientOutcome: 'redacted_sent',
      clientPreRedacted: true,
      clientFindings: [{ type: 'NOT_REAL_DETECTOR', severity: 4, score: 0.99, masked: '****' }],
      clientCategories: ['CREDENTIALS'],
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: ['clientFindings.0.type'],
  });
  assert.ok(!JSON.stringify(body).includes(tokenized));
}));

test('gate accepts scan_unavailable as a blocked unscanned file outcome', async () => withServer(async (port) => {
  const fileContent = 'member file SSN 524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[file blocked unscanned] member-loan.txt',
      user: 'endpoint-user',
      destination: 'desktop-ai-app',
      source: 'endpoint_agent',
      channel: 'file_upload',
      clientOutcome: 'scan_unavailable',
      note: 'blocked locally: control plane scan unavailable',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'file_blocked_unscanned');
  assert.ok(!JSON.stringify(body).includes(fileContent));
}));

test('gate records browser paste warnings as audit-only sensor evidence', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: 'Pasted member SSN ' + secret + ' into the composer.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'paste',
      clientOutcome: 'paste_flagged',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'log');
  assert.strictEqual(body.status, 'paste_flagged');
  assert.ok(body.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(!JSON.stringify(body).includes(secret));

  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.status, 'paste_flagged');
  assert.strictEqual(stored.channel, 'paste');
  assert.strictEqual(stored._rawPrompt, undefined);
  assert.ok(!JSON.stringify(stored).includes(secret));
  assert.ok(db.listAudit(10).some((entry) => entry.action === 'PASTE_FLAGGED' && entry.queryId === body.id));
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

test('sensor policy endpoint publishes detector and scanner controls', async () => withServer(async (port) => {
  const res = await jsonFetch(port, '/api/v1/policy', {
    method: 'GET',
    headers: { 'x-api-key': 'unit-ingest-key' },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.ok(Array.isArray(body.alwaysBlock));
  assert.ok(Array.isArray(body.ignore));
  assert.ok(Array.isArray(body.disabledDetectors));
  assert.ok(Array.isArray(body.governedDestinations));
  assert.ok(body.scanner && typeof body.scanner === 'object');
  assert.ok(Array.isArray(body.scanner.ignoreDirectories));
  assert.ok(Array.isArray(body.scanner.ignoreFilenames));
  assert.ok(Array.isArray(body.scanner.ignoreExtensions));
  assert.strictEqual(typeof body.scanner.maxFileBytes, 'number');
  assert.strictEqual(body.storeRawForApproval, undefined);
  assert.strictEqual(body.rawRetentionDays, undefined);
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

test('admin policy rejects unknown detector ids without changing policy file', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  const res = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: {
      cookie,
      'x-csrf-token': csrfToken,
    },
    body: {
      ignore: ['NOT_REAL_DETECTOR'],
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: ['ignore.0'],
  });
  assert.strictEqual(fs.readFileSync(policyPath, 'utf8'), originalPolicy);
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
});
