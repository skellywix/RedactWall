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
const policyPath = path.join(os.tmpdir(), 'ps-validation-policy-' + crypto.randomBytes(6).toString('hex') + '.json');
process.env.SENTINEL_POLICY_PATH = policyPath;
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), policyPath);

const app = require('../server/app');
const { listen, loopbackHttpFetch } = require('./support/listen');
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
  return loopbackHttpFetch(`http://127.0.0.1:${port}${apiPath}`, {
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
  assert.ok(cookie.includes('promptwall_session='));
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
    assert.strictEqual(gap.sensorVersionGap.versionHealth, 'outdated');
    assert.strictEqual(gap.sensorVersionGap.desiredVersion, '0.3.0');
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

test('gate accepts ocr_required as its own blocked file outcome', async () => withServer(async (port) => {
  const fileContent = 'image bytes with SSN 524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[file blocked unscanned] member-loan-scan.png',
      user: 'endpoint-user',
      destination: 'desktop-ai-app',
      source: 'endpoint_agent',
      channel: 'file_upload',
      clientOutcome: 'ocr_required',
      note: 'blocked locally: OCR required before inspection',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'ocr_required');
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

test('gate records locally blocked sensitive pastes from client-redacted evidence', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[REDACTED: US_SSN]',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'paste',
      clientOutcome: 'paste_flagged',
      clientPreRedacted: true,
      clientFindings: [{ type: 'US_SSN', severity: 4, score: 0.95, masked: '***-**-9043' }],
      clientCategories: [],
      clientEntityCounts: { US_SSN: 1 },
      clientRiskScore: 30,
      clientMaxSeverity: 4,
      clientMaxSeverityLabel: 'critical',
      note: 'blocked locally: sensitive paste prevented before insertion',
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
  assert.ok(stored.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(!JSON.stringify(stored).includes(secret));
}));

test('gate accepts browser action blocks without retaining clipboard text', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[browser action blocked] paste chatgpt.com ' + secret,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'paste',
      clientOutcome: 'action_blocked',
      note: 'clipboard paste blocked by policy',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'action_blocked');
  assert.deepStrictEqual(body.findings, []);
  assert.deepStrictEqual(body.categories, []);
  assert.ok(!JSON.stringify(body).includes(secret));

  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.status, 'action_blocked');
  assert.strictEqual(stored.mode, 'browser_action_block');
  assert.strictEqual(stored.channel, 'paste');
  assert.strictEqual(stored.destination, 'chatgpt.com');
  assert.strictEqual(stored._rawPrompt, undefined);
  assert.deepStrictEqual(stored.findings, []);
  assert.ok(!JSON.stringify(stored).includes(secret));
  assert.ok(db.listAudit(20).some((entry) => entry.action === 'BROWSER_ACTION_BLOCKED' && entry.queryId === body.id));
}));

test('gate accepts blocked browser drops without retaining file text', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[browser action blocked] drop chatgpt.com ' + secret,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'drop',
      clientOutcome: 'action_blocked',
      note: 'file drop blocked by policy',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'action_blocked');
  assert.deepStrictEqual(body.findings, []);
  assert.deepStrictEqual(body.categories, []);
  assert.ok(!JSON.stringify(body).includes(secret));

  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.status, 'action_blocked');
  assert.strictEqual(stored.mode, 'browser_action_block');
  assert.strictEqual(stored.channel, 'drop');
  assert.strictEqual(stored._rawPrompt, undefined);
  assert.deepStrictEqual(stored.findings, []);
  assert.ok(!JSON.stringify(stored).includes(secret));
  assert.ok(db.listAudit(20).some((entry) => entry.action === 'BROWSER_ACTION_BLOCKED' && entry.detail === 'browser_extension/drop: chatgpt.com'));
}));

test('gate accepts blocked browser copies without retaining selected text', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[browser action blocked] copy chatgpt.com ' + secret,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'copy',
      clientOutcome: 'action_blocked',
      note: 'response copy blocked by policy',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'action_blocked');
  assert.deepStrictEqual(body.findings, []);
  assert.deepStrictEqual(body.categories, []);
  assert.ok(!JSON.stringify(body).includes(secret));

  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.status, 'action_blocked');
  assert.strictEqual(stored.mode, 'browser_action_block');
  assert.strictEqual(stored.channel, 'copy');
  assert.strictEqual(stored._rawPrompt, undefined);
  assert.deepStrictEqual(stored.findings, []);
  assert.ok(!JSON.stringify(stored).includes(secret));
  assert.ok(db.listAudit(20).some((entry) => entry.action === 'BROWSER_ACTION_BLOCKED' && entry.detail === 'browser_extension/copy: chatgpt.com'));
}));

test('gate sanitizes malformed browser action labels without retaining channel text', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[browser action blocked] custom',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'paste-' + secret,
      clientOutcome: 'action_blocked',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'action_blocked');
  assert.ok(!JSON.stringify(body).includes(secret));

  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.channel, 'browser_action');
  assert.ok(!JSON.stringify(stored).includes(secret));
  assert.ok(!db.listAudit(20).some((entry) => String(entry.detail || '').includes(secret)));
}));

test('gate records endpoint clipboard action blocks with masked client evidence', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[clipboard blocked locally] US_SSN ' + secret,
      user: 'analyst@example.test',
      destination: 'Desktop AI',
      source: 'endpoint_agent',
      channel: 'clipboard',
      clientOutcome: 'action_blocked',
      clientPreRedacted: true,
      clientFindings: [{ type: 'US_SSN', severity: 4, score: 0.95, masked: '***-**-9043' }],
      clientCategories: [],
      clientEntityCounts: { US_SSN: 1 },
      clientRiskScore: 30,
      clientMaxSeverity: 4,
      clientMaxSeverityLabel: 'critical',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'action_blocked');
  assert.ok(body.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(!JSON.stringify(body).includes(secret));

  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.status, 'action_blocked');
  assert.strictEqual(stored.source, 'endpoint_agent');
  assert.strictEqual(stored.channel, 'clipboard');
  assert.strictEqual(stored.destination, 'desktop-ai');
  assert.strictEqual(stored._rawPrompt, undefined);
  assert.ok(stored.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(!JSON.stringify(stored).includes(secret));
  assert.ok(db.listAudit(20).some((entry) => entry.action === 'CLIENT_ACTION_BLOCKED' && entry.detail === 'endpoint_agent/clipboard: desktop-ai'));
}));

test('gate applies configured paste browser action blocks before prompt analysis', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const secret = '524-71-9043';
  try {
    const next = {
      ...JSON.parse(originalPolicy),
      blockedBrowserActions: [{
        id: 'block_paste_chatgpt',
        action: 'paste',
        destinations: ['chatgpt.com'],
        reason: 'clipboard_paste_blocked',
      }],
    };
    fs.writeFileSync(policyPath, JSON.stringify(next, null, 2));

    const res = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Pasted member SSN ' + secret + ' into the composer.',
        user: 'analyst@example.test',
        destination: 'https://chatgpt.com/c/unit',
        source: 'browser_extension',
        channel: 'paste',
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.status, 'action_blocked');
    assert.deepStrictEqual(body.reasons, ['clipboard_paste_blocked']);
    const stored = db.getQuery(body.id);
    assert.strictEqual(stored.status, 'action_blocked');
    assert.deepStrictEqual(stored.findings, []);
    assert.ok(!JSON.stringify(stored).includes(secret));
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('gate applies configured drop browser action blocks before prompt analysis', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const secret = '524-71-9043';
  try {
    const next = {
      ...JSON.parse(originalPolicy),
      blockedBrowserActions: [{
        id: 'block_drop_chatgpt',
        action: 'drop',
        destinations: ['chatgpt.com'],
        reason: 'file_drop_blocked',
      }],
    };
    fs.writeFileSync(policyPath, JSON.stringify(next, null, 2));

    const res = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: '[browser action blocked] drop chatgpt.com ' + secret,
        user: 'analyst@example.test',
        destination: 'https://chatgpt.com/c/unit',
        source: 'browser_extension',
        channel: 'drop',
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.status, 'action_blocked');
    assert.deepStrictEqual(body.reasons, ['file_drop_blocked']);
    const stored = db.getQuery(body.id);
    assert.strictEqual(stored.status, 'action_blocked');
    assert.strictEqual(stored.channel, 'drop');
    assert.deepStrictEqual(stored.findings, []);
    assert.ok(!JSON.stringify(stored).includes(secret));
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('gate applies configured copy browser action blocks before prompt analysis', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const secret = '524-71-9043';
  try {
    const next = {
      ...JSON.parse(originalPolicy),
      blockedBrowserActions: [{
        id: 'block_copy_chatgpt',
        action: 'copy',
        destinations: ['chatgpt.com'],
        reason: 'response_copy_blocked',
      }],
    };
    fs.writeFileSync(policyPath, JSON.stringify(next, null, 2));

    const res = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: '[browser action blocked] copy chatgpt.com ' + secret,
        user: 'analyst@example.test',
        destination: 'https://chatgpt.com/c/unit',
        source: 'browser_extension',
        channel: 'copy',
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.status, 'action_blocked');
    assert.deepStrictEqual(body.reasons, ['response_copy_blocked']);
    const stored = db.getQuery(body.id);
    assert.strictEqual(stored.status, 'action_blocked');
    assert.strictEqual(stored.channel, 'copy');
    assert.deepStrictEqual(stored.findings, []);
    assert.ok(!JSON.stringify(stored).includes(secret));
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
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

test('gate blocks configured destinations without retaining prompt text', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const secret = '524-71-9043';
  try {
    const next = { ...JSON.parse(originalPolicy), blockedDestinations: ['chatgpt.com'] };
    fs.writeFileSync(policyPath, JSON.stringify(next, null, 2));

    const res = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Please review member SSN ' + secret,
        user: 'analyst@example.test',
        destination: 'https://chatgpt.com/c/unit',
        source: 'browser_extension',
        channel: 'submit',
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.decision, 'block');
    assert.strictEqual(body.status, 'destination_blocked');
    assert.deepStrictEqual(body.reasons, ['Destination blocked by policy']);

    const stored = db.getQuery(body.id);
    assert.strictEqual(stored.status, 'destination_blocked');
    assert.strictEqual(stored.mode, 'destination_block');
    assert.strictEqual(stored.destination, 'chatgpt.com');
    assert.deepStrictEqual(stored.findings, []);
    assert.deepStrictEqual(stored.categories, []);
    assert.strictEqual(stored._rawPrompt, undefined);
    assert.ok(!JSON.stringify(stored).includes(secret));
    assert.ok(db.listAudit(20).some((entry) => entry.action === 'DESTINATION_BLOCKED' && entry.queryId === body.id));
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('scan-file blocks configured destinations before file inspection', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const secret = '524-71-9043';
  const sensitiveFilename = 'member-524-71-9043.txt';
  try {
    const next = { ...JSON.parse(originalPolicy), blockedDestinations: ['desktop-ai-app'] };
    fs.writeFileSync(policyPath, JSON.stringify(next, null, 2));

    const res = await jsonFetch(port, '/api/v1/scan-file', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        filename: sensitiveFilename,
        contentBase64: Buffer.from('member file SSN ' + secret).toString('base64'),
        user: 'endpoint-user',
        destination: 'desktop-ai-app',
        source: 'endpoint_agent',
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.decision, 'block');
    assert.strictEqual(body.status, 'destination_blocked');
    assert.strictEqual(body.inspected, false);
    assert.strictEqual(body.supported, true);

    const stored = db.getQuery(body.id);
    assert.strictEqual(stored.status, 'destination_blocked');
    assert.strictEqual(stored.destination, 'desktop-ai-app');
    assert.strictEqual(stored._rawPrompt, undefined);
    assert.strictEqual(stored.filename, undefined);
    assert.ok(!JSON.stringify(stored).includes(secret));
    assert.ok(!JSON.stringify(stored).includes(sensitiveFilename));
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('gate accepts file-upload policy blocks without retaining prompt text', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body: {
      prompt: '[file upload blocked] chatgpt.com ' + secret,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'file_upload',
      clientOutcome: 'file_upload_blocked',
      note: 'blocked locally: file upload blocked by policy',
    },
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'file_upload_blocked');
  assert.deepStrictEqual(body.reasons, ['File upload blocked by policy']);

  const stored = db.getQuery(body.id);
  assert.strictEqual(stored.status, 'file_upload_blocked');
  assert.strictEqual(stored.mode, 'file_upload_block');
  assert.strictEqual(stored.destination, 'chatgpt.com');
  assert.deepStrictEqual(stored.findings, []);
  assert.deepStrictEqual(stored.categories, []);
  assert.strictEqual(stored._rawPrompt, undefined);
  assert.ok(!JSON.stringify(stored).includes(secret));
  assert.ok(db.listAudit(20).some((entry) => entry.action === 'FILE_UPLOAD_BLOCKED' && entry.queryId === body.id));
}));

test('scan-file blocks configured file-upload destinations before file inspection', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const secret = '524-71-9043';
  const sensitiveFilename = 'member-524-71-9043.txt';
  try {
    const next = { ...JSON.parse(originalPolicy), blockedFileUploadDestinations: ['chatgpt.com'] };
    fs.writeFileSync(policyPath, JSON.stringify(next, null, 2));

    const res = await jsonFetch(port, '/api/v1/scan-file', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        filename: sensitiveFilename,
        contentBase64: Buffer.from('member file SSN ' + secret).toString('base64'),
        user: 'browser-user',
        destination: 'https://chatgpt.com/c/unit',
        source: 'browser_extension',
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.decision, 'block');
    assert.strictEqual(body.status, 'file_upload_blocked');
    assert.strictEqual(body.inspected, false);
    assert.strictEqual(body.supported, true);

    const stored = db.getQuery(body.id);
    assert.strictEqual(stored.status, 'file_upload_blocked');
    assert.strictEqual(stored.destination, 'chatgpt.com');
    assert.strictEqual(stored._rawPrompt, undefined);
    assert.strictEqual(stored.filename, undefined);
    assert.ok(!JSON.stringify(stored).includes(secret));
    assert.ok(!JSON.stringify(stored).includes(sensitiveFilename));
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('gate blocks unapproved AI destinations by default with allowlist override', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  try {
    const next = {
      ...JSON.parse(originalPolicy),
      governedDestinations: ['chatgpt.com'],
      allowedDestinations: [],
      blockedDestinations: [],
      blockUnapprovedAiDestinations: true,
    };
    fs.writeFileSync(policyPath, JSON.stringify(next, null, 2));

    const blocked = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: '[shadow-AI] visit to ungoverned AI tool: notebooklm.google.com',
        user: 'analyst@example.test',
        destination: 'notebooklm.google.com',
        source: 'browser_extension',
        channel: 'shadow_ai',
        clientOutcome: 'shadow_ai',
      },
    });
    assert.strictEqual(blocked.status, 200);
    const blockedBody = await blocked.json();
    assert.strictEqual(blockedBody.decision, 'block');
    assert.strictEqual(blockedBody.status, 'destination_blocked');
    assert.deepStrictEqual(blockedBody.reasons, ['Unapproved AI destination blocked by policy']);
    const stored = db.getQuery(blockedBody.id);
    assert.strictEqual(stored.status, 'destination_blocked');
    assert.strictEqual(stored.channel, 'shadow_ai');
    assert.strictEqual(stored.destination, 'notebooklm.google.com');

    fs.writeFileSync(policyPath, JSON.stringify({ ...next, allowedDestinations: ['notebooklm.google.com'] }, null, 2));
    const allowed = await jsonFetch(port, '/api/v1/gate', {
      headers: { 'x-api-key': 'unit-ingest-key' },
      body: {
        prompt: 'Summarize this public FAQ.',
        user: 'analyst@example.test',
        destination: 'notebooklm.google.com',
        source: 'browser_extension',
        channel: 'submit',
      },
    });
    assert.strictEqual(allowed.status, 200);
    const allowedBody = await allowed.json();
    assert.strictEqual(allowedBody.decision, 'allow');
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
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
  assert.ok(Array.isArray(body.allowedDestinations));
  assert.ok(Array.isArray(body.blockedDestinations));
  assert.ok(Array.isArray(body.blockedFileUploadDestinations));
  assert.ok(Array.isArray(body.blockedBrowserActions));
  assert.strictEqual(body.blockUnapprovedAiDestinations, true);
  assert.strictEqual(body.responseScanMode, 'flag');
  assert.strictEqual(body.desktopCollectorDestination, 'Desktop AI');
  assert.ok(Array.isArray(body.requiredSensors));
  assert.ok(body.requiredSensors.includes('browser_extension'));
  assert.ok(body.desiredSensorVersions && typeof body.desiredSensorVersions === 'object');
  assert.strictEqual(body.desiredSensorVersions.browser_extension, '0.3.0');
  assert.ok(body.scanner && typeof body.scanner === 'object');
  assert.ok(Array.isArray(body.scanner.ignoreDirectories));
  assert.ok(Array.isArray(body.scanner.ignoreFilenames));
  assert.ok(Array.isArray(body.scanner.ignoreExtensions));
  assert.strictEqual(typeof body.scanner.maxFileBytes, 'number');
  assert.strictEqual(body.approvalRoutingRules, undefined);
  assert.strictEqual(body.policyScopes, undefined);
  assert.strictEqual(body.policyExceptions, undefined);
  assert.strictEqual(body.storeRawForApproval, undefined);
  assert.strictEqual(body.rawRetentionDays, undefined);
}));

test('admin policy accepts its own full policy payload', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  try {
    const policyRes = await jsonFetch(port, '/api/policy', {
      method: 'GET',
      headers: { cookie },
    });
    assert.strictEqual(policyRes.status, 200);
    const body = await policyRes.json();
    assert.strictEqual(Number.isInteger(body.scanner.maxFileBytes), true);

    const save = await jsonFetch(port, '/api/policy', {
      method: 'PUT',
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body,
    });
    assert.strictEqual(save.status, 200);
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('admin auth accepts legacy session cookie during PromptWall migration', async () => withServer(async (port) => {
  const { cookie } = await login(port);
  const legacyCookie = cookie.replace(/^promptwall_session=/, 'sentinel_session=');

  const me = await jsonFetch(port, '/api/me', {
    method: 'GET',
    headers: { cookie: legacyCookie },
  });
  assert.strictEqual(me.status, 200);
  const body = await me.json();
  assert.strictEqual(body.user, 'admin');

  const csrfRes = await jsonFetch(port, '/api/csrf', {
    method: 'GET',
    headers: { cookie: legacyCookie },
  });
  assert.strictEqual(csrfRes.status, 200);
  const csrf = await csrfRes.json();
  assert.match(csrf.csrfToken, /^[A-Za-z0-9_-]+$/);

  const logout = await jsonFetch(port, '/api/logout', {
    headers: {
      cookie: legacyCookie,
      'x-csrf-token': csrf.csrfToken,
    },
  });
  assert.strictEqual(logout.status, 200);
  const setCookie = logout.headers.get('set-cookie') || '';
  assert.ok(setCookie.includes('promptwall_session='));
  assert.ok(setCookie.includes('sentinel_session='));
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

test('admin policy accepts desktop collector destination labels', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  try {
    const res = await jsonFetch(port, '/api/policy', {
      method: 'PUT',
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body: {
        desktopCollectorDestination: 'Copilot Desktop',
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.desktopCollectorDestination, 'Copilot Desktop');
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('admin policy accepts fleet posture settings', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  try {
    const res = await jsonFetch(port, '/api/policy', {
      method: 'PUT',
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body: {
        requiredSensors: ['browser_extension', 'endpoint_agent', 'mcp_guard', 'proxy'],
        desiredSensorVersions: {
          browser_extension: '0.3.0',
          endpoint_agent: '0.3.0',
          mcp_guard: '0.3.0',
          proxy: '1.0.0',
        },
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.deepStrictEqual(body.requiredSensors, ['browser_extension', 'endpoint_agent', 'mcp_guard', 'proxy']);
    assert.strictEqual(body.desiredSensorVersions.proxy, '1.0.0');
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('admin policy accepts browser action block rules', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  try {
    const res = await jsonFetch(port, '/api/policy', {
      method: 'PUT',
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body: {
        blockedBrowserActions: [
          {
            id: 'block_paste_chatgpt',
            action: 'paste',
            destinations: ['chatgpt.com'],
            reason: 'clipboard_paste_blocked',
          },
          {
            id: 'block_drop_claude',
            action: 'drop',
            destinations: ['claude.ai'],
            reason: 'file_drop_blocked',
          },
          {
            id: 'block_copy_chatgpt',
            action: 'copy',
            destinations: ['chatgpt.com'],
            reason: 'response_copy_blocked',
          },
        ],
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.deepStrictEqual(body.blockedBrowserActions, [
      {
        id: 'block_paste_chatgpt',
        enabled: true,
        action: 'paste',
        destinations: ['chatgpt.com'],
        reason: 'clipboard_paste_blocked',
      },
      {
        id: 'block_drop_claude',
        enabled: true,
        action: 'drop',
        destinations: ['claude.ai'],
        reason: 'file_drop_blocked',
      },
      {
        id: 'block_copy_chatgpt',
        enabled: true,
        action: 'copy',
        destinations: ['chatgpt.com'],
        reason: 'response_copy_blocked',
      },
    ]);
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('admin policy rejects malformed browser action rules without echoing values', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: {
      cookie,
      'x-csrf-token': csrfToken,
    },
    body: {
      blockedBrowserActions: [{
        id: 'bad_paste',
        action: 'download',
        destinations: [`member-${secret}.example`],
        reason: `paste-${secret}`,
      }],
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: [
      'blockedBrowserActions.0.action',
      'blockedBrowserActions.0.destinations.0',
      'blockedBrowserActions.0.reason',
    ],
  });
  assert.ok(!JSON.stringify(body).includes(secret));
  assert.strictEqual(fs.readFileSync(policyPath, 'utf8'), originalPolicy);
}));

test('admin policy accepts customer approval routing rules', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  try {
    const res = await jsonFetch(port, '/api/policy', {
      method: 'PUT',
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body: {
        approvalRoutingRules: [{
          id: 'member_services_chatgpt',
          users: ['lending@example.test'],
          groups: ['PromptWall Lending'],
          orgIds: ['cu-001'],
          detectors: ['MEMBER_ID'],
          destinations: ['chatgpt.com'],
          minSeverity: 2,
          assignedGroup: 'member_services',
          assignedRole: 'approver',
          slaMinutes: 120,
          reason: 'member_services',
        }],
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.deepStrictEqual(body.approvalRoutingRules, [{
      id: 'member_services_chatgpt',
      enabled: true,
      assignedGroup: 'member_services',
      assignedRole: 'approver',
      slaMinutes: 120,
      reason: 'member_services',
      users: ['lending@example.test'],
      groups: ['promptwall lending'],
      orgIds: ['cu-001'],
      detectors: ['MEMBER_ID'],
      destinations: ['chatgpt.com'],
      minSeverity: 2,
    }]);
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('admin policy accepts scoped policy and time-bound exceptions', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  try {
    const res = await jsonFetch(port, '/api/policy', {
      method: 'PUT',
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body: {
        policyScopes: [{
          id: 'legal_contract_review',
          groups: ['PromptWall Legal'],
          destinations: ['claude.ai'],
          categories: ['LEGAL_CONTRACT'],
          enforcementMode: 'block',
          blockMinSeverity: 2,
          blockRiskScore: 10,
          alwaysBlockAdd: ['SECRET_KEY'],
          reason: 'legal_review',
        }],
        policyExceptions: [{
          id: 'legal_vendor_24h',
          users: ['counsel@example.test'],
          destinations: ['claude.ai'],
          categories: ['LEGAL_CONTRACT'],
          expiresAt: '2030-01-01T00:00:00.000Z',
          ownerGroup: 'legal',
          reviewerRole: 'security_admin',
          reviewAfter: '2029-12-15T00:00:00.000Z',
          reason: 'approved_vendor_review',
        }],
      },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.deepStrictEqual(body.policyScopes, [{
      id: 'legal_contract_review',
      enabled: true,
      groups: ['promptwall legal'],
      detectors: undefined,
      categories: ['LEGAL_CONTRACT'],
      sources: undefined,
      channels: undefined,
      destinations: ['claude.ai'],
      enforcementMode: 'block',
      blockMinSeverity: 2,
      blockRiskScore: 10,
      alwaysBlockAdd: ['SECRET_KEY'],
      reason: 'legal_review',
    }].map((item) => Object.fromEntries(Object.entries(item).filter(([, value]) => value !== undefined))));
    assert.deepStrictEqual(body.policyExceptions, [{
      id: 'legal_vendor_24h',
      enabled: true,
      action: 'allow',
      expiresAt: '2030-01-01T00:00:00.000Z',
      ownerGroup: 'legal',
      reviewerRole: 'security_admin',
      reviewAfter: '2029-12-15T00:00:00.000Z',
      users: ['counsel@example.test'],
      categories: ['LEGAL_CONTRACT'],
      destinations: ['claude.ai'],
      reason: 'approved_vendor_review',
    }]);
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test('admin policy rejects malformed scoped policy without echoing values', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: {
      cookie,
      'x-csrf-token': csrfToken,
    },
    body: {
      policyScopes: [{
        id: 'bad_scope',
        groups: [`legal-${secret}`],
      }],
      policyExceptions: [{
        id: 'bad_exception',
        action: 'allow',
        expiresAt: 'not-a-date',
      }],
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: [
      'policyExceptions.0.expiresAt',
      'policyExceptions.0.id',
      'policyScopes.0.groups.0',
      'policyScopes.0.id',
    ],
  });
  assert.ok(!JSON.stringify(body).includes(secret));
  assert.strictEqual(fs.readFileSync(policyPath, 'utf8'), originalPolicy);
}));

test('admin policy rejects malformed approval routing rules without echoing values', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  const secret = '524-71-9043';
  const res = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: {
      cookie,
      'x-csrf-token': csrfToken,
    },
    body: {
      approvalRoutingRules: [{
        id: 'bad_member_rule',
        groups: [`member-${secret}`],
        detectors: ['NOT_REAL_DETECTOR'],
        assignedGroup: 'member services',
        assignedRole: 'owner',
        slaMinutes: 5,
        reason: `member-${secret}`,
      }],
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: [
      'approvalRoutingRules.0.assignedGroup',
      'approvalRoutingRules.0.assignedRole',
      'approvalRoutingRules.0.detectors.0',
      'approvalRoutingRules.0.groups.0',
      'approvalRoutingRules.0.reason',
      'approvalRoutingRules.0.slaMinutes',
    ],
  });
  assert.ok(!JSON.stringify(body).includes(secret));
  assert.strictEqual(fs.readFileSync(policyPath, 'utf8'), originalPolicy);
}));

test('admin policy rejects malformed fleet posture settings without changing policy file', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);
  const res = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: {
      cookie,
      'x-csrf-token': csrfToken,
    },
    body: {
      requiredSensors: ['Browser Extension'],
      desiredSensorVersions: {
        browser_extension: '0.3.0<script>',
      },
    },
  });

  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: ['desiredSensorVersions.browser_extension', 'requiredSensors.0'],
  });
  assert.strictEqual(fs.readFileSync(policyPath, 'utf8'), originalPolicy);
}));

test('admin destination review validates, persists, and audits decisions', async () => withServer(async (port) => {
  const originalPolicy = fs.readFileSync(policyPath, 'utf8');
  const { cookie, csrfToken } = await login(port);

  try {
    const invalid = await jsonFetch(port, '/api/destinations/review', {
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body: {
        destination: 'poe.com',
        decision: 'allow',
        rawPrompt: 'member SSN 524-71-9043',
      },
    });
    assert.strictEqual(invalid.status, 400);
    assert.deepStrictEqual(await invalid.json(), {
      error: 'invalid request body',
      fields: ['rawPrompt', 'reason'],
    });
    assert.strictEqual(fs.readFileSync(policyPath, 'utf8'), originalPolicy);

    const missingReason = await jsonFetch(port, '/api/destinations/review', {
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body: {
        destination: 'poe.com',
        decision: 'allow',
      },
    });
    assert.strictEqual(missingReason.status, 400);
    assert.deepStrictEqual(await missingReason.json(), {
      error: 'invalid request body',
      fields: ['reason'],
    });
    assert.strictEqual(fs.readFileSync(policyPath, 'utf8'), originalPolicy);

    const res = await jsonFetch(port, '/api/destinations/review', {
      headers: {
        cookie,
        'x-csrf-token': csrfToken,
      },
      body: {
        destination: 'https://www.Poe.com/chat',
        decision: 'allow',
        reason: 'Approved for vendor evaluation pilot',
      },
    });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.destination, 'poe.com');
    assert.strictEqual(body.decision, 'allow');
    assert.ok(body.policy.allowedDestinations.includes('poe.com'));
    assert.ok(!body.policy.governedDestinations.includes('poe.com'));
    assert.ok(!body.policy.blockedDestinations.includes('poe.com'));
    assert.ok(body.coverage);
    const reviewAudit = db.listAudit(20).find((entry) => entry.action === 'DESTINATION_REVIEWED');
    assert.ok(reviewAudit);
    assert.strictEqual(JSON.parse(reviewAudit.detail).reason, 'Approved for vendor evaluation pilot');
  } finally {
    fs.writeFileSync(policyPath, originalPolicy);
  }
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(policyPath); } catch {}
});
