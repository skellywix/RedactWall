'use strict';
/** Cloud classifier seam: opt-in, max-combine, and fail-closed to local. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-semantic-remote-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-semantic-remote-policy-' + crypto.randomBytes(6).toString('hex') + '.json');
require('node:fs').writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 20, governedDestinations: ['chatgpt.com'],
}, null, 2));

const detector = require('../detection-engine/detect');
const semanticRemote = require('../server/semantic-remote');
const app = require('../server/app');
const { listen } = require('./support/listen');

const BENIGN = 'Please summarize the cafeteria menu rotation for next month.';

function stubClassifier(handler) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => handler(req, body, res));
    });
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

test('remote settings require an explicit https/http opt-in', () => {
  assert.strictEqual(semanticRemote.remoteSettings({}).enabled, false);
  assert.strictEqual(semanticRemote.remoteSettings({ REDACTWALL_SEMANTIC_REMOTE_URL: 'ftp://x' }).enabled, false);
  const on = semanticRemote.remoteSettings({ REDACTWALL_SEMANTIC_REMOTE_URL: 'https://dlp.example/scan', REDACTWALL_SEMANTIC_REMOTE_TIMEOUT_MS: '900' });
  assert.deepStrictEqual({ enabled: on.enabled, timeoutMs: on.timeoutMs }, { enabled: true, timeoutMs: 900 });
});

test('remote categories are validated, capped, and max-combined into local analysis', async () => {
  const local = detector.analyze(BENIGN);
  assert.strictEqual(local.categories.length, 0, 'benign baseline');

  const server = await stubClassifier((req, body, res) => {
    assert.strictEqual(req.headers.authorization, 'Bearer cloud-key');
    assert.ok(JSON.parse(body).text.includes('cafeteria'));
    res.end(JSON.stringify({ categories: [
      { category: 'CONFIDENTIAL_BUSINESS', score: 0.93 },
      { category: 'NOT_A_REAL_CATEGORY', score: 0.99 },
      { category: 'CREDENTIALS', score: 7 },
    ] }));
  });
  try {
    const settings = { enabled: true, url: `http://127.0.0.1:${server.address().port}/scan`, key: 'cloud-key', timeoutMs: 2000 };
    const combined = await semanticRemote.augmentAnalysis(BENIGN, local, { settings });
    assert.deepStrictEqual(combined.categories.map((c) => c.category), ['CONFIDENTIAL_BUSINESS']);
    assert.strictEqual(combined.categories[0].source, 'remote');
    assert.ok(combined.riskScore > local.riskScore, 'remote hit raises risk');
    assert.ok(combined.maxSeverity >= 2);
    assert.strictEqual(local.categories.length, 0, 'local analysis object is not mutated');
  } finally {
    server.close();
  }
});

test('remote outage, timeout, and malformed replies fall back to local analysis', async () => {
  const local = detector.analyze(BENIGN);
  const down = await semanticRemote.augmentAnalysis(BENIGN, local, {
    settings: { enabled: true, url: 'http://127.0.0.1:9', timeoutMs: 300 },
  });
  assert.strictEqual(down, local, 'unreachable endpoint returns local analysis');

  const slow = await stubClassifier(() => { /* never responds */ });
  try {
    const timedOut = await semanticRemote.augmentAnalysis(BENIGN, local, {
      settings: { enabled: true, url: `http://127.0.0.1:${slow.address().port}/scan`, timeoutMs: 200 },
    });
    assert.strictEqual(timedOut, local, 'timeout returns local analysis');
  } finally {
    slow.close();
  }

  const garbled = await stubClassifier((req, body, res) => res.end('not json'));
  try {
    const bad = await semanticRemote.augmentAnalysis(BENIGN, local, {
      settings: { enabled: true, url: `http://127.0.0.1:${garbled.address().port}/scan`, timeoutMs: 1000 },
    });
    assert.strictEqual(bad, local, 'malformed reply returns local analysis');
  } finally {
    garbled.close();
  }
});

test('gate path consults the cloud classifier only when configured', async () => {
  let remoteCalls = 0;
  const server = await stubClassifier((req, body, res) => {
    remoteCalls += 1;
    res.end(JSON.stringify({ categories: [{ category: 'CONFIDENTIAL_BUSINESS', score: 0.95 }] }));
  });
  const gateServer = await listen(app);
  const gate = (body) => fetch(`http://127.0.0.1:${gateServer.address().port}/api/v1/gate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': 'unit-ingest-key' },
    body: JSON.stringify({ prompt: BENIGN, user: 'analyst@example.test', destination: 'chatgpt.com', source: 'browser_extension', ...body }),
  });
  try {
    const before = await (await gate({})).json();
    assert.strictEqual(remoteCalls, 0, 'no remote traffic without opt-in');
    assert.strictEqual(before.decision, 'allow');

    process.env.REDACTWALL_SEMANTIC_REMOTE_URL = `http://127.0.0.1:${server.address().port}/scan`;
    const after = await (await gate({})).json();
    assert.ok(remoteCalls >= 1, 'opt-in routes prompts through the classifier');
    assert.notStrictEqual(after.decision, 'allow', 'remote category drives the verdict');
    assert.ok((after.categories || []).includes('CONFIDENTIAL_BUSINESS'));
  } finally {
    delete process.env.REDACTWALL_SEMANTIC_REMOTE_URL;
    server.close();
    await new Promise((resolve) => gateServer.close(resolve));
  }
});

test('remote URL must be encrypted for a remote host: https anywhere, http only to loopback', () => {
  const on = (url, extra = {}) => semanticRemote.remoteSettings({ REDACTWALL_SEMANTIC_REMOTE_URL: url, ...extra }).enabled;
  assert.strictEqual(on('https://scan.vendor.example/classify'), true);
  assert.strictEqual(on('http://127.0.0.1:9000/scan'), true);          // loopback dev
  assert.strictEqual(on('http://localhost:9000/scan'), true);
  assert.strictEqual(on('http://scan.vendor.example/classify'), false); // cleartext to remote — rejected
  assert.strictEqual(on('ftp://scan.vendor.example'), false);
  // Explicit operator override re-enables cleartext to a remote host.
  assert.strictEqual(on('http://scan.vendor.example/classify', { REDACTWALL_SEMANTIC_REMOTE_ALLOW_INSECURE: '1' }), true);
});

test('fail mode: degrade returns local analysis, hold stamps remoteScanFailed', async () => {
  const local = detector.analyze(BENIGN, {});
  const downSettings = (failMode) => ({ enabled: true, url: 'http://127.0.0.1:9/scan', timeoutMs: 200, failMode });
  const fetchDown = async () => { throw new Error('ECONNREFUSED'); };

  const degraded = await semanticRemote.augmentAnalysis(BENIGN, local, { settings: downSettings('degrade'), fetchImpl: fetchDown });
  assert.strictEqual(degraded.remoteScanFailed, undefined);
  assert.strictEqual(degraded.riskScore, local.riskScore);

  const held = await semanticRemote.augmentAnalysis(BENIGN, local, { settings: downSettings('hold'), fetchImpl: fetchDown });
  assert.strictEqual(held.remoteScanFailed, true);
});

test('hold mode withholds an otherwise-allowed prompt for approval when the scanner is down', async () => {
  const down = await stubClassifier((req, body, res) => { res.destroy(); }); // connection drop = failure
  const gateServer = await listen(app);
  const port = gateServer.address().port;
  const gate = () => fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': 'unit-ingest-key' },
    body: JSON.stringify({ prompt: BENIGN, user: 'analyst@example.test', destination: 'chatgpt.com', source: 'browser_extension' }),
  });
  try {
    process.env.REDACTWALL_SEMANTIC_REMOTE_URL = `http://127.0.0.1:${down.address().port}/scan`;
    process.env.REDACTWALL_SEMANTIC_REMOTE_FAIL_MODE = 'hold';
    process.env.REDACTWALL_SEMANTIC_REMOTE_TIMEOUT_MS = '300';
    const body = await (await gate()).json();
    assert.strictEqual(body.decision, 'block');
    assert.strictEqual(body.status, 'pending'); // held for approval, not allowed through
  } finally {
    delete process.env.REDACTWALL_SEMANTIC_REMOTE_URL;
    delete process.env.REDACTWALL_SEMANTIC_REMOTE_FAIL_MODE;
    delete process.env.REDACTWALL_SEMANTIC_REMOTE_TIMEOUT_MS;
    down.close();
    await new Promise((resolve) => gateServer.close(resolve));
  }
});

test('hold mode blocks an AI response scan when the second-layer scanner is down', async () => {
  const down = await stubClassifier((req, body, res) => { res.destroy(); });
  const server = await listen(app);
  const port = server.address().port;
  const scan = () => fetch(`http://127.0.0.1:${port}/api/v1/scan-response`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': 'unit-ingest-key' },
    body: JSON.stringify({ text: BENIGN, user: 'analyst@example.test', destination: 'chatgpt.com', source: 'browser_extension' }),
  });
  try {
    process.env.REDACTWALL_SEMANTIC_REMOTE_URL = `http://127.0.0.1:${down.address().port}/scan`;
    process.env.REDACTWALL_SEMANTIC_REMOTE_FAIL_MODE = 'hold';
    process.env.REDACTWALL_SEMANTIC_REMOTE_TIMEOUT_MS = '300';
    const body = await (await scan()).json();
    // A benign response would locally scan clean; with the required second layer
    // down it must NOT return allow — fail closed by blocking.
    assert.strictEqual(body.decision, 'block');
    assert.strictEqual(body.blocked, true);
    assert.strictEqual(body.status, 'response_blocked');
  } finally {
    delete process.env.REDACTWALL_SEMANTIC_REMOTE_URL;
    delete process.env.REDACTWALL_SEMANTIC_REMOTE_FAIL_MODE;
    delete process.env.REDACTWALL_SEMANTIC_REMOTE_TIMEOUT_MS;
    down.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
