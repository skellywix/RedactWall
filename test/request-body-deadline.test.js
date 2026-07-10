'use strict';
/** Absolute inbound-body deadlines must fire before auth or route side effects. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

process.env.NODE_ENV = 'test';
process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_REQUEST_BODY_TIMEOUT_MS = '100';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), `redactwall-body-deadline-${crypto.randomBytes(6).toString('hex')}.db`);
const policyPath = path.join(os.tmpdir(), `redactwall-body-deadline-policy-${crypto.randomBytes(6).toString('hex')}.json`);
process.env.REDACTWALL_POLICY_PATH = policyPath;
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), policyPath);

const { createGateway } = require('../gateway/server');
const gatewayTokens = require('../gateway/tokens');
const app = require('../server/app');
const db = require('../server/db');
const parsePool = require('../server/parse-pool');
const { listen, loopbackHttpFetch } = require('./support/listen');

function slowJsonRequest(port, requestPath, headers = {}, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let responseStarted = false;
    const startedAt = Date.now();
    const chunked = Object.keys(headers).some((name) => name.toLowerCase() === 'transfer-encoding');
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: requestPath,
      headers: {
        'content-type': 'application/json',
        ...(chunked ? {} : { 'content-length': '512' }),
        ...headers,
      },
    }, (res) => {
      responseStarted = true;
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        req.destroy();
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body,
          json: JSON.parse(body || '{}'),
          elapsedMs: Date.now() - startedAt,
        });
      });
    });
    req.on('error', (err) => {
      if (!settled && !responseStarted) {
        settled = true;
        clearTimeout(timer);
        reject(err);
      }
    });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(new Error(`slow request to ${requestPath} exceeded the test deadline`));
    }, timeoutMs);
    req.write('{"partial":');
  });
}

function gatewayFixture(t) {
  const calls = { gate: 0, scan: 0, upstream: 0 };
  const tokenDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-body-deadline-gateway-'));
  t.after(() => fs.rmSync(tokenDir, { recursive: true, force: true }));
  const agentTokensPath = path.join(tokenDir, 'tokens.json');
  const { token } = gatewayTokens.mintToken({ user: 'body-test@example.test', orgId: 'test' }, agentTokensPath);
  const client = {
    async gate() {
      calls.gate += 1;
      return { decision: 'allow', status: 'allowed' };
    },
    async scanResponse() {
      calls.scan += 1;
      return { leaked: false, decision: 'allow', status: 'allowed', blocked: false };
    },
  };
  const adapter = {
    async callUpstream() {
      calls.upstream += 1;
      return { ok: true, json: { choices: [{ message: { role: 'assistant', content: 'safe response' } }] } };
    },
  };
  const gateway = createGateway({
    client,
    adapter,
    agentTokensPath,
    provider: 'openai',
    requestBodyTimeoutMs: 100,
  });
  return { ...gateway, calls, token };
}

async function postJson(port, requestPath, body, headers = {}) {
  return loopbackHttpFetch(`http://127.0.0.1:${port}${requestPath}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

test('first-class gateway rejects a trickled JSON body before auth, gate, or upstream work', async (t) => {
  const fixture = gatewayFixture(t);
  const server = await listen(fixture.app);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const slow = await slowJsonRequest(server.address().port, '/v1/chat/completions');
  assert.strictEqual(slow.status, 408);
  assert.strictEqual(slow.headers.connection, 'close');
  assert.strictEqual(slow.json.error.type, 'request_timeout');
  assert.ok(slow.elapsedMs < 1500, `gateway deadline fired in ${slow.elapsedMs}ms`);
  assert.deepStrictEqual(fixture.calls, { gate: 0, scan: 0, upstream: 0 });
  assert.strictEqual(fixture.metrics.requests, 0);

  const normal = await postJson(server.address().port, '/v1/chat/completions', {
    model: 'test',
    messages: [{ role: 'user', content: 'Summarize public branch hours.' }],
  }, { authorization: `Bearer ${fixture.token}` });
  assert.strictEqual(normal.status, 200);
  assert.deepStrictEqual(fixture.calls, { gate: 1, scan: 1, upstream: 1 });
});

test('control plane deadlines cover gate and Base64 file-upload JSON before route side effects', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const beforeQueries = db.listQueries({ all: true }).length;
  let extractCalls = 0;
  const originalExtractText = parsePool.extractText;
  parsePool.extractText = async (...args) => {
    extractCalls += 1;
    return originalExtractText(...args);
  };
  t.after(() => { parsePool.extractText = originalExtractText; });

  const slowRoutes = [
    { path: '/api/v1/gate', headers: {} },
    { path: '/api/v1/scan-file', headers: { 'x-api-key': 'unit-ingest-key', 'transfer-encoding': 'chunked' } },
  ];
  for (const route of slowRoutes) {
    const slow = await slowJsonRequest(port, route.path, route.headers);
    assert.strictEqual(slow.status, 408, route.path);
    assert.strictEqual(slow.headers.connection, 'close', route.path);
    assert.deepStrictEqual(slow.json, { error: 'request body deadline exceeded' }, route.path);
    assert.ok(slow.elapsedMs < 1500, `${route.path} deadline fired in ${slow.elapsedMs}ms`);
  }
  assert.strictEqual(db.listQueries({ all: true }).length, beforeQueries);
  assert.strictEqual(extractCalls, 0);

  const gate = await postJson(port, '/api/v1/gate', {
    prompt: 'Summarize public branch hours.',
    destination: 'chatgpt.com',
  }, { 'x-api-key': 'unit-ingest-key' });
  assert.strictEqual(gate.status, 200);

  const upload = await postJson(port, '/api/v1/scan-file', {
    filename: 'public-hours.txt',
    contentBase64: Buffer.from('Public branch hours are nine to five.').toString('base64'),
    destination: 'chatgpt.com',
  }, { 'x-api-key': 'unit-ingest-key' });
  assert.strictEqual(upload.status, 200);
  assert.strictEqual(extractCalls, 1);
});

test.after(() => {
  try { db._db.close(); } catch {}
  for (const file of [
    process.env.REDACTWALL_DB_PATH,
    `${process.env.REDACTWALL_DB_PATH}-wal`,
    `${process.env.REDACTWALL_DB_PATH}-shm`,
    policyPath,
  ]) {
    try { fs.rmSync(file, { force: true }); } catch {}
  }
});
