'use strict';
/** Canary fire drill should prove detection without leaking the planted token. */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const drill = require('../scripts/fire-drill');

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

test('canary fire drill token and prompt use detector-compatible shape', () => {
  const token = drill.makeCanaryToken('demo');
  assert.match(token, /^PS-CANARY-[A-Z0-9_-]{12,40}$/);
  assert.ok(drill.makePrompt(token).includes(token));
});

test('fire drill accepts block or redact responses that mask canary findings', () => {
  const token = drill.makeCanaryToken('pass');
  const result = drill.assertFireDrillResponse({
    id: 'q_1',
    decision: 'block',
    status: 'pending',
    riskScore: 80,
    findings: [{ type: 'CANARY_TOKEN', masked: '[CANARY_TOKEN]' }],
  }, token);
  assert.deepStrictEqual(result.findings, ['CANARY_TOKEN']);
  assert.strictEqual(result.decision, 'block');
});

test('fire drill fails when canary is missing', () => {
  const token = drill.makeCanaryToken('missing');
  assert.throws(() => drill.assertFireDrillResponse({
    decision: 'block',
    findings: [{ type: 'US_SSN', masked: '***' }],
  }, token), /CANARY_TOKEN was not detected/);
});

test('fire drill fails when the gate does not block or redact', () => {
  const token = drill.makeCanaryToken('allow');
  assert.throws(() => drill.assertFireDrillResponse({
    decision: 'allow',
    findings: [{ type: 'CANARY_TOKEN', masked: '[CANARY_TOKEN]' }],
  }, token), /expected block or redact decision/);
});

test('fire drill fails if the raw canary appears in response JSON', () => {
  const token = drill.makeCanaryToken('leak');
  assert.throws(() => drill.assertFireDrillResponse({
    decision: 'redact',
    status: 'redacted',
    tokenizedPrompt: `unsafe ${token}`,
    findings: [{ type: 'CANARY_TOKEN', masked: '[CANARY_TOKEN]' }],
  }, token), /raw canary token appeared/);
});

test('runFireDrill posts a canary gate request and returns sanitized summary', async () => {
  const requests = [];
  const token = drill.makeCanaryToken('request');
  const result = await drill.runFireDrill({
    baseUrl: 'https://control.example/',
    ingestKey: 'test-key',
    token,
    async fetchImpl(url, options) {
      requests.push({ url, options, body: JSON.parse(options.body) });
      return jsonResponse(200, {
        id: 'q_fire',
        decision: 'redact',
        status: 'redacted',
        riskScore: 99,
        findings: [{ type: 'CANARY_TOKEN', masked: '[CANARY_TOKEN]' }],
      });
    },
  });

  assert.strictEqual(requests[0].url, 'https://control.example/api/v1/gate');
  assert.strictEqual(requests[0].options.redirect, 'error');
  assert.strictEqual(requests[0].options.headers['x-api-key'], 'test-key');
  assert.strictEqual(requests[0].body.destination, 'chatgpt.com');
  assert.strictEqual(requests[0].body.source, 'fire_drill');
  assert.ok(requests[0].body.prompt.includes(token));
  assert.strictEqual(result.id, 'q_fire');
  assert.deepStrictEqual(result.findings, ['CANARY_TOKEN']);
});

test('runFireDrill reports non-OK gate responses', async () => {
  await assert.rejects(() => drill.runFireDrill({
    baseUrl: 'https://control.example',
    token: drill.makeCanaryToken('fail'),
    async fetchImpl() {
      return { ok: false, status: 503 };
    },
  }), /HTTP 503/);
});

test('runFireDrill cancels a stalled unknown-length response body', async () => {
  let cancelled = false;
  await assert.rejects(() => drill.runFireDrill({
    baseUrl: 'https://control.example',
    token: drill.makeCanaryToken('stall'),
    responseTimeoutMs: 20,
    async fetchImpl() {
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        body: new ReadableStream({
          cancel() { cancelled = true; },
        }),
      };
    },
  }), (err) => err && err.code === 'REDACTWALL_RESPONSE_TIMEOUT');
  assert.strictEqual(cancelled, true);
});

test('runFireDrill rejects a remote cleartext control plane before sending the key or canary', async () => {
  let called = false;
  await assert.rejects(() => drill.runFireDrill({
    baseUrl: 'http://control.example',
    ingestKey: 'unit-key',
    token: drill.makeCanaryToken('cleartext'),
    fetchImpl: async () => { called = true; },
  }), /must use HTTPS or loopback HTTP/);
  assert.strictEqual(called, false);
});

test('runFireDrill does not forward the ingest key or body through a real 307 redirect', async (t) => {
  let redirectedRequests = 0;
  const receiver = http.createServer((req, res) => {
    redirectedRequests += 1;
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  const receiverPort = await listen(receiver);
  t.after(() => close(receiver));

  const redirector = http.createServer((req, res) => {
    req.resume();
    res.writeHead(307, { location: `http://127.0.0.1:${receiverPort}/capture` });
    res.end();
  });
  const redirectorPort = await listen(redirector);
  t.after(() => close(redirector));

  await assert.rejects(() => drill.runFireDrill({
    baseUrl: `http://127.0.0.1:${redirectorPort}`,
    ingestKey: 'must-not-reach-redirect-target',
    token: drill.makeCanaryToken('redirect'),
  }), /fetch failed|redirect/i);
  assert.strictEqual(redirectedRequests, 0);
});

test('fire drill main emits an operator summary with the selected base URL', async () => {
  const lines = [];
  const result = await drill.main(['http://local.test'], {
    console: { log(message) { lines.push(message); } },
    async runFireDrill({ baseUrl }) {
      assert.strictEqual(baseUrl, 'http://local.test');
      return { id: 'q_main', decision: 'block', status: 'pending', riskScore: 88 };
    },
  });

  assert.strictEqual(result.id, 'q_main');
  assert.strictEqual(lines[0], 'FIRE_DRILL_OK q_main decision=block status=pending risk=88');
});

test('fire drill cli reports failures without leaking raw response content', async () => {
  const lines = [];
  let exitCode = 0;
  const result = await drill.cli(['http://local.test'], {
    console: {
      log(message) { lines.push(['log', message]); },
      error(message) { lines.push(['error', message]); },
    },
    setExitCode(code) { exitCode = code; },
    async runFireDrill() {
      throw new Error('fire drill request failed: HTTP 503');
    },
  });

  assert.strictEqual(result, null);
  assert.strictEqual(exitCode, 1);
  assert.deepStrictEqual(lines, [['error', 'fire drill request failed: HTTP 503']]);
});
