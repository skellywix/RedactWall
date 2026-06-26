'use strict';
/** Proxy/ICAP bridge must fail closed when the control plane is unavailable. */
const test = require('node:test');
const assert = require('node:assert');
const {
  extractPrompt,
  gate,
  awaitRelease,
  requestTimeoutMs,
} = require('../scripts/squid-icap-bridge');

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

test('extracts user prompt text from chat-style JSON bodies', () => {
  const body = JSON.stringify({
    messages: [
      { role: 'system', content: 'ignore' },
      { role: 'user', content: 'first user prompt' },
      { role: 'assistant', content: 'ignore' },
      { role: 'user', content: [{ type: 'text', text: 'second user prompt' }] },
    ],
  });

  assert.strictEqual(
    extractPrompt('api.example.test', 'application/json', body),
    'first user prompt\nsecond user prompt',
  );
});

test('gate sends proxy context and returns a usable control-plane verdict', async () => {
  let outbound;
  const verdict = await gate({
    host: 'chatgpt.com',
    user: 'proxy-user',
    sourceIp: '10.0.0.9',
    contentType: 'application/json',
    body: JSON.stringify({ prompt: 'Synthetic SSN 524-71-9043' }),
    sentinel: 'http://sentinel.test',
    key: 'proxy-key',
    fetchImpl: async (url, opts) => {
      outbound = { url, headers: opts.headers, body: JSON.parse(opts.body) };
      return jsonResponse(200, { id: 'q_proxy', decision: 'block', status: 'pending' });
    },
  });

  assert.deepStrictEqual(verdict, { id: 'q_proxy', decision: 'block', status: 'pending' });
  assert.strictEqual(outbound.url, 'http://sentinel.test/api/v1/gate');
  assert.strictEqual(outbound.headers['x-api-key'], 'proxy-key');
  assert.strictEqual(outbound.body.destination, 'chatgpt.com');
  assert.strictEqual(outbound.body.source, 'proxy');
  assert.strictEqual(outbound.body.channel, 'submit');
});

test('gate fails closed on timeout, non-ok response, or invalid JSON', async () => {
  const timedOut = await gate({
    host: 'chatgpt.com',
    body: 'synthetic prompt',
    timeoutMs: 10,
    fetchImpl: async (url, opts) => new Promise((resolve, reject) => {
      opts.signal.addEventListener('abort', () => {
        const e = new Error('aborted');
        e.name = 'AbortError';
        reject(e);
      });
    }),
  });
  assert.deepStrictEqual(timedOut, {
    decision: 'block',
    status: 'control_plane_unavailable',
    reason: 'gate_timeout',
  });

  const badStatus = await gate({
    host: 'chatgpt.com',
    body: 'synthetic prompt',
    fetchImpl: async () => jsonResponse(503, { error: 'down' }),
  });
  assert.deepStrictEqual(badStatus, {
    decision: 'block',
    status: 'control_plane_unavailable',
    reason: 'gate_http_503',
  });

  const invalid = await gate({
    host: 'chatgpt.com',
    body: 'synthetic prompt',
    fetchImpl: async () => jsonResponse(200, { status: 'pending' }),
  });
  assert.deepStrictEqual(invalid, {
    decision: 'block',
    status: 'control_plane_unavailable',
    reason: 'gate_invalid_json',
  });
});

test('awaitRelease releases only approved or allowed statuses', async () => {
  const seen = [];
  const sequence = [
    { status: 'pending' },
    { status: 'approved' },
  ];
  const result = await awaitRelease('q_1/needs encoding', {
    sentinel: 'http://sentinel.test',
    key: 'proxy-key',
    intervalMs: 1,
    timeoutMs: 1000,
    sleepImpl: async () => {},
    fetchImpl: async (url, opts) => {
      seen.push({ url, key: opts.headers['x-api-key'] });
      return jsonResponse(200, sequence.shift());
    },
  });

  assert.deepStrictEqual(result, { released: true });
  assert.strictEqual(seen[0].url, 'http://sentinel.test/api/v1/status/q_1%2Fneeds%20encoding');
  assert.strictEqual(seen[0].key, 'proxy-key');
});

test('awaitRelease fails closed on missing id and status API failure', async () => {
  assert.deepStrictEqual(await awaitRelease('', {}), { released: false, reason: 'missing_id' });

  const denied = await awaitRelease('q_denied', {
    fetchImpl: async () => jsonResponse(200, { status: 'denied' }),
  });
  assert.deepStrictEqual(denied, { released: false, reason: 'denied' });

  const down = await awaitRelease('q_down', {
    fetchImpl: async () => jsonResponse(500, { error: 'down' }),
  });
  assert.deepStrictEqual(down, { released: false, reason: 'status_http_500' });
});

test('request timeout bounds invalid values', () => {
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 1 }), 50);
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 999999 }), 120000);
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 'bad' }), 10000);
});
