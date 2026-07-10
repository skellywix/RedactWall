'use strict';
/** AI chat proxy lab reports monitor-only, sanitized evidence. */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const {
  buildMonitorPayload,
  clientEvidenceFromAnalysis,
  createProxyServer,
  main,
  observeAiChatRequest,
  parseArgs,
  postMonitorEvidence,
  safeEvidencePrompt,
  shouldInspectRequest,
} = require('../scripts/ai-chat-dlp-proxy-lab');

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', connection: 'close' },
  });
}

function textResponse(status, body, headers = {}) {
  return new Response(body, {
    status,
    headers,
  });
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function proxyRequest(port, { method = 'POST', path = 'http://chatgpt.com/v1/chat', headers = {}, body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method,
      path,
      headers: {
        host: 'chatgpt.com',
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function rawTcpRequest(port, requestText) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    const chunks = [];
    socket.on('connect', () => socket.write(requestText));
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.on('error', reject);
  });
}

test('monitor payload scans locally and contains no raw prompt text', () => {
  const secret = '524-71-9043';
  const built = buildMonitorPayload({
    host: 'chatgpt.com',
    user: 'analyst@example.test',
    sourceIp: '10.0.0.9',
    contentType: 'application/json',
    body: JSON.stringify({ prompt: `Draft a member note for SSN ${secret}.` }),
  });

  assert.strictEqual(built.destination, 'chatgpt.com');
  assert.strictEqual(built.payload.source, 'proxy');
  assert.strictEqual(built.payload.channel, 'proxy_monitor');
  assert.strictEqual(built.payload.clientOutcome, 'proxy_observed');
  assert.strictEqual(built.payload.clientPreRedacted, true);
  assert.match(built.payload.prompt, /^\[REDACTED:/);
  assert.ok(built.payload.clientFindings.some((f) => f.type === 'US_SSN'));
  assert.ok(!JSON.stringify(built).includes(secret));
});

test('monitor payload surfaces encoded sensitive and opaque content without claiming it is clean', () => {
  const encodedSsn = Buffer.from('SSN 524-71-9043').toString('base64');
  const opaqueBinary = Buffer.from([0, 255, 1, 254, 2, 253, 3, 252, 4, 251, 5, 250]).toString('base64');

  const sensitive = buildMonitorPayload({
    host: 'chatgpt.com',
    contentType: 'application/json',
    body: JSON.stringify({ prompt: encodedSsn }),
  });
  assert.match(sensitive.payload.prompt, /^\[REDACTED:/);
  assert.ok(sensitive.payload.clientFindings.some((finding) => finding.type === 'US_SSN'));
  assert.ok(!JSON.stringify(sensitive).includes(encodedSsn));

  const opaque = buildMonitorPayload({
    host: 'chatgpt.com',
    contentType: 'application/json',
    body: JSON.stringify({ prompt: opaqueBinary }),
  });
  assert.strictEqual(opaque.payload.prompt, '[REDACTED: OPAQUE_ENCODED_CONTENT]');
  assert.deepStrictEqual(opaque.payload.clientCategories, [{ category: 'OPAQUE_ENCODED_CONTENT', score: 1 }]);
  assert.deepStrictEqual(opaque.evidence.categories, ['OPAQUE_ENCODED_CONTENT']);
  assert.ok(!JSON.stringify(opaque).includes(opaqueBinary));
});

test('monitor payload handles safe prompts, category-only evidence, and CLI args', () => {
  const safe = buildMonitorPayload({
    host: 'chatgpt.com',
    contentType: 'application/json',
    body: JSON.stringify({ prompt: 'Summarize public product copy.' }),
    sensor: { name: 'custom_proxy', version: '1.2.3', platform: 'lab' },
  });
  assert.strictEqual(safe.payload.prompt, '[proxy observed] chatgpt.com');
  assert.strictEqual(safe.payload.sensor.name, 'custom_proxy');

  const empty = buildMonitorPayload({
    host: 'chatgpt.com',
    contentType: 'application/json',
    body: JSON.stringify({ messages: [] }),
  });
  assert.deepStrictEqual(empty, { destination: 'chatgpt.com', payload: null, reason: 'no_prompt' });

  assert.strictEqual(safeEvidencePrompt('chatgpt.com', {
    findings: [],
    categories: [{ category: 'CONFIDENTIAL_BUSINESS' }],
  }), '[REDACTED: CONFIDENTIAL_BUSINESS]');
  assert.deepStrictEqual(clientEvidenceFromAnalysis({
    categories: [{ category: 'CONFIDENTIAL_BUSINESS', score: 0.84 }],
  }).clientCategories, [{ category: 'CONFIDENTIAL_BUSINESS', score: 0.84 }]);
  assert.deepStrictEqual(parseArgs(['--sample', '--port', '4182', '--host', 'claude.ai', '--prompt', 'hello', '--redactwall', 'http://local', '--key', 'k']), {
    sample: true,
    port: 4182,
    host: 'claude.ai',
    prompt: 'hello',
    redactwall: 'http://local',
    key: 'k',
  });
});

test('proxy observer is AI-domain and body-method scoped', async () => {
  assert.strictEqual(shouldInspectRequest({ method: 'POST', host: 'chatgpt.com' }), true);
  assert.strictEqual(shouldInspectRequest({ method: 'GET', host: 'chatgpt.com' }), false);
  assert.strictEqual(shouldInspectRequest({ method: 'POST', host: 'example.com' }), false);

  let called = false;
  const result = await observeAiChatRequest({
    method: 'POST',
    host: 'example.com',
    body: JSON.stringify({ prompt: 'safe prompt' }),
  }, {
    fetchImpl: async () => {
      called = true;
      return jsonResponse(200, {});
    },
  });

  assert.strictEqual(called, false);
  assert.deepStrictEqual(result, {
    forward: true,
    monitored: false,
    destination: 'example.com',
    reason: 'not_ai_chat_body_request',
  });

  const noPrompt = await observeAiChatRequest({
    method: 'POST',
    url: 'http://claude.ai/v1/messages',
    headers: { 'content-type': 'application/json', 'x-redactwall-user': 'proxy-user@example.test' },
    body: JSON.stringify({ messages: [] }),
  }, {
    fetchImpl: async () => {
      called = true;
      return jsonResponse(200, {});
    },
  });
  assert.strictEqual(called, false);
  assert.deepStrictEqual(noPrompt, {
    forward: true,
    monitored: false,
    destination: 'claude.ai',
    reason: 'no_prompt',
  });
});

test('proxy observer posts only redacted evidence and still forwards on control-plane failure', async () => {
  const secret = '524-71-9043';
  let outbound;
  const observed = await observeAiChatRequest({
    method: 'POST',
    host: 'claude.ai',
    contentType: 'application/json',
    body: JSON.stringify({ messages: [{ role: 'user', content: `Member SSN ${secret}` }] }),
    user: 'analyst@example.test',
    sourceIp: '10.0.0.9',
  }, {
    redactwall: 'https://redactwall.test',
    key: 'proxy-key',
    fetchImpl: async (url, opts) => {
      outbound = { url, headers: opts.headers, redirect: opts.redirect, body: JSON.parse(opts.body) };
      return jsonResponse(200, { id: 'q_proxy_monitor', decision: 'log', status: 'proxy_observed', riskScore: 30 });
    },
  });

  assert.strictEqual(observed.forward, true);
  assert.strictEqual(observed.monitored, true);
  assert.strictEqual(observed.controlPlane.ok, true);
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
  assert.strictEqual(outbound.headers['x-api-key'], 'proxy-key');
  assert.strictEqual(outbound.redirect, 'error');
  assert.strictEqual(outbound.body.destination, 'claude.ai');
  assert.strictEqual(outbound.body.clientOutcome, 'proxy_observed');
  assert.ok(!JSON.stringify(outbound).includes(secret));
  assert.ok(!JSON.stringify(observed).includes(secret));

  const failed = await observeAiChatRequest({
    method: 'POST',
    host: 'chatgpt.com',
    contentType: 'application/json',
    body: JSON.stringify({ prompt: `Member SSN ${secret}` }),
  }, {
    fetchImpl: async () => {
      throw new Error('down');
    },
  });
  assert.strictEqual(failed.forward, true);
  assert.strictEqual(failed.monitored, true);
  assert.strictEqual(failed.controlPlane.ok, false);
  assert.strictEqual(failed.controlPlane.reason, 'gate_unreachable');
  assert.ok(!JSON.stringify(failed).includes(secret));

  const timeout = new Error('slow gate');
  timeout.code = 'REDACTWALL_TIMEOUT';
  const timedOut = await postMonitorEvidence({ prompt: '[proxy observed] chatgpt.com' }, {
    fetchImpl: async () => {
      throw timeout;
    },
  });
  assert.deepStrictEqual(timedOut, { ok: false, status: 0, reason: 'gate_timeout' });
  assert.deepStrictEqual(await postMonitorEvidence({}, { fetchImpl: null }), {
    ok: false,
    status: 0,
    reason: 'fetch_unavailable',
  });

  let cleartextCalled = false;
  assert.deepStrictEqual(await postMonitorEvidence({}, {
    redactwall: 'http://control-plane.test',
    key: 'proxy-key',
    fetchImpl: async () => { cleartextCalled = true; },
  }), { ok: false, status: 0, reason: 'insecure_control_plane_url' });
  assert.strictEqual(cleartextCalled, false);

  const oversized = await postMonitorEvidence({ prompt: '[proxy observed] chatgpt.com' }, {
    maxResponseBytes: 8,
    fetchImpl: async () => jsonResponse(200, { id: 'response-is-too-large' }),
  });
  assert.deepStrictEqual(oversized, { ok: false, status: 0, reason: 'gate_unreachable' });

  const remoteSecret = 'remote-secret-must-not-leak';
  const sanitizedError = await postMonitorEvidence({ prompt: '[proxy observed] chatgpt.com' }, {
    fetchImpl: async () => jsonResponse(500, {
      error: remoteSecret,
      reasons: [remoteSecret],
      findings: [{ type: 'SECRET_KEY', masked: remoteSecret }],
    }),
  });
  assert.strictEqual(JSON.stringify(sanitizedError).includes(remoteSecret), false);
  assert.strictEqual(sanitizedError.body.error, 'control_plane_error');
});

test('cleartext lab proxy forwards original traffic while posting only sanitized monitor evidence', async () => {
  const secret = '524-71-9043';
  const calls = [];
  const server = createProxyServer({
    redactwall: 'https://control-plane.test',
    key: 'proxy-key',
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url, opts });
      if (String(url).includes('/api/v1/gate')) {
        return jsonResponse(200, { id: 'q_proxy', decision: 'log', status: 'proxy_observed', riskScore: 29 });
      }
      return textResponse(201, 'upstream ok', { 'x-upstream': 'ok', connection: 'should-strip' });
    },
  });
  const port = await listen(server);
  try {
    const res = await proxyRequest(port, {
      path: 'http://chatgpt.com/v1/chat/completions',
      headers: {
        connection: 'close',
        'proxy-authorization': 'Basic should-not-forward',
      },
      body: JSON.stringify({ prompt: `Member SSN ${secret}` }),
    });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body, 'upstream ok');
    const monitorCall = calls.find((call) => call.url === 'https://control-plane.test/api/v1/gate');
    const upstreamCall = calls.find((call) => call.url === 'http://chatgpt.com/v1/chat/completions');
    assert.ok(monitorCall);
    assert.ok(upstreamCall);
    assert.strictEqual(monitorCall.opts.headers['x-api-key'], 'proxy-key');
    assert.ok(!monitorCall.opts.body.includes(secret));
    assert.ok(upstreamCall.opts.body.includes(secret), 'monitor-only proxy must not mutate upstream request body');
    assert.strictEqual(upstreamCall.opts.headers.connection, undefined);
    assert.strictEqual(upstreamCall.opts.headers['proxy-authorization'], undefined);
    assert.strictEqual(upstreamCall.opts.headers['content-type'], 'application/json');
  } finally {
    await close(server);
  }
});

test('cleartext lab proxy skips truncated monitoring and returns upstream failures cleanly', async () => {
  const calls = [];
  const truncatedServer = createProxyServer({
    maxBodyBytes: 8,
    redactwall: 'https://control-plane.test',
    fetchImpl: async (url, opts = {}) => {
      calls.push({ url, opts });
      return textResponse(200, 'forwarded');
    },
  });
  const truncatedPort = await listen(truncatedServer);
  try {
    const res = await proxyRequest(truncatedPort, {
      path: 'http://chatgpt.com/v1/chat/completions',
      body: JSON.stringify({ prompt: 'Member SSN 524-71-9043 should be truncated.' }),
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body, 'forwarded');
    assert.strictEqual(calls.some((call) => String(call.url).includes('/api/v1/gate')), false);
  } finally {
    await close(truncatedServer);
  }

  const failingServer = createProxyServer({
    fetchImpl: async () => {
      throw new Error('upstream down');
    },
  });
  const failingPort = await listen(failingServer);
  try {
    const res = await proxyRequest(failingPort, {
      path: 'http://example.com/safe',
      body: JSON.stringify({ prompt: '' }),
    });
    assert.strictEqual(res.status, 502);
    assert.match(res.body, /upstream unavailable/);
  } finally {
    await close(failingServer);
  }

  const oversizedServer = createProxyServer({
    maxUpstreamResponseBytes: 8,
    fetchImpl: async () => textResponse(200, 'response-is-too-large'),
  });
  const oversizedPort = await listen(oversizedServer);
  try {
    const res = await proxyRequest(oversizedPort, {
      method: 'GET',
      path: 'http://example.com/safe',
    });
    assert.strictEqual(res.status, 502);
    assert.match(res.body, /upstream unavailable/);
  } finally {
    await close(oversizedServer);
  }
});

test('cleartext lab proxy rejects unsupported connect, invalid targets, and missing upstream fetch', async () => {
  const server = createProxyServer();
  const port = await listen(server);
  const originalFetch = globalThis.fetch;
  try {
    const connectResponse = await rawTcpRequest(port, 'CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n');
    assert.match(connectResponse, /501 Not Implemented/);
    assert.match(connectResponse, /CONNECT is outside this monitor-only lab slice/);

    const invalid = await proxyRequest(port, {
      method: 'GET',
      path: '/safe',
      headers: { host: '[bad' },
    });
    assert.strictEqual(invalid.status, 400);
    assert.match(invalid.body, /invalid proxy target/);

    globalThis.fetch = undefined;
    const noFetch = await proxyRequest(port, {
      method: 'GET',
      path: 'http://example.com/safe',
    });
    assert.strictEqual(noFetch.status, 502);
    assert.match(noFetch.body, /upstream fetch unavailable/);
  } finally {
    globalThis.fetch = originalFetch;
    await close(server);
  }
});

test('cli main supports sample mode and returns a closeable lab server', async () => {
  let output = '';
  const io = { stdout: { write: (text) => { output += text; } } };
  await main(['--sample', '--host', 'example.com', '--prompt', 'safe public prompt'], io);
  const sample = JSON.parse(output);
  assert.strictEqual(sample.forward, true);
  assert.strictEqual(sample.monitored, false);
  assert.strictEqual(sample.destination, 'example.com');

  output = '';
  const server = await main(['--port', '0', '--redactwall', 'https://control-plane.test', '--key', 'proxy-key'], io);
  try {
    await new Promise((resolve) => server.listening ? resolve() : server.once('listening', resolve));
    assert.match(output, /RedactWall AI chat proxy lab listening/);
  } finally {
    await close(server);
  }
});
