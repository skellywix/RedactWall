'use strict';
/** Proxy/ICAP bridge must fail closed when the control plane is unavailable. */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const {
  extractPrompt,
  gate,
  awaitRelease,
  requestTimeoutMs,
  createIcapServer,
  decodeChunked,
} = require('../scripts/squid-icap-bridge');

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
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
  assert.strictEqual(
    extractPrompt('api.example.test', 'application/json', JSON.stringify({ input: 'single input prompt' })),
    'single input prompt',
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
    redactwall: 'https://redactwall.test',
    key: 'proxy-key',
    fetchImpl: async (url, opts) => {
      outbound = { url, headers: opts.headers, body: JSON.parse(opts.body) };
      return jsonResponse(200, { id: 'q_proxy', decision: 'block', status: 'pending' });
    },
  });

  assert.deepStrictEqual(verdict, { id: 'q_proxy', decision: 'block', status: 'pending' });
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
  assert.strictEqual(outbound.headers['x-api-key'], 'proxy-key');
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

  const malformedJson = await gate({
    host: 'chatgpt.com',
    body: 'synthetic prompt',
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new Error('not json');
      },
    }),
  });
  assert.deepStrictEqual(malformedJson, {
    decision: 'block',
    status: 'control_plane_unavailable',
    reason: 'gate_invalid_json',
  });
});

test('gate bounds stalled and oversized control-plane response bodies', async () => {
  let cancelled = 0;
  const stalled = new Response(new ReadableStream({
    cancel() { cancelled += 1; },
  }), { status: 200, headers: { 'content-type': 'application/json' } });
  const timedOutBody = await gate({
    host: 'chatgpt.com',
    body: 'synthetic prompt',
    timeoutMs: 10,
    fetchImpl: async (_url, opts) => {
      assert.strictEqual(opts.redirect, 'error');
      return stalled;
    },
  });
  assert.deepStrictEqual(timedOutBody, {
    decision: 'block',
    status: 'control_plane_unavailable',
    reason: 'gate_invalid_json',
  });
  assert.strictEqual(cancelled, 1);

  const oversized = await gate({
    host: 'chatgpt.com',
    body: 'synthetic prompt',
    fetchImpl: async () => jsonResponse(200, { padding: 'x'.repeat(600 * 1024) }),
  });
  assert.deepStrictEqual(oversized, {
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
    releaseToken: 'release-token-unit',
    redactwall: 'https://redactwall.test',
    key: 'proxy-key',
    intervalMs: 1,
    timeoutMs: 1000,
    sleepImpl: async () => {},
    fetchImpl: async (url, opts) => {
      seen.push({ url, key: opts.headers['x-api-key'], releaseToken: opts.headers['x-release-token'] });
      return jsonResponse(200, sequence.shift());
    },
  });

  assert.deepStrictEqual(result, { released: true });
  assert.strictEqual(seen[0].url, 'https://redactwall.test/api/v1/status/q_1%2Fneeds%20encoding');
  assert.strictEqual(seen[0].key, 'proxy-key');
  assert.strictEqual(seen[0].releaseToken, 'release-token-unit');
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

  const unreachable = await awaitRelease('q_unreachable', {
    fetchImpl: async () => {
      throw new Error('network down');
    },
  });
  assert.deepStrictEqual(unreachable, { released: false, reason: 'status_unreachable' });
});

test('awaitRelease times out pending release decisions', async () => {
  const result = await awaitRelease('q_pending', {
    timeoutMs: 20,
    intervalMs: 5,
    sleepImpl: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    fetchImpl: async () => jsonResponse(200, { status: 'pending' }),
  });

  assert.deepStrictEqual(result, { released: false, reason: 'timeout' });
});

test('request timeout bounds invalid values', () => {
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 1 }), 50);
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 999999 }), 120000);
  assert.strictEqual(requestTimeoutMs({ timeoutMs: 'bad' }), 10000);
});

// ---------------------------------------------------------------------------
// ICAP server (RFC 3507 subset) driven over a real socket
// ---------------------------------------------------------------------------

const SYNTHETIC_SSN = '524-71-9043';

test('decodeChunked handles split, terminated, and over-limit bodies', () => {
  const body = Buffer.from('5\r\nhello\r\n0\r\n\r\n', 'latin1');
  const done = decodeChunked(body, 0, 1024);
  assert.strictEqual(done.state, 'done');
  assert.strictEqual(done.body.toString(), 'hello');
  assert.strictEqual(done.end, body.length);

  assert.strictEqual(decodeChunked(Buffer.from('5\r\nhel', 'latin1'), 0, 1024).state, 'need_more');
  assert.strictEqual(decodeChunked(Buffer.from('fffff\r\n', 'latin1'), 0, 1024).state, 'too_large');
  assert.strictEqual(decodeChunked(Buffer.from('zz\r\n', 'latin1'), 0, 1024).state, 'error');
});

function startControlPlaneStub() {
  const requests = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.method === 'POST' && req.url === '/api/v1/gate') {
        const body = JSON.parse(raw || '{}');
        requests.push(body);
        res.end(JSON.stringify(stubVerdict(String(body.prompt || ''))));
      } else if (req.url.startsWith('/api/v1/status/')) {
        res.end(JSON.stringify({ status: 'approved' }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, url: `http://127.0.0.1:${server.address().port}`, requests });
    });
  });
}

function stubVerdict(prompt) {
  if (/\d{3}-\d{2}-\d{4}/.test(prompt)) return { id: 'q_ssn_block', decision: 'block', status: 'blocked' };
  if (prompt.includes('HOLDME')) return { id: 'q_hold', decision: 'block', status: 'pending', releaseToken: 'rt_hold' };
  return { decision: 'allow', status: 'allowed' };
}

function startBridge(opts = {}) {
  const logs = [];
  const io = { stdout: { write: (line) => logs.push(String(line)) } };
  const server = createIcapServer({ key: 'test-key', io, ...opts });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, logs }));
  });
}

function icapResponseComplete(text) {
  const headerEnd = text.indexOf('\r\n\r\n');
  if (headerEnd === -1) return false;
  const head = text.slice(0, headerEnd);
  if (/^ICAP\/1\.0 (204|4\d\d)/.test(head)) return true;
  if (/Encapsulated:[^\r\n]*null-body=0/i.test(head)) return true;
  return /\r\n0\r\n\r\n$/.test(text);
}

function icapExchange(port, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => socket.write(payload));
    let data = '';
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(guard);
      socket.destroy();
      resolve(data);
    };
    const guard = setTimeout(finish, 5000);
    socket.on('data', (chunk) => {
      data += chunk.toString('latin1');
      if (icapResponseComplete(data)) finish();
    });
    socket.on('close', finish);
    socket.on('error', (err) => { if (!settled) { settled = true; clearTimeout(guard); reject(err); } });
  });
}

function reqmodMessage({ host = 'chatgpt.com', prompt, body, allow204 = true } = {}) {
  const httpBody = body !== undefined ? body : JSON.stringify({ prompt });
  const httpReq = [
    `POST https://${host}/backend-api/conversation HTTP/1.1`,
    `Host: ${host}`,
    'Content-Type: application/json',
    `Content-Length: ${Buffer.byteLength(httpBody)}`,
    '',
    '',
  ].join('\r\n');
  const chunked = `${Buffer.byteLength(httpBody).toString(16)}\r\n${httpBody}\r\n0\r\n\r\n`;
  const head = [
    'REQMOD icap://127.0.0.1/reqmod ICAP/1.0',
    'Host: 127.0.0.1',
    'X-Client-IP: 10.0.0.9',
    ...(allow204 ? ['Allow: 204'] : []),
    `Encapsulated: req-hdr=0, req-body=${Buffer.byteLength(httpReq)}`,
    '',
    '',
  ].join('\r\n');
  return head + httpReq + chunked;
}

test('ICAP server end-to-end: OPTIONS, allow, hold-release, block, and hygiene', async (t) => {
  const stub = await startControlPlaneStub();
  const bridge = await startBridge({ redactwall: stub.url });
  t.after(() => { bridge.server.close(); bridge.server.destroyConnections(); stub.server.close(); });

  await t.test('OPTIONS handshake advertises REQMOD without Preview', async () => {
    const res = await icapExchange(bridge.port, 'OPTIONS icap://127.0.0.1/reqmod ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n');
    assert.match(res, /^ICAP\/1\.0 200 OK\r\n/);
    assert.match(res, /Methods: REQMOD\r\n/);
    assert.match(res, /Allow: 204\r\n/);
    assert.doesNotMatch(res, /Preview:/);
  });

  await t.test('benign prompt is allowed with ICAP 204', async () => {
    const res = await icapExchange(bridge.port, reqmodMessage({ prompt: 'what is our branch address' }));
    assert.match(res, /^ICAP\/1\.0 204 No Content\r\n/);
  });

  await t.test('benign prompt without Allow: 204 echoes the request back', async () => {
    const res = await icapExchange(bridge.port, reqmodMessage({ prompt: 'hours for the downtown branch', allow204: false }));
    assert.match(res, /^ICAP\/1\.0 200 OK\r\n/);
    assert.match(res, /Encapsulated: req-hdr=0, req-body=\d+\r\n/);
    assert.match(res, /POST https:\/\/chatgpt\.com/);
  });

  await t.test('seeded SSN prompt is replaced with a prompt-free 403 refusal', async () => {
    const res = await icapExchange(bridge.port, reqmodMessage({ prompt: `member ssn is ${SYNTHETIC_SSN}` }));
    assert.match(res, /^ICAP\/1\.0 200 OK\r\n/);
    assert.match(res, /Encapsulated: res-hdr=0, res-body=\d+\r\n/);
    assert.match(res, /HTTP\/1\.1 403 Forbidden\r\n/);
    assert.match(res, /"blocked":true/);
    assert.match(res, /"queryId":"q_ssn_block"/);
    assert.ok(!res.includes(SYNTHETIC_SSN), 'raw SSN must not appear in the ICAP response');
  });

  await t.test('pending verdict waits for release, then allows', async () => {
    const res = await icapExchange(bridge.port, reqmodMessage({ prompt: 'HOLDME please review' }));
    assert.match(res, /^ICAP\/1\.0 204 No Content\r\n/);
  });

  await t.test('gate saw proxy context and bridge logs stay prompt-free', () => {
    const ssnCall = stub.requests.find((r) => String(r.prompt).includes(SYNTHETIC_SSN));
    assert.ok(ssnCall, 'gate should receive the prompt for detection');
    assert.strictEqual(ssnCall.destination, 'chatgpt.com');
    assert.strictEqual(ssnCall.source, 'proxy');
    assert.strictEqual(ssnCall.sourceIp, '10.0.0.9');
    const logText = bridge.logs.join('');
    assert.ok(logText.length > 0, 'bridge should emit log lines');
    assert.ok(!logText.includes(SYNTHETIC_SSN), 'raw SSN must never be logged');
    assert.ok(!logText.includes('HOLDME'), 'prompt text must never be logged');
  });
});

test('ICAP server fails closed when the control plane is down', async (t) => {
  const bridge = await startBridge({ redactwall: 'http://127.0.0.1:9', gateTimeoutMs: 200 });
  t.after(() => { bridge.server.close(); bridge.server.destroyConnections(); });

  const res = await icapExchange(bridge.port, reqmodMessage({ prompt: 'anything at all' }));
  assert.match(res, /HTTP\/1\.1 403 Forbidden\r\n/);
  assert.match(res, /"blocked":true/);
});

test('ICAP server blocks oversized bodies without calling the control plane', async (t) => {
  const stub = await startControlPlaneStub();
  const bridge = await startBridge({ redactwall: stub.url, maxBodyBytes: 2048 });
  t.after(() => { bridge.server.close(); bridge.server.destroyConnections(); stub.server.close(); });

  const res = await icapExchange(bridge.port, reqmodMessage({ body: JSON.stringify({ prompt: 'A'.repeat(4096) }) }));
  assert.match(res, /HTTP\/1\.1 403 Forbidden\r\n/);
  assert.match(res, /"blocked":true/);
  assert.strictEqual(stub.requests.length, 0, 'oversized body must be blocked locally');
});

test('ICAP server rejects malformed input without crashing', async (t) => {
  const bridge = await startBridge({ redactwall: 'http://127.0.0.1:9' });
  t.after(() => { bridge.server.close(); bridge.server.destroyConnections(); });

  const garbage = await icapExchange(bridge.port, 'THIS IS NOT ICAP\r\n\r\n');
  assert.match(garbage, /^ICAP\/1\.0 400 Bad Request\r\n/);

  const httpNotIcap = await icapExchange(bridge.port, 'GET / HTTP/1.1\r\nHost: x\r\n\r\n');
  assert.match(httpNotIcap, /^ICAP\/1\.0 400 Bad Request\r\n/);

  // Server must still answer a well-formed handshake afterwards.
  const options = await icapExchange(bridge.port, 'OPTIONS icap://127.0.0.1/reqmod ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n');
  assert.match(options, /^ICAP\/1\.0 200 OK\r\n/);
});
