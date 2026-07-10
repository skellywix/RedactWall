'use strict';
/** Shared limiter service backs AI gateway HTTP rate limiting without raw tokens. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const {
  createRedisLimiterStore,
  createLimiterServer,
  limiterHealth,
  normalizeLimiterInput,
  parseArgs,
  parseRespReplies,
  redisCommand,
  redisUrl,
} = require('../scripts/ai-gateway-rate-limiter');
const { createGatewayServer } = require('../scripts/ai-llm-gateway');

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function requestJson(port, {
  method = 'POST',
  path: requestPath = '/check',
  token = 'limiter-token',
  body = {},
} = {}) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method,
      path: requestPath,
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: text,
          json: () => JSON.parse(text || '{}'),
        });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function requestSlowBody(port, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: '/check',
      headers: {
        authorization: 'Bearer limiter-token',
        'content-type': 'application/json',
        'content-length': '128',
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        settled = true;
        clearTimeout(timer);
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    req.on('error', (err) => {
      if (!settled) reject(err);
    });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(new Error('slow request did not receive an absolute-deadline response'));
    }, timeoutMs);
    req.write('{');
  });
}

function listenNet(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function gatewayRequest(port, {
  token = 'client-token',
  body = { messages: [{ role: 'user', content: 'Summarize public FAQ copy.' }] },
} = {}) {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: '/v1/chat/completions',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        authorization: `Bearer ${token}`,
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
    req.write(payload);
    req.end();
  });
}

function jsonFetchResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

test('shared limiter validates config, health, auth, and bounded hashed input', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-shared-limiter-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const dbPath = path.join(dir, 'limiter.db');
  const parsed = parseArgs(['--port', '4998', '--host', '127.0.0.1', '--store', 'redis', '--db', dbPath, '--redis-url', 'rediss://cache.example.test:6380/2', '--redis-prefix', 'pw:test:', '--redis-timeout-ms', '1500', '--allow-insecure-redis-loopback', '--token', 'limiter-token', '--body-timeout-ms', '3000', '--default-limit', '10', '--default-window-ms', '2000']);
  assert.strictEqual(parsed.port, 4998);
  assert.strictEqual(parsed.storeBackend, 'redis');
  assert.strictEqual(parsed.dbPath, dbPath);
  assert.strictEqual(parsed.redisUrl, 'rediss://cache.example.test:6380/2');
  assert.strictEqual(parsed.redisPrefix, 'pw:test:');
  assert.strictEqual(parsed.redisTimeoutMs, 1500);
  assert.strictEqual(parsed.allowInsecureRedisLoopback, true);
  assert.strictEqual(parsed.token, 'limiter-token');
  assert.strictEqual(parsed.bodyTimeoutMs, 3000);
  assert.strictEqual(parsed.defaultLimit, 10);
  assert.throws(() => normalizeLimiterInput({ key: 'client-token', limit: 1, windowMs: 1000 }), /sha256 hex digest/);

  const server = createLimiterServer({
    dbPath,
    token: 'limiter-token',
    defaultLimit: 2,
    defaultWindowMs: 60000,
  });
  const port = await listen(server);
  try {
    const health = await requestJson(port, { method: 'GET', path: '/healthz', token: '', body: '' });
    assert.strictEqual(health.status, 200);
    assert.match(health.body, /redactwall-ai-gateway-rate-limiter/);

    const ready = await requestJson(port, { method: 'GET', path: '/readyz', token: '', body: '' });
    assert.strictEqual(ready.status, 200);
    assert.strictEqual(ready.json().storesRawClientTokens, false);

    const unauth = await requestJson(port, { token: '', body: {} });
    assert.strictEqual(unauth.status, 401);

    const badKey = await requestJson(port, { body: { key: 'client-token', limit: 1, windowMs: 1000 } });
    assert.strictEqual(badKey.status, 400);
    assert.ok(!badKey.body.includes('limiter-token'));

    const key = 'a'.repeat(64);
    const first = await requestJson(port, { body: { key, limit: 1, windowMs: 60000, now: 1000 } });
    assert.strictEqual(first.status, 200);
    assert.deepStrictEqual(first.json(), { ok: true, limit: 1, remaining: 0, resetMs: 60000 });

    const second = await requestJson(port, { body: { key, limit: 1, windowMs: 60000, now: 1001 } });
    assert.strictEqual(second.status, 200);
    assert.strictEqual(second.json().ok, false);
    assert.strictEqual(second.json().remaining, 0);
    assert.ok(!second.body.includes(key.slice(0, 16)));
  } finally {
    await close(server);
  }

  assert.strictEqual((await limiterHealth({ stats: () => ({ entries: 0 }) }, { token: 'limiter-token' })).status, 'ready');
  assert.strictEqual((await limiterHealth({ stats: () => ({ entries: 0 }) }, {})).status, 'attention');
});

test('redis limiter backend uses prefixed hashed keys and supports async health checks', async () => {
  const key = 'b'.repeat(64);
  const calls = [];
  let count = 0;
  const parsedUrl = redisUrl({ redisUrl: 'rediss://user:pass@cache.example.test:6380/2' });
  assert.strictEqual(parsedUrl.tls, true);
  assert.strictEqual(parsedUrl.host, 'cache.example.test');
  assert.strictEqual(parsedUrl.port, 6380);
  assert.strictEqual(parsedUrl.username, 'user');
  assert.strictEqual(parsedUrl.password, 'pass');
  assert.strictEqual(parsedUrl.db, '2');

  const parsedResp = parseRespReplies(Buffer.from('+OK\r\n*2\r\n:3\r\n$4\r\n1234\r\n'), 2);
  assert.deepStrictEqual(parsedResp, { replies: ['OK', [3, '1234']], complete: true });

  const store = createRedisLimiterStore({
    redisUrl: 'rediss://cache.example.test:6379/0',
    redisPrefix: 'pw:test prefix:',
    redisCommand: async (args) => {
      calls.push(args);
      if (args[0] === 'PING') return 'PONG';
      assert.strictEqual(args[0], 'EVAL');
      assert.strictEqual(args[2], '1');
      assert.strictEqual(args[3], `pw:testprefix:${key}`);
      assert.strictEqual(args[4], '60000');
      count += 1;
      return [count, 60000 - count];
    },
  });
  const ready = await limiterHealth(store, { token: 'limiter-token' });
  assert.strictEqual(ready.status, 'ready');
  assert.strictEqual(ready.backend, 'redis');

  const first = await store.check({ key, limit: 1, windowMs: 60000, now: 1000 });
  assert.deepStrictEqual(first, { ok: true, limit: 1, remaining: 0, resetMs: 59999 });
  const second = await store.check({ key, limit: 1, windowMs: 60000, now: 1001 });
  assert.strictEqual(second.ok, false);
  assert.strictEqual(second.remaining, 0);
  assert.ok(!JSON.stringify(calls).includes('client-token'));
});

test('shared limiter server can run against an async redis backend without leaking keys', async () => {
  const key = 'c'.repeat(64);
  let count = 0;
  const store = createRedisLimiterStore({
    redisUrl: 'rediss://cache.example.test:6379/0',
    redisPrefix: 'pw:server:',
    redisCommand: async (args) => {
      if (args[0] === 'PING') return 'PONG';
      assert.strictEqual(args[3], `pw:server:${key}`);
      count += 1;
      return [count, 60000];
    },
  });
  const server = createLimiterServer({ store, token: 'limiter-token' });
  const port = await listen(server);
  try {
    const ready = await requestJson(port, { method: 'GET', path: '/readyz', token: '', body: '' });
    assert.strictEqual(ready.status, 200);
    assert.strictEqual(ready.json().backend, 'redis');

    const first = await requestJson(port, { body: { key, limit: 1, windowMs: 60000, now: 1000 } });
    assert.strictEqual(first.status, 200);
    assert.strictEqual(first.json().ok, true);
    const second = await requestJson(port, { body: { key, limit: 1, windowMs: 60000, now: 1001 } });
    assert.strictEqual(second.status, 200);
    assert.strictEqual(second.json().ok, false);
    assert.ok(!second.body.includes(key.slice(0, 16)));
  } finally {
    await close(server);
  }
});

test('redis transport rejects remote cleartext and requires an explicit non-production loopback exception', () => {
  assert.throws(
    () => redisUrl({ redisUrl: 'redis://user:secret@203.0.113.10:6379/0' }),
    /TLS is required for remote Redis/,
  );
  assert.throws(
    () => redisUrl({ redisUrl: 'redis://127.0.0.1:6379/0', nodeEnv: 'development' }),
    /explicit non-production loopback exception/,
  );
  assert.throws(
    () => redisUrl({
      redisUrl: 'redis://127.0.0.1:6379/0',
      nodeEnv: 'production',
      allowInsecureRedisLoopback: true,
    }),
    /disabled in production/,
  );
  const local = redisUrl({
    redisUrl: 'redis://127.0.0.1:6379/0',
    nodeEnv: 'development',
    allowInsecureRedisLoopback: true,
  });
  assert.strictEqual(local.tls, false);
  assert.strictEqual(local.host, '127.0.0.1');
  assert.strictEqual(redisUrl({ redisUrl: 'rediss://user:secret@cache.example.test:6380/0' }).tls, true);
});

test('RESP parser enforces byte, line, bulk, array, nesting, and element limits', () => {
  const valid = parseRespReplies(Buffer.from('*2\r\n:3\r\n$4\r\n1234\r\n'), 1);
  assert.deepStrictEqual(valid, { replies: [[3, '1234']], complete: true });

  assert.throws(
    () => parseRespReplies(Buffer.from('+123456789\r\n'), 1, { maxResponseBytes: 8 }),
    /response exceeds byte limit/,
  );
  assert.throws(
    () => parseRespReplies(Buffer.from('+123456789\r\n'), 1, { maxLineBytes: 8 }),
    /line exceeds byte limit/,
  );
  assert.throws(
    () => parseRespReplies(Buffer.from('$9\r\n123456789\r\n'), 1, { maxBulkBytes: 8 }),
    /bulk string exceeds byte limit/,
  );
  assert.throws(
    () => parseRespReplies(Buffer.from('*3\r\n:1\r\n:2\r\n:3\r\n'), 1, { maxArrayLength: 2 }),
    /array exceeds element limit/,
  );
  assert.throws(
    () => parseRespReplies(Buffer.from('*1\r\n*1\r\n*1\r\n:1\r\n'), 1, { maxDepth: 2 }),
    /nesting exceeds depth limit/,
  );
  assert.throws(
    () => parseRespReplies(Buffer.from('*3\r\n:1\r\n:2\r\n:3\r\n'), 1, { maxElements: 3 }),
    /response exceeds element limit/,
  );
  assert.throws(
    () => parseRespReplies(Buffer.from('$4\r\n1234xx'), 1),
    /bulk string terminator is malformed/,
  );
  assert.throws(
    () => parseRespReplies(Buffer.from(':not-a-number\r\n'), 1),
    /integer is malformed/,
  );
});

test('redis command aborts an oversized streamed response', async (t) => {
  const fakeRedis = net.createServer((socket) => {
    socket.once('data', () => socket.write(`+${'x'.repeat(128)}\r\n`));
  });
  const port = await listenNet(fakeRedis);
  t.after(() => close(fakeRedis));
  await assert.rejects(
    redisCommand(
      { tls: false, host: '127.0.0.1', port, username: '', password: '', db: '' },
      ['PING'],
      { timeoutMs: 1000, maxResponseBytes: 64 },
    ),
    /response exceeds byte limit/,
  );
});

test('redis command accepts a bounded valid response split across network chunks', async (t) => {
  const fakeRedis = net.createServer((socket) => {
    socket.once('data', () => {
      socket.write('+PO');
      setImmediate(() => socket.write('NG\r\n'));
    });
  });
  const port = await listenNet(fakeRedis);
  t.after(() => close(fakeRedis));
  const reply = await redisCommand(
    { tls: false, host: '127.0.0.1', port, username: '', password: '', db: '' },
    ['PING'],
    { timeoutMs: 1000, maxResponseBytes: 64 },
  );
  assert.strictEqual(reply, 'PONG');
});

test('shared limiter enforces an absolute request-body deadline against trickle clients', async () => {
  let checks = 0;
  const store = {
    check() {
      checks += 1;
      return { ok: true, limit: 1, remaining: 0, resetMs: 1000 };
    },
    stats() {
      return { ready: true, entries: 0, checks, store: 'test' };
    },
    close() {},
  };
  const server = createLimiterServer({ store, token: 'limiter-token', bodyTimeoutMs: 100 });
  const port = await listen(server);
  try {
    const startedAt = Date.now();
    const response = await requestSlowBody(port);
    assert.strictEqual(response.status, 408);
    assert.strictEqual(response.headers.connection, 'close');
    assert.match(response.body, /request body deadline exceeded/);
    assert.ok(Date.now() - startedAt < 1500);
    assert.strictEqual(checks, 0);
  } finally {
    await close(server);
  }
});

test('AI gateway can use the shipped shared limiter service across gateway replicas', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-gateway-limiter-integration-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const limiter = createLimiterServer({
    dbPath: path.join(dir, 'limiter.db'),
    token: 'limiter-token',
  });
  const limiterPort = await listen(limiter);
  const limiterUrl = `http://127.0.0.1:${limiterPort}/check`;
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    if (String(url).includes('/api/v1/gate')) return jsonFetchResponse(200, { id: 'q_allowed', decision: 'allow', status: 'allowed' });
    if (String(url).includes('/api/v1/scan-response')) return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
    return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'safe answer' } }] });
  };
  const gatewayOpts = {
    clientToken: 'client-token',
    upstream: 'https://upstream.test',
    rateLimit: 1,
    rateWindowMs: 60000,
    rateLimitStore: 'http',
    rateLimitUrl: limiterUrl,
    rateLimitToken: 'limiter-token',
    rateLimitFetchImpl: globalThis.fetch,
    fetchImpl,
  };
  const firstGateway = createGatewayServer(gatewayOpts);
  const secondGateway = createGatewayServer(gatewayOpts);
  const firstPort = await listen(firstGateway);
  const secondPort = await listen(secondGateway);
  try {
    const first = await gatewayRequest(firstPort);
    assert.strictEqual(first.status, 200);
    assert.strictEqual(first.headers['x-ratelimit-limit'], '1');
    assert.strictEqual(first.headers['x-ratelimit-remaining'], '0');

    const second = await gatewayRequest(secondPort);
    assert.strictEqual(second.status, 429);
    assert.match(second.body, /gateway rate limit exceeded/);
    assert.strictEqual(calls.filter((call) => call.url === 'https://upstream.test/v1/chat/completions').length, 1);
  } finally {
    await close(firstGateway);
    await close(secondGateway);
    await close(limiter);
  }
});
