'use strict';
/** Shared limiter service backs AI gateway HTTP rate limiting without raw tokens. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {
  createRedisLimiterStore,
  createLimiterServer,
  limiterHealth,
  normalizeLimiterInput,
  parseArgs,
  parseRespReplies,
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
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ 'content-type': 'application/json', ...headers }),
    arrayBuffer: async () => Buffer.from(JSON.stringify(body)),
    json: async () => body,
  };
}

test('shared limiter validates config, health, auth, and bounded hashed input', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-shared-limiter-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const dbPath = path.join(dir, 'limiter.db');
  const parsed = parseArgs(['--port', '4998', '--host', '127.0.0.1', '--store', 'redis', '--db', dbPath, '--redis-url', 'rediss://cache.example.test:6380/2', '--redis-prefix', 'pw:test:', '--redis-timeout-ms', '1500', '--token', 'limiter-token', '--default-limit', '10', '--default-window-ms', '2000']);
  assert.strictEqual(parsed.port, 4998);
  assert.strictEqual(parsed.storeBackend, 'redis');
  assert.strictEqual(parsed.dbPath, dbPath);
  assert.strictEqual(parsed.redisUrl, 'rediss://cache.example.test:6380/2');
  assert.strictEqual(parsed.redisPrefix, 'pw:test:');
  assert.strictEqual(parsed.redisTimeoutMs, 1500);
  assert.strictEqual(parsed.token, 'limiter-token');
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
    assert.match(health.body, /promptwall-ai-gateway-rate-limiter/);

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
    redisUrl: 'redis://cache.example.test:6379/0',
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
    redisUrl: 'redis://cache.example.test:6379/0',
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

test('AI gateway can use the shipped shared limiter service across gateway replicas', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-gateway-limiter-integration-'));
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
    upstream: 'http://upstream.test',
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
    assert.strictEqual(calls.filter((call) => call.url === 'http://upstream.test/v1/chat/completions').length, 1);
  } finally {
    await close(firstGateway);
    await close(secondGateway);
    await close(limiter);
  }
});
