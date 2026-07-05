'use strict';
require('../server/env').loadEnv();
/**
 * Reference shared limiter service for the RedactWall AI LLM Gateway.
 *
 * Run this as a small internal service when gateway replicas need one shared
 * abuse-control counter. It accepts only hashed limiter keys from the gateway
 * and stores no raw client tokens, prompts, users, or destinations.
 */
const http = require('node:http');
const net = require('node:net');
const tls = require('node:tls');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const Database = require('better-sqlite3');

const DEFAULT_PORT = 4183;
const DEFAULT_STORE = process.env.REDACTWALL_RATE_LIMITER_STORE || 'sqlite';
const DEFAULT_DB = process.env.REDACTWALL_RATE_LIMITER_DB || path.join(process.cwd(), 'data', 'gateway-shared-rate-limiter.db');
const DEFAULT_REDIS_URL = process.env.REDACTWALL_RATE_LIMITER_REDIS_URL || '';
const DEFAULT_REDIS_PREFIX = process.env.REDACTWALL_RATE_LIMITER_REDIS_PREFIX || 'redactwall:gateway:rl:';
const DEFAULT_REDIS_TIMEOUT_MS = 2000;
const DEFAULT_TOKEN = process.env.REDACTWALL_RATE_LIMITER_TOKEN || process.env.REDACTWALL_GATEWAY_RATE_LIMIT_TOKEN || '';
const DEFAULT_MAX_BODY_BYTES = 16 * 1024;
const DEFAULT_MAX_LIMIT = 100000;
const DEFAULT_MAX_WINDOW_MS = 24 * 60 * 60 * 1000;
const REDIS_LIMITER_SCRIPT = [
  'local window = tonumber(ARGV[1])',
  "local count = redis.call('INCR', KEYS[1])",
  "if count == 1 then redis.call('PEXPIRE', KEYS[1], window) end",
  "local ttl = redis.call('PTTL', KEYS[1])",
  "if ttl < 0 then redis.call('PEXPIRE', KEYS[1], window); ttl = window end",
  'return {count, ttl}',
].join('\n');

function boundedInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function safeText(value, fallback = '', max = 160) {
  const text = String(value || '').replace(/[\r\n\t]/g, ' ').trim();
  return (text || fallback).slice(0, max);
}

function limiterStoreMode(opts = {}) {
  const raw = opts.storeBackend || opts.storeMode || opts.limiterStore || DEFAULT_STORE;
  const mode = safeText(raw, 'sqlite', 32).toLowerCase();
  if (!mode || mode === 'sqlite' || mode === 'database') return 'sqlite';
  if (mode === 'redis' || mode === 'valkey') return 'redis';
  throw new Error('unsupported rate limiter store');
}

function bearerToken(value = '') {
  const match = String(value || '').match(/^\s*Bearer\s+(.+?)\s*$/i);
  return match ? match[1] : '';
}

function constantTimeEqual(a, b) {
  const left = String(a || '');
  const right = String(b || '');
  if (!left || !right || left.length > 4096 || right.length > 4096) return false;
  const length = Math.max(left.length, right.length);
  const leftBuffer = Buffer.alloc(length);
  const rightBuffer = Buffer.alloc(length);
  Buffer.from(left).copy(leftBuffer);
  Buffer.from(right).copy(rightBuffer);
  return left.length === right.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function configuredToken(opts = {}) {
  return String(opts.token || DEFAULT_TOKEN || '').trim();
}

function authenticate(req, opts = {}) {
  const expected = configuredToken(opts);
  if (!expected && opts.allowInsecureDev === true) return { ok: true };
  if (!expected) return { ok: false, status: 503, error: 'rate limiter token not configured' };
  const supplied = bearerToken(req.headers.authorization || '');
  if (!supplied) return { ok: false, status: 401, error: 'missing rate limiter token' };
  if (!constantTimeEqual(supplied, expected)) return { ok: false, status: 401, error: 'invalid rate limiter token' };
  return { ok: true };
}

function ensureParent(file) {
  if (file && file !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
}

function openLimiterDatabase(dbPath = DEFAULT_DB) {
  const target = String(dbPath || '').trim();
  if (!target) throw new Error('rate limiter database path is required');
  ensureParent(target);
  const db = new Database(target);
  db.pragma('busy_timeout = 5000');
  if (target !== ':memory:') db.pragma('journal_mode = WAL');
  db.exec(`CREATE TABLE IF NOT EXISTS gateway_shared_rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`);
  return db;
}

function normalizeLimiterInput(input = {}, opts = {}) {
  const key = safeText(input.key, '', 128).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(key)) throw new Error('key must be a sha256 hex digest');
  const limit = boundedInt(input.limit, boundedInt(opts.defaultLimit, 60, 1, DEFAULT_MAX_LIMIT), 1, boundedInt(opts.maxLimit, DEFAULT_MAX_LIMIT, 1, DEFAULT_MAX_LIMIT));
  const windowMs = boundedInt(input.windowMs, boundedInt(opts.defaultWindowMs, 60000, 1000, DEFAULT_MAX_WINDOW_MS), 1000, boundedInt(opts.maxWindowMs, DEFAULT_MAX_WINDOW_MS, 1000, DEFAULT_MAX_WINDOW_MS));
  const now = boundedInt(input.now, Date.now(), 0, Number.MAX_SAFE_INTEGER);
  return { key, limit, windowMs, now };
}

function createLimiterStore(opts = {}) {
  return limiterStoreMode(opts) === 'redis' ? createRedisLimiterStore(opts) : createSqliteLimiterStore(opts);
}

function createSqliteLimiterStore(opts = {}) {
  const db = opts.db || openLimiterDatabase(opts.dbPath || DEFAULT_DB);
  const upsert = db.prepare(`INSERT INTO gateway_shared_rate_limits (key, count, reset_at, updated_at)
    VALUES (@key, 1, @resetAt, @now)
    ON CONFLICT(key) DO UPDATE SET
      count = CASE WHEN gateway_shared_rate_limits.reset_at <= excluded.updated_at THEN 1 ELSE gateway_shared_rate_limits.count + 1 END,
      reset_at = CASE WHEN gateway_shared_rate_limits.reset_at <= excluded.updated_at THEN excluded.reset_at ELSE gateway_shared_rate_limits.reset_at END,
      updated_at = excluded.updated_at
    RETURNING count, reset_at`);
  const cleanupExpired = db.prepare('DELETE FROM gateway_shared_rate_limits WHERE reset_at < ?');
  const countRows = db.prepare('SELECT COUNT(*) AS count FROM gateway_shared_rate_limits');
  let checks = 0;
  return {
    store: 'sqlite',
    check(input) {
      const normalized = normalizeLimiterInput(input, opts);
      const row = upsert.get({
        key: normalized.key,
        resetAt: normalized.now + normalized.windowMs,
        now: normalized.now,
      });
      checks += 1;
      if (checks % boundedInt(opts.cleanupEvery, 100, 1, 100000) === 0) {
        cleanupExpired.run(normalized.now - normalized.windowMs);
      }
      const count = Number(row && row.count) || 0;
      const resetAt = Number(row && row.reset_at) || normalized.now + normalized.windowMs;
      return {
        ok: count <= normalized.limit,
        limit: normalized.limit,
        remaining: Math.max(0, normalized.limit - count),
        resetMs: Math.max(0, resetAt - normalized.now),
      };
    },
    stats() {
      return { entries: Number(countRows.get().count) || 0, checks, store: 'sqlite' };
    },
    close() {
      if (opts.db) return;
      db.close();
    },
  };
}

function redisUrl(opts = {}) {
  const raw = String(opts.redisUrl || DEFAULT_REDIS_URL || '').trim();
  if (!raw) throw new Error('rate limiter redis url is required');
  const url = new URL(raw);
  if (!['redis:', 'rediss:'].includes(url.protocol)) throw new Error('rate limiter redis url must use redis or rediss');
  return {
    tls: url.protocol === 'rediss:',
    host: url.hostname || '127.0.0.1',
    port: Number(url.port || 6379),
    username: decodeURIComponent(url.username || ''),
    password: decodeURIComponent(url.password || ''),
    db: String(url.pathname || '').replace(/^\/+/, ''),
  };
}

function encodeRedisCommand(args = []) {
  let out = `*${args.length}\r\n`;
  for (const arg of args) {
    const text = String(arg ?? '');
    out += `$${Buffer.byteLength(text)}\r\n${text}\r\n`;
  }
  return out;
}

function incompleteResp() {
  const err = new Error('incomplete redis response');
  err.code = 'RESP_INCOMPLETE';
  return err;
}

function parseRespReplies(buffer, expectedReplies) {
  let offset = 0;
  const readLine = () => {
    const end = buffer.indexOf('\r\n', offset, 'utf8');
    if (end === -1) throw incompleteResp();
    const value = buffer.slice(offset, end).toString('utf8');
    offset = end + 2;
    return value;
  };
  const ensure = (n) => {
    if (offset + n > buffer.length) throw incompleteResp();
  };
  const parseOne = () => {
    ensure(1);
    const type = String.fromCharCode(buffer[offset]);
    offset += 1;
    if (type === '+') return readLine();
    if (type === ':') return Number(readLine());
    if (type === '-') {
      const err = new Error(`redis error: ${safeText(readLine(), 'command failed', 80)}`);
      err.code = 'REDIS_ERROR';
      throw err;
    }
    if (type === '$') {
      const length = Number(readLine());
      if (length === -1) return null;
      ensure(length + 2);
      const value = buffer.slice(offset, offset + length).toString('utf8');
      offset += length + 2;
      return value;
    }
    if (type === '*') {
      const length = Number(readLine());
      if (length === -1) return null;
      const values = [];
      for (let i = 0; i < length; i += 1) values.push(parseOne());
      return values;
    }
    const err = new Error('unsupported redis response');
    err.code = 'REDIS_ERROR';
    throw err;
  };
  const replies = [];
  while (offset < buffer.length && replies.length < expectedReplies) replies.push(parseOne());
  return { replies, complete: replies.length >= expectedReplies };
}

function redisCommand(config, args, opts = {}) {
  const timeoutMs = boundedInt(opts.timeoutMs, DEFAULT_REDIS_TIMEOUT_MS, 100, 30000);
  const commands = [];
  if (config.password && config.username) commands.push(['AUTH', config.username, config.password]);
  else if (config.password) commands.push(['AUTH', config.password]);
  if (config.db) commands.push(['SELECT', config.db]);
  commands.push(args);
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = (config.tls ? tls : net).connect({
      host: config.host,
      port: config.port,
      servername: config.tls ? config.host : undefined,
    });
    const chunks = [];
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err) reject(err);
      else resolve(value);
    };
    const timer = setTimeout(() => finish(new Error('redis limiter timeout')), timeoutMs);
    socket.on('connect', () => {
      socket.write(commands.map(encodeRedisCommand).join(''));
    });
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      try {
        const parsed = parseRespReplies(Buffer.concat(chunks), commands.length);
        if (parsed.complete) finish(null, parsed.replies[parsed.replies.length - 1]);
      } catch (err) {
        if (err && err.code === 'RESP_INCOMPLETE') return;
        finish(err);
      }
    });
    socket.on('error', (err) => finish(err));
    socket.on('end', () => {
      if (!settled) finish(new Error('redis limiter connection closed'));
    });
  });
}

function redisKeyPrefix(opts = {}) {
  const raw = safeText(opts.redisPrefix || DEFAULT_REDIS_PREFIX, DEFAULT_REDIS_PREFIX, 160);
  return raw.replace(/[^A-Za-z0-9:._-]/g, '').slice(0, 160) || DEFAULT_REDIS_PREFIX;
}

function backendUnavailable(message) {
  const err = new Error(message);
  err.status = 503;
  return err;
}

function createRedisLimiterStore(opts = {}) {
  const config = redisUrl(opts);
  const timeoutMs = boundedInt(opts.redisTimeoutMs, DEFAULT_REDIS_TIMEOUT_MS, 100, 30000);
  const prefix = redisKeyPrefix(opts);
  const command = opts.redisCommand || ((args) => redisCommand(config, args, { timeoutMs }));
  let checks = 0;
  return {
    store: 'redis',
    async check(input) {
      const normalized = normalizeLimiterInput(input, opts);
      try {
        const reply = await command(['EVAL', REDIS_LIMITER_SCRIPT, '1', `${prefix}${normalized.key}`, String(normalized.windowMs)]);
        const count = Number(Array.isArray(reply) ? reply[0] : 0) || 0;
        const resetMs = Number(Array.isArray(reply) ? reply[1] : normalized.windowMs) || normalized.windowMs;
        checks += 1;
        return {
          ok: count <= normalized.limit,
          limit: normalized.limit,
          remaining: Math.max(0, normalized.limit - count),
          resetMs: Math.max(0, resetMs),
        };
      } catch {
        throw backendUnavailable('redis rate limiter unavailable');
      }
    },
    async health() {
      try {
        const pong = await command(['PING']);
        return { ready: /^PONG$/i.test(String(pong || '')), entries: 0, checks, store: 'redis' };
      } catch {
        return { ready: false, entries: 0, checks, store: 'redis' };
      }
    },
    stats() {
      return { entries: 0, checks, store: 'redis' };
    },
    close() {},
  };
}

function jsonResponse(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

function collectBody(req, maxBodyBytes = DEFAULT_MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let truncated = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size <= maxBodyBytes) chunks.push(chunk);
      else truncated = true;
    });
    req.on('end', () => resolve({ body: Buffer.concat(chunks), truncated }));
    req.on('error', reject);
  });
}

function parseJson(buffer) {
  try {
    return { ok: true, value: JSON.parse(buffer.toString('utf8') || '{}') };
  } catch {
    return { ok: false, error: 'invalid json' };
  }
}

async function limiterHealth(store, opts = {}) {
  const tokenConfigured = !!configuredToken(opts) || opts.allowInsecureDev === true;
  let backendReady = false;
  let entries = 0;
  let backend = 'unknown';
  try {
    const stats = typeof store.health === 'function' ? await store.health() : store.stats();
    entries = stats.entries;
    backendReady = stats.ready !== false;
    backend = stats.store || backend;
  } catch {}
  return {
    status: tokenConfigured && backendReady ? 'ready' : 'attention',
    service: 'redactwall-ai-gateway-rate-limiter',
    tokenConfigured,
    dbReady: backendReady,
    backendReady,
    backend,
    entries,
    storesRawClientTokens: false,
  };
}

async function handleLimiterRequest(req, res, opts = {}, state = {}) {
  const store = state.store || createLimiterStore(opts);
  state.store = store;
  res.setHeader('x-redactwall-rate-limiter', 'ai-gateway');

  if (req.method === 'GET' && req.url === '/healthz') {
    return jsonResponse(res, 200, { status: 'ok', service: 'redactwall-ai-gateway-rate-limiter' });
  }
  if (req.method === 'GET' && req.url === '/readyz') {
    const health = await limiterHealth(store, opts);
    return jsonResponse(res, health.status === 'ready' ? 200 : 503, health);
  }
  if (req.url !== '/check') return jsonResponse(res, 404, { error: 'not found' });
  if (req.method !== 'POST') return jsonResponse(res, 405, { error: 'method not allowed' }, { allow: 'POST' });

  const auth = authenticate(req, opts);
  if (!auth.ok) return jsonResponse(res, auth.status, { error: auth.error });

  const collected = await collectBody(req, boundedInt(opts.maxBodyBytes, DEFAULT_MAX_BODY_BYTES, 1024, 128 * 1024));
  if (collected.truncated) return jsonResponse(res, 413, { error: 'request too large' });
  const parsed = parseJson(collected.body);
  if (!parsed.ok) return jsonResponse(res, 400, { error: parsed.error });
  try {
    return jsonResponse(res, 200, await Promise.resolve(store.check(parsed.value)));
  } catch (e) {
    return jsonResponse(res, Number(e && e.status) || 400, { error: e && e.message ? safeText(e.message, 'invalid limiter request') : 'invalid limiter request' });
  }
}

function createLimiterServer(opts = {}) {
  const state = { store: opts.store || createLimiterStore(opts) };
  const server = http.createServer((req, res) => {
    Promise.resolve(handleLimiterRequest(req, res, opts, state)).catch(() => {
      if (!res.headersSent) jsonResponse(res, 500, { error: 'rate limiter internal error' });
      else res.end();
    });
  });
  server.on('close', () => {
    if (state.store && typeof state.store.close === 'function') state.store.close();
  });
  return server;
}

function parseArgs(argv = process.argv.slice(2)) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === '--port') out.port = Number(argv[++i]);
    else if (item === '--host') out.host = argv[++i];
    else if (item === '--store') out.storeBackend = argv[++i];
    else if (item === '--db') out.dbPath = argv[++i];
    else if (item === '--redis-url') out.redisUrl = argv[++i];
    else if (item === '--redis-prefix') out.redisPrefix = argv[++i];
    else if (item === '--redis-timeout-ms') out.redisTimeoutMs = Number(argv[++i]);
    else if (item === '--token') out.token = argv[++i];
    else if (item === '--allow-insecure-dev') out.allowInsecureDev = true;
    else if (item === '--default-limit') out.defaultLimit = Number(argv[++i]);
    else if (item === '--default-window-ms') out.defaultWindowMs = Number(argv[++i]);
    else if (item === '--max-limit') out.maxLimit = Number(argv[++i]);
    else if (item === '--max-window-ms') out.maxWindowMs = Number(argv[++i]);
  }
  return out;
}

async function main(argv = process.argv.slice(2), io = process) {
  const args = parseArgs(argv);
  if (!configuredToken(args) && args.allowInsecureDev !== true) {
    throw new Error('Set REDACTWALL_RATE_LIMITER_TOKEN or pass --token before starting the shared limiter.');
  }
  const port = Number.isFinite(args.port) ? args.port : DEFAULT_PORT;
  const host = args.host || '127.0.0.1';
  const server = createLimiterServer(args).listen(port, host, () => {
    const address = server.address();
    io.stdout.write(`RedactWall AI gateway shared limiter listening on http://${host}:${address && address.port ? address.port : port}\n`);
  });
  return server;
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`${err && err.message ? err.message : err}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  authenticate,
  createRedisLimiterStore,
  createLimiterServer,
  createLimiterStore,
  createSqliteLimiterStore,
  handleLimiterRequest,
  limiterHealth,
  main,
  normalizeLimiterInput,
  openLimiterDatabase,
  parseArgs,
  parseRespReplies,
  redisCommand,
  redisUrl,
};
