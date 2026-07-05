'use strict';
require('../server/env').loadEnv();
/**
 * Provider-aware enforcement gateway for private apps and internal agents.
 *
 * This reverse gateway keeps upstream provider credentials on the gateway side,
 * requires a client token before any app can send traffic, gates prompt text
 * before forwarding, and scans model output before returning it to the caller.
 */
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const { extractPrompt, fetchWithTimeout, awaitRelease } = require('./squid-icap-bridge');

const REDACTWALL = process.env.REDACTWALL_URL || process.env.PROMPTWALL_URL || process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';
const DEFAULT_PORT = 4182;
const DEFAULT_HOST = (process.env.REDACTWALL_GATEWAY_HOST || process.env.PROMPTWALL_GATEWAY_HOST) || '127.0.0.1';
const DEFAULT_UPSTREAM = (process.env.REDACTWALL_GATEWAY_UPSTREAM || process.env.PROMPTWALL_GATEWAY_UPSTREAM) || 'https://api.openai.com';
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_RATE_LIMIT = 60;
const DEFAULT_RATE_WINDOW_MS = 60000;
const DEFAULT_RATE_LIMIT_STORE = (process.env.REDACTWALL_GATEWAY_RATE_LIMIT_STORE || process.env.PROMPTWALL_GATEWAY_RATE_LIMIT_STORE) || 'memory';
const DEFAULT_RATE_LIMIT_DB = (process.env.REDACTWALL_GATEWAY_RATE_LIMIT_DB || process.env.PROMPTWALL_GATEWAY_RATE_LIMIT_DB) || path.join(process.cwd(), 'data', 'gateway-rate-limits.db');
const DEFAULT_RATE_LIMIT_URL = (process.env.REDACTWALL_GATEWAY_RATE_LIMIT_URL || process.env.PROMPTWALL_GATEWAY_RATE_LIMIT_URL) || '';
const DEFAULT_RATE_LIMIT_TOKEN = (process.env.REDACTWALL_GATEWAY_RATE_LIMIT_TOKEN || process.env.PROMPTWALL_GATEWAY_RATE_LIMIT_TOKEN) || '';
const DEFAULT_RATE_LIMIT_TIMEOUT_MS = 2000;
const DEFAULT_APPROVAL_WAIT_MS = 0;
const DEFAULT_ALLOWED_MODELS = (process.env.REDACTWALL_GATEWAY_ALLOWED_MODELS || process.env.PROMPTWALL_GATEWAY_ALLOWED_MODELS) || '';
const DEFAULT_UPSTREAM_AUTH_HEADER = (process.env.REDACTWALL_GATEWAY_UPSTREAM_AUTH_HEADER || process.env.PROMPTWALL_GATEWAY_UPSTREAM_AUTH_HEADER) || 'authorization';
const DEFAULT_UPSTREAM_AUTH_SCHEME = (process.env.REDACTWALL_GATEWAY_UPSTREAM_AUTH_SCHEME || process.env.PROMPTWALL_GATEWAY_UPSTREAM_AUTH_SCHEME) || 'Bearer';
const DEFAULT_AWS_SIGV4_SERVICE = (process.env.REDACTWALL_GATEWAY_AWS_SERVICE || process.env.PROMPTWALL_GATEWAY_AWS_SERVICE) || 'bedrock';
const SENSOR = { name: 'ai_llm_gateway', version: '0.1.0', platform: 'node_reverse_gateway' };
const PROMPT_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);
const PRIVATE_HEADERS = new Set([
  'authorization',
  'cookie',
  'x-api-key',
  'x-redactwall-gateway-token',
  'x-redactwall-user',
  'x-redactwall-org',
]);

function boundedInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function configuredClientTokens(opts = {}) {
  const raw = opts.clientTokens || opts.clientToken || (process.env.REDACTWALL_GATEWAY_TOKEN || process.env.PROMPTWALL_GATEWAY_TOKEN) || '';
  const values = Array.isArray(raw) ? raw : String(raw).split(',');
  return values.map((item) => String(item || '').trim()).filter(Boolean);
}

function normalizeModelList(value) {
  const values = Array.isArray(value) ? value : String(value || '').split(',');
  const out = [];
  const seen = new Set();
  for (const item of values) {
    const text = safeHeaderValue(item, '', 120);
    if (!text || !/^[A-Za-z0-9.*:_/-]+$/.test(text)) continue;
    const key = text.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(text);
  }
  return out;
}

function configuredAllowedModels(opts = {}) {
  return normalizeModelList(opts.allowedModels || opts.allowedModel || DEFAULT_ALLOWED_MODELS);
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

function bearerToken(value = '') {
  const match = String(value || '').match(/^\s*Bearer\s+(.+?)\s*$/i);
  return match ? match[1] : '';
}

function tokenDigest(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function safeHeaderValue(value, fallback = 'unknown', max = 160) {
  const text = String(value || '').replace(/[\r\n\t]/g, ' ').trim();
  return (text || fallback).slice(0, max);
}

function safeHeaderName(value, fallback = '') {
  const name = safeHeaderValue(value, fallback, 80).toLowerCase();
  return /^[a-z0-9][a-z0-9-]{0,79}$/.test(name) ? name : '';
}

function clientTokenFromRequest(req) {
  return safeHeaderValue(req.headers['x-redactwall-gateway-token'] || bearerToken(req.headers.authorization || ''), '', 4096);
}

function authenticateGatewayClient(req, opts = {}) {
  const tokens = configuredClientTokens(opts);
  if (!tokens.length && opts.allowInsecureDev === true) {
    return { ok: true, principal: 'anonymous-dev', tokenHash: 'anonymous-dev' };
  }
  if (!tokens.length) {
    return { ok: false, status: 503, error: 'gateway client auth token not configured' };
  }
  const supplied = clientTokenFromRequest(req);
  if (!supplied) return { ok: false, status: 401, error: 'missing gateway client token' };
  const matched = tokens.some((expected) => constantTimeEqual(supplied, expected));
  if (!matched) return { ok: false, status: 401, error: 'invalid gateway client token' };
  const digest = tokenDigest(supplied);
  return { ok: true, principal: `gateway-client-${digest.slice(0, 12)}`, tokenHash: digest };
}

function rateLimitStoreMode(opts = {}) {
  const mode = safeHeaderValue(opts.rateLimitStore || opts.rateStore || DEFAULT_RATE_LIMIT_STORE, 'memory', 40).toLowerCase();
  if (!mode || mode === 'memory') return 'memory';
  if (mode === 'sqlite') return 'sqlite';
  if (mode === 'http' || mode === 'https' || mode === 'external') return 'http';
  throw new Error('unsupported gateway rate limit store');
}

function rateLimitDbPath(opts = {}) {
  return String(opts.rateLimitDbPath || opts.rateDbPath || DEFAULT_RATE_LIMIT_DB || '').trim();
}

function rateLimitServiceUrl(opts = {}) {
  return String(opts.rateLimitUrl || opts.rateUrl || DEFAULT_RATE_LIMIT_URL || '').trim();
}

function rateLimitServiceToken(opts = {}) {
  return String(opts.rateLimitToken || opts.rateToken || DEFAULT_RATE_LIMIT_TOKEN || '').trim();
}

function rateLimitKey(key) {
  return crypto.createHash('sha256').update(String(key || 'unknown')).digest('hex');
}

function normalizeRateLimitServiceUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) throw new Error('gateway http rate limit url is required');
  const url = new URL(raw);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('gateway http rate limit url must be http or https');
  if (url.username || url.password) throw new Error('gateway http rate limit url must not contain credentials');
  return url;
}

function openRateLimitDatabase(dbPath) {
  const target = String(dbPath || '').trim();
  if (!target) throw new Error('gateway sqlite rate limit database path is required');
  if (target !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(target)), { recursive: true });
  }
  const Database = require('better-sqlite3');
  const db = new Database(target);
  db.pragma('busy_timeout = 5000');
  if (target !== ':memory:') db.pragma('journal_mode = WAL');
  db.exec(`CREATE TABLE IF NOT EXISTS gateway_rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`);
  return db;
}

function createSqliteRateLimiter({ limit, windowMs, dbPath }) {
  const db = openRateLimitDatabase(dbPath);
  const upsert = db.prepare(`INSERT INTO gateway_rate_limits (key, count, reset_at, updated_at)
    VALUES (@key, 1, @resetAt, @now)
    ON CONFLICT(key) DO UPDATE SET
      count = CASE WHEN gateway_rate_limits.reset_at <= excluded.updated_at THEN 1 ELSE gateway_rate_limits.count + 1 END,
      reset_at = CASE WHEN gateway_rate_limits.reset_at <= excluded.updated_at THEN excluded.reset_at ELSE gateway_rate_limits.reset_at END,
      updated_at = excluded.updated_at
    RETURNING count, reset_at`);
  const cleanup = db.prepare('DELETE FROM gateway_rate_limits WHERE reset_at < ?');
  let checks = 0;
  return {
    store: 'sqlite',
    check(key, now = Date.now()) {
      const row = upsert.get({ key: rateLimitKey(key), resetAt: now + windowMs, now });
      checks += 1;
      if (checks % 100 === 0) cleanup.run(now - windowMs);
      const count = Number(row && row.count) || 0;
      const resetAt = Number(row && row.reset_at) || now + windowMs;
      return {
        ok: count <= limit,
        limit,
        remaining: Math.max(0, limit - count),
        resetMs: Math.max(0, resetAt - now),
        store: 'sqlite',
      };
    },
    close() {
      db.close();
    },
  };
}

function unavailableRateLimit(limit, store, error) {
  return {
    ok: false,
    limit,
    remaining: 0,
    resetMs: 1000,
    store,
    shared: true,
    unavailable: true,
    error: safeHeaderValue(error, 'gateway shared rate limiter unavailable', 160),
  };
}

function createHttpRateLimiter({ limit, windowMs, url, token, fetchImpl, timeoutMs }) {
  const target = normalizeRateLimitServiceUrl(url);
  const authToken = String(token || '').trim();
  const timeout = boundedInt(timeoutMs ?? (process.env.REDACTWALL_GATEWAY_RATE_LIMIT_TIMEOUT_MS || process.env.PROMPTWALL_GATEWAY_RATE_LIMIT_TIMEOUT_MS), DEFAULT_RATE_LIMIT_TIMEOUT_MS, 100, 30000);
  return {
    store: 'http',
    endpoint: target.origin,
    async check(key, now = Date.now()) {
      const fetcher = fetchImpl || globalThis.fetch;
      if (!fetcher) return unavailableRateLimit(limit, 'http', 'gateway shared rate limiter fetch unavailable');
      try {
        const res = await fetchWithTimeout(fetcher, target.href, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(authToken ? { authorization: `Bearer ${authToken}` } : {}),
          },
          body: JSON.stringify({
            key: rateLimitKey(key),
            limit,
            windowMs,
            now,
          }),
        }, { timeoutMs: timeout });
        const body = res && typeof res.json === 'function' ? await res.json().catch(() => null) : null;
        if (!res || !res.ok || !body || typeof body !== 'object') {
          return unavailableRateLimit(limit, 'http', `gateway shared rate limiter http_${res ? res.status : 'missing'}`);
        }
        const allowed = body.ok !== false && body.allowed !== false;
        return {
          ok: allowed,
          limit: boundedInt(body.limit ?? limit, limit, 1, 100000),
          remaining: boundedInt(body.remaining, allowed ? Math.max(0, limit - 1) : 0, 0, 100000),
          resetMs: boundedInt(body.resetMs ?? body.retryMs, windowMs, 0, 3600000),
          store: 'http',
          shared: true,
        };
      } catch {
        return unavailableRateLimit(limit, 'http', 'gateway shared rate limiter unavailable');
      }
    },
  };
}

function createRateLimiter(opts = {}) {
  const limit = boundedInt(opts.rateLimit ?? (process.env.REDACTWALL_GATEWAY_RATE_LIMIT || process.env.PROMPTWALL_GATEWAY_RATE_LIMIT), DEFAULT_RATE_LIMIT, 1, 100000);
  const windowMs = boundedInt(opts.rateWindowMs ?? (process.env.REDACTWALL_GATEWAY_RATE_WINDOW_MS || process.env.PROMPTWALL_GATEWAY_RATE_WINDOW_MS), DEFAULT_RATE_WINDOW_MS, 1000, 3600000);
  const store = rateLimitStoreMode(opts);
  if (store === 'sqlite') return createSqliteRateLimiter({ limit, windowMs, dbPath: rateLimitDbPath(opts) });
  if (store === 'http') {
    return createHttpRateLimiter({
      limit,
      windowMs,
      url: rateLimitServiceUrl(opts),
      token: rateLimitServiceToken(opts),
      fetchImpl: opts.rateLimitFetchImpl || opts.fetchImpl,
      timeoutMs: opts.rateLimitTimeoutMs,
    });
  }
  const buckets = new Map();
  return {
    store: 'memory',
    check(key, now = Date.now()) {
      const id = key || 'unknown';
      const current = buckets.get(id);
      if (!current || current.resetAt <= now) {
        buckets.set(id, { count: 1, resetAt: now + windowMs });
        return { ok: true, limit, remaining: limit - 1, resetMs: windowMs, store: 'memory' };
      }
      current.count += 1;
      if (current.count > limit) return { ok: false, limit, remaining: 0, resetMs: Math.max(0, current.resetAt - now), store: 'memory' };
      return { ok: true, limit, remaining: Math.max(0, limit - current.count), resetMs: Math.max(0, current.resetAt - now), store: 'memory' };
    },
    buckets,
  };
}

function normalizeUpstreamBase(value = DEFAULT_UPSTREAM) {
  const url = new URL(String(value || DEFAULT_UPSTREAM));
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('upstream must be http or https');
  return url;
}

function targetUrl(req, upstream = DEFAULT_UPSTREAM) {
  const rawPath = String(req.url || '/');
  if (/^https?:\/\//i.test(rawPath) || rawPath.startsWith('//')) {
    throw new Error('absolute proxy targets are not allowed');
  }
  const base = normalizeUpstreamBase(upstream);
  const joinedBase = new URL(base.href);
  if (!joinedBase.pathname.endsWith('/')) joinedBase.pathname += '/';
  const normalizedPath = rawPath.replace(/^\/+/, '');
  const out = new URL(normalizedPath || '.', joinedBase);
  out.protocol = base.protocol;
  out.host = base.host;
  return out;
}

function pathAllowed(pathname, opts = {}) {
  if (opts.allowAnyPath === true) return true;
  const path = String(pathname || '');
  return /(?:^|\/)(chat\/completions|responses|messages)$/.test(path)
    || /\/models\/[^/]+:(?:generateContent|streamGenerateContent)$/i.test(path)
    || /\/model\/[^/]+\/(?:converse|converse-stream|invoke|invoke-with-response-stream)$/i.test(path);
}

function collectBody(req, maxBytes = DEFAULT_MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let truncated = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size <= maxBytes) chunks.push(chunk);
      else truncated = true;
    });
    req.on('end', () => resolve({ body: Buffer.concat(chunks), size, truncated }));
    req.on('error', reject);
  });
}

function parseJsonBody(body) {
  try {
    return { ok: true, value: JSON.parse(String(body || '')) };
  } catch {
    return { ok: false, error: 'invalid json' };
  }
}

function textFromContent(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.map((item) => {
    if (!item || typeof item !== 'object') return '';
    if (typeof item.text === 'string') return item.text;
    if (typeof item.input_text === 'string') return item.input_text;
    return '';
  }).filter(Boolean).join(' ');
}

function textFromParts(parts) {
  if (!Array.isArray(parts)) return '';
  return parts
    .map((part) => part && typeof part === 'object' && typeof part.text === 'string' ? part.text : '')
    .filter(Boolean)
    .join(' ');
}

function promptTextFromJson(bodyJson) {
  const payload = bodyJson && typeof bodyJson === 'object' ? bodyJson : {};
  if (typeof payload.prompt === 'string') return payload.prompt;
  if (typeof payload.inputText === 'string') return payload.inputText;
  if (typeof payload.input === 'string') return payload.input;
  const messages = [];
  if (Array.isArray(payload.messages)) messages.push(...payload.messages);
  if (Array.isArray(payload.input)) messages.push(...payload.input);
  const messageText = messages
    .filter((message) => message && typeof message === 'object' && String(message.role || '').toLowerCase() === 'user')
    .map((message) => textFromContent(message.content))
    .filter(Boolean)
    .join('\n');
  if (messageText) return messageText;
  if (Array.isArray(payload.contents)) {
    return payload.contents
      .filter((content) => content && typeof content === 'object' && (!content.role || String(content.role).toLowerCase() === 'user'))
      .map((content) => textFromParts(content.parts))
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

function modelFromJson(bodyJson) {
  const payload = bodyJson && typeof bodyJson === 'object' ? bodyJson : {};
  return safeHeaderValue(payload.model, '', 120);
}

function modelFromPathname(pathname) {
  const path = String(pathname || '');
  const bedrock = path.match(/\/model\/([^/]+)\/(?:converse|converse-stream|invoke|invoke-with-response-stream)$/i);
  const match = bedrock || path.match(/\/models\/([^/:]+)(?::|\/|$)/i);
  if (!match) return '';
  try {
    return safeHeaderValue(decodeURIComponent(match[1]), '', 120);
  } catch {
    return safeHeaderValue(match[1], '', 120);
  }
}

function modelFromRequest(target, bodyJson) {
  return modelFromJson(bodyJson) || modelFromPathname(target && target.pathname);
}

function inspectContentBlocks(content, reasons) {
  if (typeof content === 'string' || !Array.isArray(content)) return;
  for (const item of content) {
    if (!item || typeof item !== 'object') continue;
    if (typeof item.text === 'string' || typeof item.input_text === 'string') continue;
    const key = ['image', 'document', 'video', 'toolUse', 'toolResult', 'guardContent', 'cachePoint', 'reasoningContent']
      .find((name) => Object.prototype.hasOwnProperty.call(item, name));
    reasons.add(key ? `bedrock_non_text_${safeHeaderValue(key, 'content', 40)}` : `non_text_${safeHeaderValue(item.type, 'content', 40)}`);
  }
}

function inspectRequestContent(bodyJson) {
  const payload = bodyJson && typeof bodyJson === 'object' ? bodyJson : {};
  const reasons = new Set();
  const messages = [];
  if (Array.isArray(payload.messages)) messages.push(...payload.messages);
  if (Array.isArray(payload.input)) messages.push(...payload.input);
  for (const message of messages) {
    if (!message || typeof message !== 'object') continue;
    if (message.role && !['user', 'assistant', 'system', 'developer'].includes(String(message.role).toLowerCase())) {
      reasons.add('unknown_message_role');
    }
    inspectContentBlocks(message.content, reasons);
  }
  if (Array.isArray(payload.contents)) {
    for (const content of payload.contents) {
      if (!content || typeof content !== 'object') continue;
      if (!Array.isArray(content.parts)) continue;
      for (const part of content.parts) {
        if (!part || typeof part !== 'object' || typeof part.text === 'string') continue;
        reasons.add(part.inlineData ? 'gemini_inline_data' : part.fileData ? 'gemini_file_data' : 'gemini_non_text_part');
      }
    }
  }
  return { inspectable: reasons.size === 0, reasons: [...reasons] };
}

function patternMatches(value, pattern) {
  const target = safeHeaderValue(value, '', 160).toLowerCase();
  const rule = safeHeaderValue(pattern, '', 160).toLowerCase();
  if (!target || !rule) return false;
  if (rule === '*') return true;
  if (rule.startsWith('*') && rule.endsWith('*') && rule.length > 2) return target.includes(rule.slice(1, -1));
  if (rule.startsWith('*')) return target.endsWith(rule.slice(1));
  if (rule.endsWith('*')) return target.startsWith(rule.slice(0, -1));
  return target === rule;
}

function modelAllowed(model, opts = {}) {
  const allowedModels = configuredAllowedModels(opts);
  const safeModel = safeHeaderValue(model, '', 120);
  if (!allowedModels.length) return { allowed: true, model: safeModel, reason: 'all models allowed' };
  if (!safeModel) return { allowed: false, model: 'unknown', reason: 'model is required by gateway policy' };
  if (allowedModels.some((pattern) => patternMatches(safeModel, pattern))) {
    return { allowed: true, model: safeModel, reason: 'model allowed by gateway policy' };
  }
  return { allowed: false, model: safeModel, reason: 'model is outside the gateway allowlist' };
}

function extractPromptText(destination, bodyJson, bodyText, contentType = 'application/json') {
  const structured = promptTextFromJson(bodyJson);
  if (String(structured || '').trim()) return String(structured).trim();
  return String(extractPrompt(destination, contentType, bodyText) || '').trim();
}

function replaceTextContent(content, replacement, state) {
  if (typeof content === 'string') {
    state.replaced += 1;
    return replacement;
  }
  if (Array.isArray(content)) {
    return content.map((item) => {
      if (item && typeof item === 'object' && typeof item.text === 'string') {
        state.replaced += 1;
        return { ...item, text: replacement };
      }
      return item;
    });
  }
  return content;
}

function replaceGeminiParts(parts, replacement, state) {
  if (!Array.isArray(parts)) return parts;
  return parts.map((part) => {
    if (part && typeof part === 'object' && typeof part.text === 'string') {
      state.replaced += 1;
      return { ...part, text: replacement };
    }
    return part;
  });
}

function replacePromptPayload(bodyJson, replacement) {
  const clone = JSON.parse(JSON.stringify(bodyJson || {}));
  const state = { replaced: 0 };
  if (typeof clone.prompt === 'string') {
    clone.prompt = replacement;
    state.replaced += 1;
  }
  if (typeof clone.inputText === 'string') {
    clone.inputText = replacement;
    state.replaced += 1;
  }
  if (typeof clone.input === 'string') {
    clone.input = replacement;
    state.replaced += 1;
  }
  const messageArrays = [];
  if (Array.isArray(clone.messages)) messageArrays.push(clone.messages);
  if (Array.isArray(clone.input)) messageArrays.push(clone.input);
  for (const messages of messageArrays) {
    for (const message of messages) {
      if (!message || typeof message !== 'object') continue;
      if (message.role && String(message.role).toLowerCase() !== 'user') continue;
      if (Object.prototype.hasOwnProperty.call(message, 'content')) {
        message.content = replaceTextContent(message.content, replacement, state);
      }
    }
  }
  if (Array.isArray(clone.contents)) {
    for (const content of clone.contents) {
      if (!content || typeof content !== 'object') continue;
      if (content.role && String(content.role).toLowerCase() !== 'user') continue;
      content.parts = replaceGeminiParts(content.parts, replacement, state);
    }
  }
  return { body: clone, replaced: state.replaced };
}

function readControlPlaneJson(res) {
  return res.json().catch(() => null);
}

function sanitizeGateBody(body = {}) {
  return {
    id: body.id || null,
    decision: body.decision || null,
    mode: body.mode || null,
    status: body.status || null,
    releaseToken: body.releaseToken || undefined,
    riskScore: body.riskScore || 0,
    findings: Array.isArray(body.findings) ? body.findings : [],
    categories: Array.isArray(body.categories) ? body.categories : [],
    reasons: Array.isArray(body.reasons) ? body.reasons : [],
    tokenizedPrompt: typeof body.tokenizedPrompt === 'string' ? body.tokenizedPrompt : undefined,
    receipt: body.receipt || undefined,
  };
}

async function postGate({ prompt, user, orgId, destination, sourceIp, clientOutcome, note }, opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return { ok: false, status: 0, body: { decision: 'block', status: 'control_plane_unavailable', reasons: ['fetch unavailable'] } };
  try {
    const res = await fetchWithTimeout(fetchImpl, `${opts.redactwall || REDACTWALL}/api/v1/gate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': opts.key || KEY },
      body: JSON.stringify({
        prompt,
        user,
        orgId: orgId || null,
        destination,
        sourceIp,
        source: 'proxy',
        channel: 'llm_gateway',
        sensor: opts.sensor || SENSOR,
        clientOutcome,
        note,
      }),
    }, { timeoutMs: opts.controlPlaneTimeoutMs });
    const body = await readControlPlaneJson(res);
    if (!res || !res.ok || !body || typeof body.decision !== 'string') {
      return { ok: false, status: res ? res.status : 0, body: { decision: 'block', status: 'control_plane_unavailable', reasons: [`gate_http_${res ? res.status : 'missing'}`] } };
    }
    return { ok: true, status: res.status, body: sanitizeGateBody(body) };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      body: {
        decision: 'block',
        status: 'control_plane_unavailable',
        reasons: [e && e.code === 'REDACTWALL_TIMEOUT' ? 'gate_timeout' : 'gate_unreachable'],
      },
    };
  }
}

function promptForwardPlan(verdict = {}, opts = {}) {
  const status = verdict.status || '';
  if (verdict.decision === 'allow' || verdict.decision === 'log' || ['allowed', 'warned', 'warned_sent', 'justified'].includes(status)) {
    return { forward: true, bodyMode: 'original' };
  }
  if (verdict.decision === 'redact' && status === 'redacted' && typeof verdict.tokenizedPrompt === 'string') {
    return { forward: true, bodyMode: 'redacted', prompt: verdict.tokenizedPrompt };
  }
  if (['pending', 'pending_justification'].includes(status) && opts.approvalWaitMs > 0 && verdict.id && verdict.releaseToken) {
    return { forward: 'await_release' };
  }
  return { forward: false, statusCode: status === 'control_plane_unavailable' ? 503 : 403 };
}

function configuredUpstreamExtraHeaders(opts = {}) {
  const raw = opts.upstreamHeaders || opts.upstreamHeader || (process.env.REDACTWALL_GATEWAY_UPSTREAM_HEADERS || process.env.PROMPTWALL_GATEWAY_UPSTREAM_HEADERS) || '';
  const values = Array.isArray(raw) ? raw : String(raw).split(',');
  const out = {};
  for (const item of values) {
    const text = String(item || '');
    const idx = text.indexOf('=') >= 0 ? text.indexOf('=') : text.indexOf(':');
    if (idx <= 0) continue;
    const name = safeHeaderName(text.slice(0, idx));
    const lower = name.toLowerCase();
    if (!name || HOP_BY_HOP_HEADERS.has(lower) || PRIVATE_HEADERS.has(lower) || lower === 'host' || lower === 'content-length') continue;
    const value = safeHeaderValue(text.slice(idx + 1), '', 500);
    if (value) out[name] = value;
  }
  return out;
}

function upstreamAuthHeader(opts = {}) {
  const apiKey = opts.upstreamApiKey || (process.env.REDACTWALL_GATEWAY_UPSTREAM_API_KEY || process.env.PROMPTWALL_GATEWAY_UPSTREAM_API_KEY);
  if (upstreamAuthMode(opts) === 'aws-sigv4') return {};
  if (!apiKey) return {};
  const name = safeHeaderName(opts.upstreamAuthHeader || DEFAULT_UPSTREAM_AUTH_HEADER, 'authorization');
  if (!name || HOP_BY_HOP_HEADERS.has(name) || name === 'host' || name === 'content-length' || name === 'cookie') return {};
  const rawScheme = opts.upstreamAuthScheme !== undefined ? opts.upstreamAuthScheme : DEFAULT_UPSTREAM_AUTH_SCHEME;
  const scheme = safeHeaderValue(rawScheme, '', 40);
  const value = !scheme || /^none$/i.test(scheme) ? String(apiKey) : `${scheme} ${apiKey}`;
  return { [name]: value };
}

function upstreamAuthMode(opts = {}) {
  const rawScheme = opts.upstreamAuthScheme !== undefined ? opts.upstreamAuthScheme : DEFAULT_UPSTREAM_AUTH_SCHEME;
  const scheme = safeHeaderValue(rawScheme, '', 40).toLowerCase();
  return scheme === 'aws-sigv4' || scheme === 'sigv4' ? 'aws-sigv4' : 'header';
}

function awsSigningConfig(opts = {}) {
  return {
    accessKeyId: String(opts.awsAccessKeyId || (process.env.REDACTWALL_GATEWAY_AWS_ACCESS_KEY_ID || process.env.PROMPTWALL_GATEWAY_AWS_ACCESS_KEY_ID) || process.env.AWS_ACCESS_KEY_ID || '').trim(),
    secretAccessKey: String(opts.awsSecretAccessKey || (process.env.REDACTWALL_GATEWAY_AWS_SECRET_ACCESS_KEY || process.env.PROMPTWALL_GATEWAY_AWS_SECRET_ACCESS_KEY) || process.env.AWS_SECRET_ACCESS_KEY || '').trim(),
    sessionToken: String(opts.awsSessionToken || (process.env.REDACTWALL_GATEWAY_AWS_SESSION_TOKEN || process.env.PROMPTWALL_GATEWAY_AWS_SESSION_TOKEN) || process.env.AWS_SESSION_TOKEN || '').trim(),
    region: safeHeaderValue(opts.awsRegion || (process.env.REDACTWALL_GATEWAY_AWS_REGION || process.env.PROMPTWALL_GATEWAY_AWS_REGION) || process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || '', '', 80),
    service: safeHeaderValue(opts.awsService || DEFAULT_AWS_SIGV4_SERVICE, 'bedrock', 80),
  };
}

function awsSigningConfigured(opts = {}) {
  const cfg = awsSigningConfig(opts);
  return !!(cfg.accessKeyId && cfg.secretAccessKey && cfg.region && cfg.service);
}

function hashHex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hmac(key, value, encoding) {
  return crypto.createHmac('sha256', key).update(value).digest(encoding);
}

function awsDateParts(date = new Date()) {
  const iso = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  return { amzDate: iso, dateStamp: iso.slice(0, 8) };
}

function canonicalQuery(searchParams) {
  return [...searchParams.entries()]
    .sort(([aKey, aValue], [bKey, bValue]) => aKey.localeCompare(bKey) || aValue.localeCompare(bValue))
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

function signAwsSigV4({ method, target, headers, body, opts = {} }) {
  const cfg = awsSigningConfig(opts);
  if (!cfg.accessKeyId || !cfg.secretAccessKey || !cfg.region || !cfg.service) {
    throw new Error('aws sigv4 upstream signing is not configured');
  }
  const now = opts.awsNow instanceof Date ? opts.awsNow : new Date(opts.awsNow || Date.now());
  const { amzDate, dateStamp } = awsDateParts(now);
  const payloadHash = hashHex(body || '');
  const signedHeadersObj = {
    ...headers,
    host: target.host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    ...(cfg.sessionToken ? { 'x-amz-security-token': cfg.sessionToken } : {}),
  };
  const entries = Object.entries(signedHeadersObj)
    .map(([key, value]) => [String(key).toLowerCase(), String(value).replace(/\s+/g, ' ').trim()])
    .sort(([a], [b]) => a.localeCompare(b));
  const canonicalHeaders = entries.map(([key, value]) => `${key}:${value}\n`).join('');
  const signedHeaders = entries.map(([key]) => key).join(';');
  const canonicalRequest = [
    String(method || 'POST').toUpperCase(),
    target.pathname || '/',
    canonicalQuery(target.searchParams),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');
  const scope = `${dateStamp}/${cfg.region}/${cfg.service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, hashHex(canonicalRequest)].join('\n');
  const dateKey = hmac(`AWS4${cfg.secretAccessKey}`, dateStamp);
  const regionKey = hmac(dateKey, cfg.region);
  const serviceKey = hmac(regionKey, cfg.service);
  const signingKey = hmac(serviceKey, 'aws4_request');
  const signature = hmac(signingKey, stringToSign, 'hex');
  return {
    ...signedHeadersObj,
    authorization: `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

function stripPrivateHeaders(headers = {}, opts = {}) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || PRIVATE_HEADERS.has(lower)) continue;
    out[lower] = value;
  }
  delete out.host;
  delete out['content-length'];
  Object.assign(out, configuredUpstreamExtraHeaders(opts), upstreamAuthHeader(opts));
  return out;
}

async function forwardToUpstream({ req, target, bodyJson, opts = {} }) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return { ok: false, status: 502, error: 'upstream fetch unavailable' };
  const bodyText = JSON.stringify(bodyJson);
  let headers = {
    ...stripPrivateHeaders(req.headers, opts),
    'content-type': 'application/json',
  };
  if (upstreamAuthMode(opts) === 'aws-sigv4') {
    try {
      headers = signAwsSigV4({ method: req.method, target, headers, body: bodyText, opts });
    } catch {
      return { ok: false, status: 502, error: 'aws upstream signing unavailable' };
    }
  }
  try {
    const res = await fetchImpl(target.href, {
      method: req.method,
      headers,
      body: bodyText,
      redirect: 'manual',
    });
    const contentType = res.headers && typeof res.headers.get === 'function'
      ? res.headers.get('content-type') || ''
      : '';
    const buffer = Buffer.from(await res.arrayBuffer());
    if (buffer.length > boundedInt(opts.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES, 1024, 20 * 1024 * 1024)) {
      return { ok: false, status: 502, error: 'upstream response too large to scan' };
    }
    return { ok: !!(res && res.ok), status: res ? res.status : 0, contentType, body: buffer };
  } catch {
    return { ok: false, status: 502, error: 'upstream unavailable' };
  }
}

function collectText(value, texts) {
  if (typeof value === 'string' && value.trim()) texts.push(value);
}

function extractResponseText(bodyJson) {
  const texts = [];
  if (!bodyJson || typeof bodyJson !== 'object') return '';
  collectText(bodyJson.output_text, texts);
  collectText(bodyJson.text, texts);
  collectText(bodyJson.completion, texts);
  if (Array.isArray(bodyJson.choices)) {
    for (const choice of bodyJson.choices) {
      collectText(choice && choice.text, texts);
      collectText(choice && choice.message && textFromContent(choice.message.content), texts);
      collectText(choice && choice.delta && textFromContent(choice.delta.content), texts);
    }
  }
  if (Array.isArray(bodyJson.content)) {
    for (const item of bodyJson.content) collectText(item && item.text, texts);
  }
  if (bodyJson.output && bodyJson.output.message) {
    collectText(textFromContent(bodyJson.output.message.content), texts);
  }
  if (Array.isArray(bodyJson.output)) {
    for (const output of bodyJson.output) {
      if (Array.isArray(output && output.content)) {
        for (const item of output.content) collectText(item && item.text, texts);
      }
    }
  }
  if (Array.isArray(bodyJson.candidates)) {
    for (const candidate of bodyJson.candidates) {
      if (candidate && candidate.content) collectText(textFromParts(candidate.content.parts), texts);
    }
  }
  return texts.join('\n').trim();
}

function rewriteResponseJson(bodyJson, replacement) {
  const clone = JSON.parse(JSON.stringify(bodyJson || {}));
  let replaced = 0;
  function replaceString(obj, key) {
    if (obj && typeof obj[key] === 'string') {
      obj[key] = replacement;
      replaced += 1;
    }
  }
  function replaceContent(obj, key) {
    if (!obj || !Object.prototype.hasOwnProperty.call(obj, key)) return;
    if (typeof obj[key] === 'string') {
      obj[key] = replacement;
      replaced += 1;
      return;
    }
    if (Array.isArray(obj[key])) {
      obj[key] = obj[key].map((item) => {
        if (!item || typeof item !== 'object') return item;
        if (typeof item.text === 'string') {
          replaced += 1;
          return { ...item, text: replacement };
        }
        if (typeof item.input_text === 'string') {
          replaced += 1;
          return { ...item, input_text: replacement };
        }
        return item;
      });
    }
  }
  replaceString(clone, 'output_text');
  replaceString(clone, 'text');
  replaceString(clone, 'completion');
  if (Array.isArray(clone.choices)) {
    for (const choice of clone.choices) {
      replaceString(choice, 'text');
      if (choice && choice.message) replaceContent(choice.message, 'content');
      if (choice && choice.delta) replaceContent(choice.delta, 'content');
    }
  }
  if (Array.isArray(clone.content)) {
    for (const item of clone.content) replaceString(item, 'text');
  }
  if (clone.output && clone.output.message) {
    replaceContent(clone.output.message, 'content');
  }
  if (Array.isArray(clone.output)) {
    for (const output of clone.output) {
      if (Array.isArray(output && output.content)) {
        for (const item of output.content) replaceString(item, 'text');
      }
    }
  }
  if (Array.isArray(clone.candidates)) {
    for (const candidate of clone.candidates) {
      if (candidate && candidate.content) {
        const state = { replaced: 0 };
        candidate.content.parts = replaceGeminiParts(candidate.content.parts, replacement, state);
        replaced += state.replaced;
      }
    }
  }
  if (replaced > 0) {
    clone.redactwall = { ...(clone.redactwall || {}), responseRedacted: true };
    return clone;
  }
  return {
    id: clone.id || undefined,
    object: clone.object || 'redactwall.redacted_response',
    choices: [{ index: 0, message: { role: 'assistant', content: replacement }, finish_reason: 'content_filter' }],
    redactwall: { responseRedacted: true, fallbackShape: true },
  };
}

function sanitizeResponseScan(body = {}) {
  return {
    leaked: body.leaked === true,
    decision: body.decision || 'allow',
    status: body.status || 'allowed',
    blocked: body.blocked === true,
    findings: Array.isArray(body.findings) ? body.findings : [],
    categories: Array.isArray(body.categories) ? body.categories : [],
    redacted: typeof body.redacted === 'string' ? body.redacted : '',
    reasons: Array.isArray(body.reasons) ? body.reasons : [],
  };
}

async function scanResponseText({ text, user, orgId, destination }, opts = {}) {
  if (!String(text || '').trim()) return { ok: true, body: { decision: 'allow', status: 'allowed', leaked: false, blocked: false } };
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return { ok: false, body: { decision: 'block', status: 'response_scan_unavailable', blocked: true } };
  try {
    const res = await fetchWithTimeout(fetchImpl, `${opts.redactwall || REDACTWALL}/api/v1/scan-response`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': opts.key || KEY },
      body: JSON.stringify({
        text,
        user,
        orgId: orgId || null,
        destination,
        source: 'proxy',
        sensor: opts.sensor || SENSOR,
      }),
    }, { timeoutMs: opts.controlPlaneTimeoutMs });
    const body = await readControlPlaneJson(res);
    if (!res || !res.ok || !body || typeof body.decision !== 'string') {
      return { ok: false, body: { decision: 'block', status: 'response_scan_unavailable', blocked: true } };
    }
    return { ok: true, body: sanitizeResponseScan(body) };
  } catch {
    return { ok: false, body: { decision: 'block', status: 'response_scan_unavailable', blocked: true } };
  }
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

function setRateLimitHeaders(res, rate = {}) {
  if (!res || !rate || !Number.isFinite(Number(rate.limit))) return;
  res.setHeader('x-ratelimit-limit', String(rate.limit));
  res.setHeader('x-ratelimit-remaining', String(Math.max(0, Number(rate.remaining) || 0)));
  res.setHeader('x-ratelimit-reset-ms', String(Math.max(0, Number(rate.resetMs) || 0)));
}

function gatewayHealth(opts = {}) {
  const authConfigured = configuredClientTokens(opts).length > 0 || opts.allowInsecureDev === true;
  const rateLimitStore = rateLimitStoreMode(opts);
  const rateLimit = {
    limit: boundedInt(opts.rateLimit ?? (process.env.REDACTWALL_GATEWAY_RATE_LIMIT || process.env.PROMPTWALL_GATEWAY_RATE_LIMIT), DEFAULT_RATE_LIMIT, 1, 100000),
    windowMs: boundedInt(opts.rateWindowMs ?? (process.env.REDACTWALL_GATEWAY_RATE_WINDOW_MS || process.env.PROMPTWALL_GATEWAY_RATE_WINDOW_MS), DEFAULT_RATE_WINDOW_MS, 1000, 3600000),
    store: rateLimitStore,
    shared: rateLimitStore !== 'memory',
  };
  if (rateLimitStore === 'sqlite') {
    rateLimit.scope = 'single_host';
  }
  if (rateLimitStore === 'http') {
    try {
      const url = normalizeRateLimitServiceUrl(rateLimitServiceUrl(opts));
      rateLimit.endpoint = url.origin;
      rateLimit.externalConfigured = true;
    } catch {
      rateLimit.externalConfigured = false;
    }
  }
  let upstream = '';
  let upstreamReady = false;
  try {
    upstream = normalizeUpstreamBase(opts.upstream || DEFAULT_UPSTREAM).origin;
    upstreamReady = true;
  } catch {
    upstream = 'invalid';
  }
  const allowedModels = configuredAllowedModels(opts);
  const rateLimitReady = rateLimitStore !== 'http' || rateLimit.externalConfigured === true;
  const authMode = upstreamAuthMode(opts);
  const upstreamAuth = authMode === 'aws-sigv4'
    ? { mode: 'aws-sigv4', configured: awsSigningConfigured(opts), service: awsSigningConfig(opts).service, region: awsSigningConfig(opts).region || 'unset' }
    : { mode: 'header', configured: !!(opts.upstreamApiKey || (process.env.REDACTWALL_GATEWAY_UPSTREAM_API_KEY || process.env.PROMPTWALL_GATEWAY_UPSTREAM_API_KEY)), header: safeHeaderName(opts.upstreamAuthHeader || DEFAULT_UPSTREAM_AUTH_HEADER, 'authorization') };
  const upstreamAuthReady = authMode !== 'aws-sigv4' || upstreamAuth.configured === true;
  return {
    status: authConfigured && upstreamReady && rateLimitReady && upstreamAuthReady ? 'ready' : 'attention',
    service: 'redactwall-ai-llm-gateway',
    authConfigured,
    upstream,
    upstreamReady,
    upstreamAuth,
    allowedModels: allowedModels.length ? allowedModels : ['*'],
    rateLimit,
    responseScanning: 'required',
    streaming: 'buffered_scan',
    sensor: opts.sensor || SENSOR,
  };
}

function upstreamHeaders(contentType) {
  const safeContentType = /^(application\/json|text\/event-stream|text\/plain)(?:\b|;)/i.test(String(contentType || ''))
    ? contentType
    : 'application/json';
  return {
    'content-type': safeContentType,
    'cache-control': 'no-store',
  };
}

function isBufferedStreamingRequest(target, bodyJson) {
  return !!(bodyJson && bodyJson.stream === true)
    || /:streamGenerateContent$/i.test(String(target && target.pathname || ''))
    || /\/model\/[^/]+\/(?:converse-stream|invoke-with-response-stream)$/i.test(String(target && target.pathname || ''));
}

async function handleGatewayRequest(req, res, opts = {}, state = {}) {
  const requestId = safeHeaderValue(req.headers['x-redactwall-request-id'] || req.headers['x-request-id'] || (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex')), 'gateway-request', 80);
  res.setHeader('x-redactwall-request-id', requestId);
  res.setHeader('x-redactwall-gateway', 'ai-llm-gateway');
  if (req.method === 'GET' && req.url === '/healthz') {
    return jsonResponse(res, 200, { status: 'ok', service: 'redactwall-ai-llm-gateway', requestId });
  }
  if (req.method === 'GET' && req.url === '/readyz') {
    const health = gatewayHealth(opts);
    return jsonResponse(res, health.status === 'ready' ? 200 : 503, { ...health, requestId });
  }
  if (!PROMPT_METHODS.has(String(req.method || '').toUpperCase())) {
    return jsonResponse(res, 405, { error: 'method not allowed' }, { allow: 'POST, PUT, PATCH' });
  }

  const auth = authenticateGatewayClient(req, opts);
  if (!auth.ok) return jsonResponse(res, auth.status, { error: auth.error });
  const limiter = state.rateLimiter || createRateLimiter(opts);
  state.rateLimiter = limiter;
  const rate = await Promise.resolve(limiter.check(auth.tokenHash));
  setRateLimitHeaders(res, rate);
  if (!rate.ok) {
    if (rate.unavailable) {
      return jsonResponse(res, 503, { error: 'gateway shared rate limiter unavailable', requestId });
    }
    return jsonResponse(res, 429, { error: 'gateway rate limit exceeded', retryMs: rate.resetMs, requestId });
  }

  let target;
  try {
    target = targetUrl(req, opts.upstream || DEFAULT_UPSTREAM);
  } catch (e) {
    return jsonResponse(res, 400, { error: e.message || 'invalid gateway target' });
  }
  if (!pathAllowed(target.pathname, opts)) {
    return jsonResponse(res, 404, { error: 'gateway path is not enabled' });
  }

  const maxBodyBytes = boundedInt(opts.maxBodyBytes, DEFAULT_MAX_BODY_BYTES, 1024, 20 * 1024 * 1024);
  const collected = await collectBody(req, maxBodyBytes);
  if (collected.truncated) return jsonResponse(res, 413, { error: 'request too large to inspect' });
  const parsed = parseJsonBody(collected.body.toString('utf8'));
  if (!parsed.ok) return jsonResponse(res, 400, { error: parsed.error });
  const requestJson = parsed.value;
  if (isBufferedStreamingRequest(target, requestJson)) res.setHeader('x-redactwall-stream-buffered', 'true');

  const destination = safeHeaderValue(target.hostname, 'unknown', 253);
  const user = safeHeaderValue(req.headers['x-redactwall-user'], auth.principal, 320);
  const orgId = req.headers['x-redactwall-org'] ? safeHeaderValue(req.headers['x-redactwall-org'], '', 160) : null;
  const requestInspection = inspectRequestContent(requestJson);
  if (!requestInspection.inspectable && opts.allowMultimodal !== true) {
    await postGate({
      prompt: `[LLM non-text content blocked] ${requestInspection.reasons.join(', ')}`,
      user,
      orgId,
      destination,
      sourceIp: req.socket && req.socket.remoteAddress,
      clientOutcome: 'action_blocked',
      note: 'gateway_non_text_content',
    }, opts);
    return jsonResponse(res, 415, {
      error: 'LLM request contains non-text content the gateway cannot inspect',
      decision: 'block',
      status: 'non_text_content_blocked',
      reasons: requestInspection.reasons,
      requestId,
    });
  }
  const modelDecision = modelAllowed(modelFromRequest(target, requestJson), opts);
  if (!modelDecision.allowed) {
    await postGate({
      prompt: `[LLM model blocked] ${modelDecision.model}`,
      user,
      orgId,
      destination,
      sourceIp: req.socket && req.socket.remoteAddress,
      clientOutcome: 'action_blocked',
      note: modelDecision.reason,
    }, opts);
    return jsonResponse(res, 403, {
      error: 'LLM model blocked by RedactWall gateway policy',
      decision: 'block',
      status: 'model_blocked',
      model: modelDecision.model,
      reasons: [modelDecision.reason],
      requestId,
    });
  }
  const prompt = extractPromptText(destination, requestJson, collected.body.toString('utf8'), req.headers['content-type'] || 'application/json');
  if (!prompt) return jsonResponse(res, 400, { error: 'no prompt text extracted for gateway inspection', requestId });

  const gateResult = await postGate({
    prompt,
    user,
    orgId,
    destination,
    sourceIp: req.socket && req.socket.remoteAddress,
  }, opts);
  const verdict = gateResult.body;
  const approvalWaitMs = boundedInt(opts.approvalWaitMs ?? (process.env.REDACTWALL_GATEWAY_APPROVAL_WAIT_MS || process.env.PROMPTWALL_GATEWAY_APPROVAL_WAIT_MS), DEFAULT_APPROVAL_WAIT_MS, 0, 10 * 60 * 1000);
  const plan = promptForwardPlan(verdict, { approvalWaitMs });
  if (plan.forward === 'await_release') {
    const release = await awaitRelease(verdict.id, {
      releaseToken: verdict.releaseToken,
      timeoutMs: approvalWaitMs,
      intervalMs: boundedInt(opts.approvalPollMs, 2000, 100, 60000),
      redactwall: opts.redactwall || REDACTWALL,
      key: opts.key || KEY,
      fetchImpl: opts.fetchImpl || globalThis.fetch,
      requestTimeoutMs: opts.controlPlaneTimeoutMs,
      sleepImpl: opts.sleepImpl,
    });
    if (!release.released) {
      return jsonResponse(res, 403, {
        error: 'prompt withheld by RedactWall',
        id: verdict.id,
        decision: 'block',
        status: verdict.status,
        release: { released: false, reason: release.reason },
        reasons: verdict.reasons || [],
        requestId,
      });
    }
  } else if (!plan.forward) {
    return jsonResponse(res, plan.statusCode || 403, {
      error: gateResult.ok ? 'prompt blocked by RedactWall' : 'RedactWall control plane unavailable',
      id: verdict.id || undefined,
      decision: 'block',
      status: verdict.status || 'blocked',
      riskScore: verdict.riskScore || 0,
      findings: verdict.findings || [],
      categories: verdict.categories || [],
      reasons: verdict.reasons || [],
      requestId,
    });
  }

  let outboundJson = requestJson;
  if (plan.bodyMode === 'redacted') {
    const replaced = replacePromptPayload(requestJson, plan.prompt);
    if (!replaced.replaced) return jsonResponse(res, 409, { error: 'unable to apply RedactWall redaction to request payload', requestId });
    outboundJson = replaced.body;
  }

  const upstream = await forwardToUpstream({ req, target, bodyJson: outboundJson, opts });
  if (!upstream.ok) {
    return jsonResponse(res, upstream.status || 502, { error: upstream.error || 'upstream request failed', requestId });
  }

  const upstreamText = upstream.body.toString('utf8');
  let upstreamJson = null;
  if ((upstream.contentType || '').includes('json')) {
    try { upstreamJson = JSON.parse(upstreamText); } catch {}
  }
  const responseText = upstreamJson ? extractResponseText(upstreamJson) : upstreamText;
  const responseScan = await scanResponseText({ text: responseText, user, orgId, destination }, opts);
  const scanBody = responseScan.body;
  if (!responseScan.ok) {
    return jsonResponse(res, 502, { error: 'RedactWall response scan unavailable', decision: 'block', status: scanBody.status, requestId });
  }
  if (scanBody.blocked || scanBody.decision === 'block') {
    return jsonResponse(res, 403, {
      error: 'AI response blocked by RedactWall',
      decision: 'block',
      status: scanBody.status,
      findings: scanBody.findings,
      categories: scanBody.categories,
      reasons: scanBody.reasons,
      requestId,
    });
  }
  if (scanBody.decision === 'redact') {
    if (upstreamJson) {
      const rewritten = rewriteResponseJson(upstreamJson, scanBody.redacted || '[REDACTED]');
      return jsonResponse(res, upstream.status, rewritten, upstreamHeaders(upstream.contentType));
    }
    res.writeHead(upstream.status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    res.end(scanBody.redacted || '[REDACTED]');
    return undefined;
  }

  res.writeHead(upstream.status, upstreamHeaders(upstream.contentType));
  res.end(upstream.body);
  return undefined;
}

function createGatewayServer(opts = {}) {
  const state = { rateLimiter: opts.rateLimiter || createRateLimiter(opts) };
  const server = http.createServer((req, res) => {
    Promise.resolve(handleGatewayRequest(req, res, opts, state)).catch(() => {
      if (!res.headersSent) jsonResponse(res, 500, { error: 'gateway internal error' });
      else res.end();
    });
  });
  server.on('close', () => {
    if (state.rateLimiter && typeof state.rateLimiter.close === 'function') state.rateLimiter.close();
  });
  return server;
}

function parseArgs(argv = process.argv.slice(2)) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === '--port') out.port = Number(argv[++i]);
    else if (item === '--host') out.host = argv[++i];
    else if (item === '--redactwall' || item === '--sentinel') out.redactwall = argv[++i];
    else if (item === '--key') out.key = argv[++i];
    else if (item === '--upstream') out.upstream = argv[++i];
    else if (item === '--upstream-key') out.upstreamApiKey = argv[++i];
    else if (item === '--upstream-auth-header') out.upstreamAuthHeader = argv[++i];
    else if (item === '--upstream-auth-scheme') out.upstreamAuthScheme = argv[++i];
    else if (item === '--aws-region') out.awsRegion = argv[++i];
    else if (item === '--aws-service') out.awsService = argv[++i];
    else if (item === '--upstream-header') {
      out.upstreamHeader = out.upstreamHeader || [];
      out.upstreamHeader.push(argv[++i]);
    }
    else if (item === '--token') out.clientToken = argv[++i];
    else if (item === '--approval-wait-ms') out.approvalWaitMs = Number(argv[++i]);
    else if (item === '--rate-limit') out.rateLimit = Number(argv[++i]);
    else if (item === '--rate-window-ms') out.rateWindowMs = Number(argv[++i]);
    else if (item === '--rate-store') out.rateLimitStore = argv[++i];
    else if (item === '--rate-db-path') out.rateLimitDbPath = argv[++i];
    else if (item === '--rate-url') out.rateLimitUrl = argv[++i];
    else if (item === '--rate-token') out.rateLimitToken = argv[++i];
    else if (item === '--rate-timeout-ms') out.rateLimitTimeoutMs = Number(argv[++i]);
    else if (item === '--allowed-models') out.allowedModels = argv[++i];
    else if (item === '--allow-multimodal') out.allowMultimodal = true;
    else if (item === '--allow-insecure-dev') out.allowInsecureDev = true;
  }
  return out;
}

async function main(argv = process.argv.slice(2), io = process) {
  const args = parseArgs(argv);
  if (!configuredClientTokens(args).length && args.allowInsecureDev !== true) {
    throw new Error('Set REDACTWALL_GATEWAY_TOKEN or pass --token before starting the AI gateway.');
  }
  const port = Number.isFinite(args.port) ? args.port : DEFAULT_PORT;
  const host = args.host || DEFAULT_HOST;
  const server = createGatewayServer(args).listen(port, host, () => {
    const address = server.address();
    io.stdout.write(`RedactWall AI LLM gateway listening on http://${host}:${address && address.port ? address.port : port}\n`);
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
  authenticateGatewayClient,
  createGatewayServer,
  createHttpRateLimiter,
  createRateLimiter,
  createSqliteRateLimiter,
  extractResponseText,
  gatewayHealth,
  handleGatewayRequest,
  inspectRequestContent,
  isBufferedStreamingRequest,
  modelAllowed,
  modelFromJson,
  modelFromRequest,
  parseArgs,
  pathAllowed,
  postGate,
  promptForwardPlan,
  replacePromptPayload,
  rewriteResponseJson,
  signAwsSigV4,
  scanResponseText,
  targetUrl,
  promptTextFromJson,
};
