'use strict';
require('../server/env').loadEnv();
/**
 * Squid ICAP REQMOD bridge (network backstop).
 *
 * A minimal RFC 3507 REQMOD service: Squid hands each intercepted HTTP request
 * to this bridge, the bridge extracts the user's prompt from the embedded HTTP
 * body, calls the RedactWall control plane (`POST /api/v1/gate`), and enforces
 * the verdict inline - allow (ICAP 204 / echo), block (synthesized HTTP 403),
 * or hold (poll `/api/v1/status/:id` until released, deny by default).
 *
 * Fail-closed: any control-plane failure, parse failure, or over-limit body
 * results in a block response. No raw prompt text, PII, or request bodies are
 * ever written to logs - only decisions, hosts, byte counts, and latencies.
 *
 * Protocol subset: REQMOD + OPTIONS, no Preview negotiation, no RESPMOD.
 */
const net = require('node:net');
const REDACTWALL = process.env.REDACTWALL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;

function requestTimeoutMs(opts = {}) {
  const n = Number(opts.timeoutMs ?? process.env.REDACTWALL_REQUEST_TIMEOUT_MS ?? DEFAULT_REQUEST_TIMEOUT_MS);
  if (!Number.isFinite(n)) return DEFAULT_REQUEST_TIMEOUT_MS;
  return Math.max(50, Math.min(120000, n));
}

async function fetchWithTimeout(fetchImpl, url, options, opts = {}) {
  if (!fetchImpl || !globalThis.AbortController) return fetchImpl(url, options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs(opts));
  try {
    return await fetchImpl(url, { ...options, signal: controller.signal });
  } catch (e) {
    if (e && e.name === 'AbortError') e.code = 'REDACTWALL_TIMEOUT';
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function failClosed(reason) {
  return { decision: 'block', status: 'control_plane_unavailable', reason };
}

async function responseJson(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

/** Extract the user prompt from a captured request body for known AI endpoints. */
function extractPrompt(host, contentType, body) {
  try {
    if (contentType && contentType.includes('application/json')) {
      const j = JSON.parse(body);
      // OpenAI / Anthropic style chat payloads
      if (Array.isArray(j.messages)) {
        return j.messages.filter(m => m.role === 'user').map(m =>
          typeof m.content === 'string' ? m.content
            : Array.isArray(m.content) ? m.content.map(c => c.text || '').join(' ') : ''
        ).join('\n');
      }
      if (typeof j.prompt === 'string') return j.prompt;
      if (typeof j.input === 'string') return j.input;
    }
  } catch { /* fall through */ }
  // Web-UI form posts vary; fall back to raw body text.
  return body;
}

async function gate({
  host,
  user,
  sourceIp,
  contentType,
  body,
  redactwall = REDACTWALL,
  key = KEY,
  fetchImpl = globalThis.fetch,
  timeoutMs,
}) {
  if (!fetchImpl) return failClosed('fetch_unavailable');
  const prompt = extractPrompt(host, contentType, body);
  try {
    const r = await fetchWithTimeout(fetchImpl, redactwall + '/api/v1/gate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': key },
      body: JSON.stringify({ prompt, user, destination: host, sourceIp, source: 'proxy', channel: 'submit' }),
    }, { timeoutMs });
    if (!r || !r.ok) return failClosed(`gate_http_${r ? r.status : 'missing'}`);
    const verdict = await responseJson(r);
    if (!verdict || typeof verdict.decision !== 'string') return failClosed('gate_invalid_json');
    return verdict; // { id, decision, status, ... }
  } catch (e) {
    return failClosed(e && e.code === 'REDACTWALL_TIMEOUT' ? 'gate_timeout' : 'gate_unreachable');
  }
}

/** Block inline: poll until the admin releases, or time out (deny by default). */
async function awaitRelease(id, {
  releaseToken,
  timeoutMs = 5 * 60 * 1000,
  intervalMs = 2000,
  redactwall = REDACTWALL,
  key = KEY,
  fetchImpl = globalThis.fetch,
  requestTimeoutMs: perRequestTimeoutMs,
  sleepImpl = (ms) => new Promise((res) => setTimeout(res, ms)),
} = {}) {
  if (!id) return { released: false, reason: 'missing_id' };
  if (!fetchImpl) return { released: false, reason: 'fetch_unavailable' };
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    let r;
    try {
      r = await fetchWithTimeout(fetchImpl, `${redactwall}/api/v1/status/${encodeURIComponent(id)}`, {
        headers: {
          'x-api-key': key,
          ...(releaseToken ? { 'x-release-token': releaseToken } : {}),
        },
      }, { timeoutMs: perRequestTimeoutMs });
    } catch (e) {
      return { released: false, reason: e && e.code === 'REDACTWALL_TIMEOUT' ? 'status_timeout' : 'status_unreachable' };
    }
    if (!r || !r.ok) return { released: false, reason: `status_http_${r ? r.status : 'missing'}` };
    const s = await responseJson(r);
    if (!s || typeof s.status !== 'string') return { released: false, reason: 'status_invalid_json' };
    if (s.status === 'approved' || s.status === 'allowed') return { released: true };
    if (s.status === 'denied') return { released: false, reason: 'denied' };
    await sleepImpl(intervalMs);
  }
  return { released: false, reason: 'timeout' };
}

// ---------------------------------------------------------------------------
// ICAP/1.0 server (RFC 3507 subset: OPTIONS + REQMOD, no Preview, no RESPMOD)
// ---------------------------------------------------------------------------

const DEFAULT_ICAP_PORT = 1344;
const DEFAULT_ICAP_HOST = '127.0.0.1';
const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_HEADER_BYTES = 16 * 1024;
const DEFAULT_SOCKET_TIMEOUT_MS = 30000;
const DEFAULT_RELEASE_WAIT_MS = 5 * 60 * 1000;
const MAX_HEADER_COUNT = 128;
const MAX_CHUNK_SIZE_LINE_BYTES = 64;
const ISTAG = '"redactwall-icap-bridge-1"';
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const EMPTY = Buffer.alloc(0);

function boundedInt(value, def, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function icapConfig(opts = {}) {
  const maxBodyBytes = boundedInt(opts.maxBodyBytes ?? process.env.ICAP_BRIDGE_MAX_BODY_BYTES, DEFAULT_MAX_BODY_BYTES, 1024, 32 * 1024 * 1024);
  const maxHeaderBytes = boundedInt(opts.maxHeaderBytes ?? process.env.ICAP_BRIDGE_MAX_HEADER_BYTES, DEFAULT_MAX_HEADER_BYTES, 1024, 256 * 1024);
  return {
    redactwall: opts.redactwall || REDACTWALL,
    key: opts.key || KEY,
    fetchImpl: opts.fetchImpl || globalThis.fetch,
    io: opts.io || process,
    maxBodyBytes,
    maxHeaderBytes,
    maxHeaders: boundedInt(opts.maxHeaders, MAX_HEADER_COUNT, 8, 1024),
    maxRawBytes: maxHeaderBytes * 2 + maxBodyBytes * 4,
    socketTimeoutMs: boundedInt(opts.socketTimeoutMs ?? process.env.ICAP_BRIDGE_SOCKET_TIMEOUT_MS, DEFAULT_SOCKET_TIMEOUT_MS, 1000, 600000),
    releaseWaitMs: boundedInt(opts.releaseWaitMs ?? process.env.ICAP_BRIDGE_RELEASE_WAIT_MS, DEFAULT_RELEASE_WAIT_MS, 0, 30 * 60 * 1000),
    gateTimeoutMs: opts.gateTimeoutMs,
  };
}

/** Metadata-only log line. MUST never receive prompt text, bodies, or PII. */
function logEvent(config, fields) {
  const io = (config && config.io) || process;
  io.stdout.write(`${JSON.stringify({ service: 'squid-icap-bridge', ts: new Date().toISOString(), ...fields })}\n`);
}

/** Parse "METHOD uri VERSION" + "Name: value" lines. Returns null on any malformation. */
function parseHeaderBlock(text, maxHeaders) {
  const lines = text.split('\r\n');
  const requestLine = lines[0].split(' ').filter(Boolean);
  if (requestLine.length !== 3) return null;
  if (lines.length - 1 > maxHeaders) return null;
  const headers = {};
  for (let i = 1; i < lines.length; i += 1) {
    if (!lines[i]) continue;
    const idx = lines[i].indexOf(':');
    if (idx <= 0) return null;
    headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
  }
  return { method: requestLine[0].toUpperCase(), uri: requestLine[1], version: requestLine[2], headers };
}

/** Parse an Encapsulated header into ordered [name, offset] pairs. */
function parseEncapsulated(value) {
  const out = [];
  for (const part of String(value || '').split(',')) {
    if (!part.trim()) continue;
    const eq = part.indexOf('=');
    if (eq === -1) return null;
    const offset = Number(part.slice(eq + 1).trim());
    if (!Number.isInteger(offset) || offset < 0) return null;
    out.push([part.slice(0, eq).trim().toLowerCase(), offset]);
  }
  return out;
}

/**
 * Decode an ICAP chunked body starting at `offset`.
 * Returns { state: 'need_more' | 'done' | 'error' | 'too_large', body?, end?, ieof? }.
 */
function decodeChunked(buffer, offset, maxBytes) {
  const parts = [];
  let pos = offset;
  let total = 0;
  for (;;) {
    const lineEnd = buffer.indexOf('\r\n', pos);
    if (lineEnd === -1) {
      return buffer.length - pos > MAX_CHUNK_SIZE_LINE_BYTES ? { state: 'error' } : { state: 'need_more' };
    }
    if (lineEnd - pos > MAX_CHUNK_SIZE_LINE_BYTES) return { state: 'error' };
    const sizeLine = buffer.slice(pos, lineEnd).toString('latin1');
    const size = Number.parseInt(sizeLine.split(';')[0].trim(), 16);
    if (!Number.isInteger(size) || size < 0) return { state: 'error' };
    if (size === 0) {
      if (buffer.length < lineEnd + 4) return { state: 'need_more' };
      if (buffer[lineEnd + 2] !== 0x0d || buffer[lineEnd + 3] !== 0x0a) return { state: 'error' };
      return { state: 'done', body: Buffer.concat(parts, total), end: lineEnd + 4, ieof: /;\s*ieof/i.test(sizeLine) };
    }
    total += size;
    if (total > maxBytes) return { state: 'too_large' };
    const dataStart = lineEnd + 2;
    if (buffer.length < dataStart + size + 2) return { state: 'need_more' };
    parts.push(buffer.slice(dataStart, dataStart + size));
    pos = dataStart + size + 2;
  }
}

/** Extract the encapsulated req-hdr/req-body once the ICAP head is parsed. */
function extractEncapsulated(buffer, bodyStart, head, config) {
  const enc = parseEncapsulated(head.headers.encapsulated || 'null-body=0');
  if (!enc) return { error: 'icap_malformed' };
  if (head.method === 'OPTIONS' || (enc.length === 1 && enc[0][0] === 'null-body' && enc[0][1] === 0)) {
    return { message: { head, reqHdr: EMPTY, body: EMPTY }, end: bodyStart };
  }
  if (enc.length !== 2 || enc[0][0] !== 'req-hdr' || enc[0][1] !== 0) return { error: 'icap_malformed' };
  const reqHdrLen = enc[1][1];
  if (reqHdrLen > config.maxHeaderBytes) return { error: 'http_header_overflow' };
  if (buffer.length < bodyStart + reqHdrLen) return null;
  const reqHdr = buffer.slice(bodyStart, bodyStart + reqHdrLen);
  if (enc[1][0] === 'null-body') return { message: { head, reqHdr, body: EMPTY }, end: bodyStart + reqHdrLen };
  if (enc[1][0] !== 'req-body') return { error: 'icap_malformed' };
  const decoded = decodeChunked(buffer, bodyStart + reqHdrLen, config.maxBodyBytes);
  if (decoded.state === 'need_more') return null;
  if (decoded.state === 'too_large') return { tooLarge: true, head };
  if (decoded.state === 'error') return { error: 'icap_chunk_malformed' };
  if (head.headers.preview !== undefined && !decoded.ieof) return { error: 'preview_unsupported' };
  return { message: { head, reqHdr, body: decoded.body }, end: decoded.end };
}

/** Returns null (need more data), { error }, { tooLarge }, or { message, end }. */
function tryExtractMessage(buffer, config) {
  const headerEnd = buffer.indexOf('\r\n\r\n');
  if (headerEnd === -1) {
    return buffer.length > config.maxHeaderBytes ? { error: 'icap_header_overflow' } : null;
  }
  if (headerEnd > config.maxHeaderBytes) return { error: 'icap_header_overflow' };
  const head = parseHeaderBlock(buffer.slice(0, headerEnd).toString('latin1'), config.maxHeaders);
  if (!head || !head.version.startsWith('ICAP/')) return { error: 'icap_malformed' };
  return extractEncapsulated(buffer, headerEnd + 4, head, config);
}

/** Parse the embedded (encapsulated) HTTP request head; null on malformation. */
function parseHttpRequestHead(reqHdr, config) {
  const text = reqHdr.toString('latin1');
  const end = text.indexOf('\r\n\r\n');
  const head = parseHeaderBlock(end === -1 ? text.replace(/(\r\n)+$/, '') : text.slice(0, end), config.maxHeaders);
  if (!head || !head.version.startsWith('HTTP/')) return null;
  return { ...head, host: httpHost(head) };
}

function httpHost(head) {
  try {
    if (/^https?:\/\//i.test(head.uri)) return new URL(head.uri).hostname;
  } catch { /* fall through to Host header */ }
  return String(head.headers.host || 'unknown').split(':')[0];
}

function icapMessage(status, headers = {}, payload = null) {
  const lines = [`ICAP/1.0 ${status}`, `ISTag: ${ISTAG}`, 'Service: RedactWall ICAP bridge'];
  for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
  lines.push('', '');
  const head = Buffer.from(lines.join('\r\n'), 'latin1');
  return payload ? Buffer.concat([head, payload]) : head;
}

function chunkedBody(buf) {
  return Buffer.concat([Buffer.from(`${buf.length.toString(16)}\r\n`, 'latin1'), buf, Buffer.from('\r\n0\r\n\r\n', 'latin1')]);
}

function optionsResponse() {
  return icapMessage('200 OK', {
    Methods: 'REQMOD',
    'Options-TTL': 3600,
    Allow: 204,
    'Max-Connections': 100,
    'Transfer-Complete': '*',
    Encapsulated: 'null-body=0',
  });
}

function icapErrorResponse(status) {
  return icapMessage(status, { Connection: 'close', Encapsulated: 'null-body=0' });
}

/** Allow: ICAP 204 when the client offered it, otherwise echo the request back. */
function allowResponse(message) {
  if (String(message.head.headers.allow || '').split(',').map((s) => s.trim()).includes('204')) {
    return icapMessage('204 No Content', { Encapsulated: 'null-body=0' });
  }
  const hasBody = message.body.length > 0;
  const enc = hasBody ? `req-hdr=0, req-body=${message.reqHdr.length}` : `req-hdr=0, null-body=${message.reqHdr.length}`;
  const payload = hasBody ? Buffer.concat([message.reqHdr, chunkedBody(message.body)]) : message.reqHdr;
  return icapMessage('200 OK', { Encapsulated: enc }, payload);
}

/** Block: replace the HTTP request with a synthesized, prompt-free 403 response. */
function blockResponse(decision, queryId) {
  const json = Buffer.from(JSON.stringify({ blocked: true, decision: decision || 'block', queryId: queryId || null }));
  const resHdr = Buffer.from([
    'HTTP/1.1 403 Forbidden',
    'Content-Type: application/json',
    `Content-Length: ${json.length}`,
    'X-RedactWall: blocked',
    'Connection: close',
    '',
    '',
  ].join('\r\n'), 'latin1');
  return icapMessage('200 OK', { Encapsulated: `res-hdr=0, res-body=${resHdr.length}` }, Buffer.concat([resHdr, chunkedBody(json)]));
}

/** Gate the embedded request; fail closed on every non-allow path. */
async function decideReqmod(embedded, message, config) {
  if (!BODY_METHODS.has(embedded.method) || !message.body.length) {
    return { action: 'allow', decision: 'allow', queryId: null, reason: 'no_body' };
  }
  const shared = { redactwall: config.redactwall, key: config.key, fetchImpl: config.fetchImpl };
  const verdict = await gate({
    host: embedded.host,
    user: embedded.headers['x-redactwall-user'] || message.head.headers['x-client-username'] || 'unknown',
    sourceIp: message.head.headers['x-client-ip'] || null,
    contentType: embedded.headers['content-type'] || '',
    body: message.body.toString('utf8'),
    timeoutMs: config.gateTimeoutMs,
    ...shared,
  });
  if (verdict.decision === 'allow') return { action: 'allow', decision: 'allow', queryId: verdict.id || null };
  if (verdict.status !== 'pending' || !verdict.id) {
    return { action: 'block', decision: verdict.decision || 'block', queryId: verdict.id || null, reason: verdict.reason || verdict.status || null };
  }
  const release = await awaitRelease(verdict.id, {
    releaseToken: verdict.releaseToken,
    timeoutMs: config.releaseWaitMs,
    ...shared,
  });
  if (release.released) return { action: 'allow', decision: 'allow_after_release', queryId: verdict.id };
  return { action: 'block', decision: 'block', queryId: verdict.id, reason: release.reason || null };
}

async function handleMessage(socket, message, config) {
  const started = Date.now();
  if (message.head.method === 'OPTIONS') {
    socket.write(optionsResponse());
    return logEvent(config, { event: 'options', latencyMs: Date.now() - started });
  }
  if (message.head.method !== 'REQMOD') {
    socket.write(icapErrorResponse('405 Method Not Allowed'));
    return logEvent(config, { event: 'method_not_allowed' });
  }
  const embedded = parseHttpRequestHead(message.reqHdr, config);
  if (!embedded) {
    socket.write(blockResponse('block', null));
    return logEvent(config, { event: 'reqmod', decision: 'block', reason: 'http_malformed' });
  }
  const outcome = await decideReqmod(embedded, message, config);
  socket.write(outcome.action === 'allow' ? allowResponse(message) : blockResponse(outcome.decision, outcome.queryId));
  logEvent(config, {
    event: 'reqmod',
    decision: outcome.action,
    verdict: outcome.decision,
    host: embedded.host,
    reason: outcome.reason || null,
    bodyBytes: message.body.length,
    latencyMs: Date.now() - started,
  });
}

function rejectConnection(socket, state, config, payload, reason) {
  state.dead = true;
  try {
    socket.write(payload);
  } catch { /* socket already gone */ }
  socket.end();
  logEvent(config, { event: 'reject', reason });
}

function processBuffer(socket, state, config) {
  if (state.dead || state.busy || socket.destroyed) return;
  const result = tryExtractMessage(state.buffer, config);
  if (!result) return;
  if (result.error) return rejectConnection(socket, state, config, icapErrorResponse('400 Bad Request'), result.error);
  if (result.tooLarge) return rejectConnection(socket, state, config, blockResponse('block', null), 'body_too_large');
  state.buffer = state.buffer.slice(result.end);
  state.busy = true;
  socket.pause();
  handleMessage(socket, result.message, config)
    .catch(() => {
      try {
        socket.write(blockResponse('block', null));
      } catch { /* socket already gone */ }
    })
    .finally(() => {
      state.busy = false;
      if (!socket.destroyed) {
        socket.resume();
        processBuffer(socket, state, config);
      }
    });
}

function onSocketData(socket, state, chunk, config) {
  if (state.dead) return;
  state.buffer = Buffer.concat([state.buffer, chunk]);
  if (state.buffer.length > config.maxRawBytes) {
    return rejectConnection(socket, state, config, blockResponse('block', null), 'raw_overflow');
  }
  processBuffer(socket, state, config);
}

function createIcapServer(opts = {}) {
  const config = icapConfig(opts);
  const sockets = new Set();
  const server = net.createServer((socket) => {
    const state = { buffer: EMPTY, busy: false, dead: false };
    sockets.add(socket);
    socket.setTimeout(config.socketTimeoutMs, () => socket.destroy());
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
    socket.on('data', (chunk) => onSocketData(socket, state, chunk, config));
  });
  server.destroyConnections = () => {
    for (const socket of sockets) socket.destroy();
  };
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
    else if (item === '--max-body-bytes') out.maxBodyBytes = Number(argv[++i]);
  }
  return out;
}

async function main(argv = process.argv.slice(2), io = process) {
  const args = parseArgs(argv);
  const port = Number.isFinite(args.port) ? args.port : boundedInt(process.env.ICAP_BRIDGE_PORT, DEFAULT_ICAP_PORT, 1, 65535);
  const host = args.host || process.env.ICAP_BRIDGE_HOST || DEFAULT_ICAP_HOST;
  const server = createIcapServer({ ...args, io });
  server.listen(port, host, () => {
    const address = server.address();
    io.stdout.write(`RedactWall Squid ICAP bridge (REQMOD) listening on icap://${host}:${address && address.port ? address.port : port}/reqmod\n`);
  });
  const shutdown = () => {
    server.close(() => process.exit(0));
    server.destroyConnections();
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  return server;
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`${err && err.message ? err.message : err}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  awaitRelease,
  blockResponse,
  createIcapServer,
  decodeChunked,
  decideReqmod,
  extractPrompt,
  failClosed,
  fetchWithTimeout,
  gate,
  icapConfig,
  main,
  parseArgs,
  parseEncapsulated,
  parseHeaderBlock,
  parseHttpRequestHead,
  requestTimeoutMs,
  tryExtractMessage,
};
