'use strict';
/**
 * RedactWall connected-license verdict service.
 *
 * This online service intentionally uses a verdict-only Ed25519 identity. The
 * offline license-issuance root must never be installed here. Customers are
 * allowlisted in a private registry and authenticate each heartbeat with a
 * customer-bound bearer token whose SHA-256 digest is stored in that registry.
 */
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');

const PORT = Number(process.env.LICENSE_SERVER_PORT || 8080);
const HOST = process.env.LICENSE_SERVER_HOST || '127.0.0.1';
const KEY_PATH = process.env.LICENSE_VERDICT_SIGNING_KEY_PATH
  || '/etc/redactwall-license/verdict-signing-key.pem';
const ROOT_PUBLIC_KEY_PATH = process.env.LICENSE_ROOT_PUBLIC_KEY_PATH
  || '/etc/redactwall-license/license-signing-pub.pem';
const REVOKED_PATH = process.env.LICENSE_REVOKED_PATH
  || '/etc/redactwall-license/revoked.json';
const CUSTOMERS_PATH = process.env.LICENSE_CUSTOMERS_PATH
  || '/etc/redactwall-license/customers.json';
const LOG_PATH = process.env.LICENSE_HEARTBEAT_LOG
  || '/var/lib/redactwall-license/heartbeats.jsonl';
const VERDICT_DOMAIN = 'redactwall.connected-license-verdict.v1';

const MAX_BODY_BYTES = 16 * 1024;
const MAX_AUTHORITY_BYTES = 64 * 1024;
const MAX_SIGNING_KEY_BYTES = 16 * 1024;
const MAX_CUSTOMERS = 2048;
const MAX_SEATS = 10_000_000;
const RATE_WINDOW_MS = 60 * 1000;
const MAX_RATE_KEYS = 4096;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const TOKEN_RE = /^[A-Za-z0-9._~+/=-]{32,256}$/;
const TOKEN_HASH_RE = /^[a-f0-9]{64}$/;
const VERSION_RE = /^(?:0|[1-9]\d{0,5})\.(?:0|[1-9]\d{0,5})\.(?:0|[1-9]\d{0,5})(?:-[0-9A-Za-z.-]{1,32})?$/;
const PLANS = new Set(['standard', 'enterprise']);
const BODY_KEYS = new Set(['customerId', 'plan', 'seatsUsed', 'seatLimit', 'version', 'sentAt']);

function boundedInteger(value, fallback, min, max) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : fallback;
}

const BODY_TIMEOUT_MS = boundedInteger(process.env.LICENSE_BODY_TIMEOUT_MS, 5000, 50, 30_000);
const RATE_LIMIT = boundedInteger(process.env.LICENSE_RATE_LIMIT_PER_MINUTE, 60, 1, 6000);
const MAX_LOG_BYTES = boundedInteger(
  process.env.LICENSE_HEARTBEAT_LOG_MAX_BYTES,
  10 * 1024 * 1024,
  256,
  100 * 1024 * 1024,
);
const TRUST_PROXY = process.env.LICENSE_TRUST_PROXY === '1';

if (!Number.isSafeInteger(PORT) || PORT < 0 || PORT > 65535) {
  throw new Error('license server port is invalid');
}
if (!loopbackAddress(HOST)) {
  throw new Error('license server must bind to a numeric loopback address');
}

class RequestError extends Error {
  constructor(statusCode, publicMessage) {
    super(publicMessage);
    this.statusCode = statusCode;
    this.publicMessage = publicMessage;
  }
}

class ServiceConfigError extends Error {
  constructor() {
    super('license service configuration is unavailable');
    this.code = 'LICENSE_SERVICE_CONFIG_INVALID';
  }
}

function sameFile(left, right) {
  if (!left || !right || left.dev !== right.dev) return false;
  return !left.ino || !right.ino || left.ino === right.ino;
}

function sameSnapshot(left, right) {
  return sameFile(left, right)
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function trustedAuthorityPath(stat) {
  if (process.platform === 'win32') return true;
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : -1;
  return (stat.uid === 0 || stat.uid === currentUid) && (stat.mode & 0o022) === 0;
}

function validateAuthorityLink(file, maxBytes) {
  const directory = fs.lstatSync(path.dirname(file));
  const link = fs.lstatSync(file);
  if (!directory.isDirectory() || directory.isSymbolicLink() || !trustedAuthorityPath(directory)
      || !link.isFile() || link.isSymbolicLink() || link.nlink !== 1
      || !trustedAuthorityPath(link) || link.size > maxBytes) {
    throw new ServiceConfigError();
  }
  return link;
}

function readOpenedAuthority(descriptor, before, file, maxBytes) {
  const body = Buffer.allocUnsafe(maxBytes + 1);
  let length = 0;
  while (length < body.length) {
    const bytes = fs.readSync(descriptor, body, length, body.length - length, null);
    if (!bytes) break;
    length += bytes;
  }
  const after = fs.fstatSync(descriptor);
  const current = fs.statSync(file);
  if (length > maxBytes || length !== after.size || !sameSnapshot(before, after)
      || !sameFile(after, current)) throw new ServiceConfigError();
  return body.subarray(0, length).toString('utf8');
}

function readAuthorityFile(file, maxBytes = MAX_AUTHORITY_BYTES) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let descriptor;
  try {
    const link = validateAuthorityLink(file, maxBytes);
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameFile(link, before)
        || !trustedAuthorityPath(before) || before.size > maxBytes) {
      throw new ServiceConfigError();
    }
    return readOpenedAuthority(descriptor, before, file, maxBytes);
  } catch (error) {
    if (error instanceof ServiceConfigError) throw error;
    throw new ServiceConfigError();
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function parsePrivateJson(file) {
  try { return JSON.parse(readAuthorityFile(file)); } catch (error) {
    if (error instanceof ServiceConfigError) throw error;
    throw new ServiceConfigError();
  }
}

function revokedCustomerIds() {
  const parsed = parsePrivateJson(REVOKED_PATH);
  if (!Array.isArray(parsed) || parsed.length > MAX_CUSTOMERS) throw new ServiceConfigError();
  const customers = new Set();
  for (const value of parsed) {
    if (typeof value !== 'string' || !CUSTOMER_ID_RE.test(value)) throw new ServiceConfigError();
    customers.add(value);
  }
  return customers;
}

function validRegistryEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const keys = Object.keys(entry);
  if (keys.length !== 2 || !keys.includes('tokenSha256') || !keys.includes('plans')) return false;
  if (!TOKEN_HASH_RE.test(entry.tokenSha256) || !Array.isArray(entry.plans)) return false;
  if (entry.plans.length < 1 || entry.plans.length > PLANS.size) return false;
  return new Set(entry.plans).size === entry.plans.length && entry.plans.every((plan) => PLANS.has(plan));
}

function customerRegistry() {
  const parsed = parsePrivateJson(CUSTOMERS_PATH);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new ServiceConfigError();
  const entries = Object.entries(parsed);
  if (entries.length < 1 || entries.length > MAX_CUSTOMERS) throw new ServiceConfigError();
  const registry = new Map();
  const tokenHashes = new Set();
  for (const [customerId, entry] of entries) {
    if (!CUSTOMER_ID_RE.test(customerId) || !validRegistryEntry(entry)) throw new ServiceConfigError();
    if (tokenHashes.has(entry.tokenSha256)) throw new ServiceConfigError();
    tokenHashes.add(entry.tokenSha256);
    registry.set(customerId, entry);
  }
  return registry;
}

function loadVerdictSigningKey() {
  if (String(process.env.LICENSE_SIGNING_KEY_PATH || '').trim()) {
    throw new Error('refusing legacy offline license-root key configuration');
  }
  let key;
  try { key = crypto.createPrivateKey(readAuthorityFile(KEY_PATH, MAX_SIGNING_KEY_BYTES)); } catch {
    throw new Error('dedicated verdict signing key is unavailable');
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('dedicated verdict signing key must be Ed25519');
  let rootPublicKey;
  try { rootPublicKey = crypto.createPublicKey(readAuthorityFile(ROOT_PUBLIC_KEY_PATH, MAX_SIGNING_KEY_BYTES)); } catch {
    throw new Error('offline license-root public key is unavailable');
  }
  if (rootPublicKey.asymmetricKeyType !== 'ed25519') throw new Error('offline license-root public key must be Ed25519');
  const verdictPublicDer = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' });
  const rootPublicDer = rootPublicKey.export({ type: 'spki', format: 'der' });
  if (verdictPublicDer.length === rootPublicDer.length
      && crypto.timingSafeEqual(verdictPublicDer, rootPublicDer)) {
    throw new Error('online verdict key must differ from the offline license root');
  }
  return key;
}

const verdictSigningKey = loadVerdictSigningKey();

function tokenDigest(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

function bearerToken(req) {
  const raw = req.headers.authorization;
  if (typeof raw !== 'string') return null;
  const match = /^Bearer ([^\s]+)$/.exec(raw);
  return match && TOKEN_RE.test(match[1]) ? match[1] : null;
}

function authorizeCustomer(customerId, plan, token) {
  const entry = customerRegistry().get(customerId);
  if (!entry || !entry.plans.includes(plan)) return false;
  const expected = Buffer.from(entry.tokenSha256, 'hex');
  const actual = tokenDigest(token);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function loopbackAddress(address) {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
}

function clientAddress(req) {
  const remote = String(req.socket.remoteAddress || 'unknown');
  if (!TRUST_PROXY || !loopbackAddress(remote)) return remote;
  const chain = String(req.headers['x-forwarded-for'] || '').split(',');
  const forwarded = chain[chain.length - 1].trim();
  return net.isIP(forwarded) ? forwarded : remote;
}

const rateWindows = new Map();

function pruneRateWindows(now) {
  for (const [key, value] of rateWindows) {
    if (now - value.startedAt >= RATE_WINDOW_MS) rateWindows.delete(key);
  }
  while (rateWindows.size >= MAX_RATE_KEYS) rateWindows.delete(rateWindows.keys().next().value);
}

function withinRateLimit(scope, identity, now = Date.now()) {
  const key = `${scope}:${crypto.createHash('sha256').update(identity).digest('hex')}`;
  let window = rateWindows.get(key);
  if (!window || now - window.startedAt >= RATE_WINDOW_MS) {
    if (rateWindows.size >= MAX_RATE_KEYS) pruneRateWindows(now);
    window = { startedAt: now, count: 0 };
    rateWindows.set(key, window);
  }
  window.count += 1;
  return window.count <= RATE_LIMIT;
}

function validateContentType(req) {
  const value = String(req.headers['content-type'] || '').toLowerCase();
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/.test(value)) {
    throw new RequestError(415, 'unsupported media type');
  }
}

function declaredLength(req) {
  if (req.headers['content-length'] === undefined) return null;
  const raw = String(req.headers['content-length']);
  if (!/^(?:0|[1-9]\d*)$/.test(raw)) throw new RequestError(400, 'bad request');
  const size = Number(raw);
  if (!Number.isSafeInteger(size)) throw new RequestError(413, 'request too large');
  return size;
}

class BodyReader {
  constructor(req, resolve, reject) {
    this.req = req;
    this.resolve = resolve;
    this.reject = reject;
    this.chunks = [];
    this.size = 0;
    this.settled = false;
    this.onData = this.onData.bind(this);
    this.onEnd = this.onEnd.bind(this);
    this.onFailure = this.onFailure.bind(this);
  }

  start() {
    this.timer = setTimeout(() => this.fail(new RequestError(408, 'request timeout')), BODY_TIMEOUT_MS);
    if (this.timer.unref) this.timer.unref();
    this.req.on('data', this.onData);
    this.req.on('end', this.onEnd);
    this.req.on('aborted', this.onFailure);
    this.req.on('error', this.onFailure);
  }

  cleanup() {
    clearTimeout(this.timer);
    this.req.off('data', this.onData);
    this.req.off('end', this.onEnd);
    this.req.off('aborted', this.onFailure);
    this.req.off('error', this.onFailure);
  }

  fail(error) {
    if (this.settled) return;
    this.settled = true;
    this.cleanup();
    this.req.pause();
    this.reject(error);
  }

  onFailure() { this.fail(new RequestError(400, 'bad request')); }

  onData(chunk) {
    this.size += chunk.length;
    if (this.size > MAX_BODY_BYTES) {
      this.fail(new RequestError(413, 'request too large'));
      return;
    }
    this.chunks.push(chunk);
  }

  onEnd() {
    if (this.settled) return;
    this.settled = true;
    this.cleanup();
    this.resolve(Buffer.concat(this.chunks, this.size).toString('utf8'));
  }
}

function readBody(req) {
  const declared = declaredLength(req);
  if (declared !== null && declared > MAX_BODY_BYTES) {
    return Promise.reject(new RequestError(413, 'request too large'));
  }
  return new Promise((resolve, reject) => new BodyReader(req, resolve, reject).start());
}

function parseHeartbeat(text) {
  let body;
  try { body = JSON.parse(text); } catch { throw new RequestError(400, 'bad request'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new RequestError(400, 'bad request');
  if (Object.keys(body).some((key) => !BODY_KEYS.has(key)) || Object.keys(body).length !== BODY_KEYS.size) {
    throw new RequestError(400, 'bad request');
  }
  if (typeof body.customerId !== 'string' || !CUSTOMER_ID_RE.test(body.customerId)) throw new RequestError(400, 'bad request');
  if (typeof body.plan !== 'string' || !PLANS.has(body.plan)) throw new RequestError(400, 'bad request');
  if (!Number.isSafeInteger(body.seatsUsed) || body.seatsUsed < 0 || body.seatsUsed > MAX_SEATS) throw new RequestError(400, 'bad request');
  if (!Number.isSafeInteger(body.seatLimit) || body.seatLimit < 1 || body.seatLimit > MAX_SEATS) throw new RequestError(400, 'bad request');
  if (typeof body.version !== 'string' || !VERSION_RE.test(body.version)) throw new RequestError(400, 'bad request');
  if (typeof body.sentAt !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(body.sentAt)
      || !Number.isFinite(Date.parse(body.sentAt))) throw new RequestError(400, 'bad request');
  return body;
}

function signVerdict(customerId) {
  const payload = {
    kind: VERDICT_DOMAIN,
    status: revokedCustomerIds().has(customerId) ? 'revoked' : 'active',
    customerId,
    issuedAt: new Date().toISOString(),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const signedInput = Buffer.from(`${VERDICT_DOMAIN}\0${payloadB64}`, 'utf8');
  const signature = crypto.sign(null, signedInput, verdictSigningKey).toString('base64');
  return { text: `${payloadB64}.${signature}`, status: payload.status };
}

let logCapReported = false;

function safeHeartbeatLogEntry(body, verdict) {
  return {
    receivedAt: new Date().toISOString(),
    customerRef: crypto.createHash('sha256').update(body.customerId).digest('hex').slice(0, 24),
    plan: body.plan,
    seatsUsed: body.seatsUsed,
    seatLimit: body.seatLimit,
    version: body.version,
    verdict,
  };
}

function ensurePrivateLogDirectory() {
  const directoryPath = path.dirname(LOG_PATH);
  fs.mkdirSync(directoryPath, { recursive: true, mode: 0o700 });
  const directory = fs.lstatSync(directoryPath);
  if (!directory.isDirectory() || directory.isSymbolicLink() || !trustedAuthorityPath(directory)) {
    throw new ServiceConfigError();
  }
  if (process.platform !== 'win32') fs.chmodSync(directoryPath, 0o700);
}

function appendHeartbeatLog(entry) {
  let descriptor;
  try {
    ensurePrivateLogDirectory();
    const noFollow = fs.constants.O_NOFOLLOW || 0;
    descriptor = fs.openSync(
      LOG_PATH,
      fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_WRONLY | noFollow,
      0o600,
    );
    const line = Buffer.from(`${JSON.stringify(entry)}\n`, 'utf8');
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || !trustedAuthorityPath(stat)
        || line.length > 1024 || stat.size + line.length > MAX_LOG_BYTES) {
      if (!logCapReported) console.error('heartbeat log cap reached');
      logCapReported = true;
      return;
    }
    if (process.platform !== 'win32') fs.fchmodSync(descriptor, 0o600);
    fs.writeSync(descriptor, line);
  } catch {
    console.error('heartbeat log write failed');
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function respond(res, statusCode, text, headers = {}) {
  res.writeHead(statusCode, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(`${text}\n`);
}

function closeAfterResponse(req, res) {
  res.setHeader('connection', 'close');
  res.once('finish', () => req.destroy());
}

function rejectRequest(req, res, statusCode, message, headers = {}) {
  closeAfterResponse(req, res);
  respond(res, statusCode, message, headers);
}

async function handleHeartbeat(req, res) {
  if (!withinRateLimit('address', clientAddress(req))) {
    rejectRequest(req, res, 429, 'rate limited', { 'retry-after': '60' });
    return;
  }
  const token = bearerToken(req);
  if (!token) { rejectRequest(req, res, 401, 'unauthorized'); return; }
  validateContentType(req);
  const body = parseHeartbeat(await readBody(req));
  if (!authorizeCustomer(body.customerId, body.plan, token)) {
    rejectRequest(req, res, 401, 'unauthorized');
    return;
  }
  if (!withinRateLimit('customer', body.customerId)) {
    rejectRequest(req, res, 429, 'rate limited', { 'retry-after': '60' });
    return;
  }
  const verdict = signVerdict(body.customerId);
  appendHeartbeatLog(safeHeartbeatLogEntry(body, verdict.status));
  respond(res, 200, verdict.text);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    try {
      revokedCustomerIds();
      customerRegistry();
      respond(res, 200, 'ok');
    } catch {
      respond(res, 503, 'service unavailable');
    }
    return;
  }
  if (req.method === 'POST' && req.url === '/heartbeat') {
    handleHeartbeat(req, res).catch((error) => {
      if (error instanceof RequestError) {
        if (!res.headersSent && !res.destroyed) rejectRequest(req, res, error.statusCode, error.publicMessage);
        return;
      }
      console.error('heartbeat processing failed');
      if (!res.headersSent && !res.destroyed) respond(res, 503, 'service unavailable');
    });
    return;
  }
  respond(res, 404, 'not found');
});

server.requestTimeout = 0;
server.headersTimeout = 10_000;
server.listen(PORT, HOST, () => {
  const address = server.address();
  const port = address && typeof address === 'object' ? address.port : PORT;
  console.log(`RedactWall license server on http://${HOST}:${port} (TLS proxy required)`);
});
