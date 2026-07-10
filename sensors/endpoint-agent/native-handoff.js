'use strict';
/**
 * Signed local handoff events for future native endpoint interceptors.
 *
 * A native collector can write one small JSON event per attempted desktop-AI
 * file upload. The endpoint agent validates the event, reads the referenced
 * local file, and keeps the event itself free of file bytes or prompt text.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { withEnvAliases } = require('../../server/env');
const privatePaths = require('../../server/private-path');
const fileMutationLock = require('../../server/file-mutation-lock');

const EVENT_VERSION = 1;
const MAX_EVENT_BYTES = 16 * 1024;
const DEFAULT_TTL_MS = 5 * 60 * 1000;
const DEFAULT_CLAIM_RETENTION_MS = 24 * 60 * 60 * 1000;
const CLAIM_PRUNE_INTERVAL_MS = 60 * 1000;
const DEFAULT_HANDOFF_DIR = path.join(os.tmpdir(), 'redactwall-native-handoff');
const CONSUMED_DIR_NAME = '.consumed';
const CLAIM_DOMAIN = 'redactwall-native-handoff-consumed-v1\0';
const INGEST_IDEMPOTENCY_SCOPE = 'native_handoff_v1';
const INGEST_IDEMPOTENCY_DOMAIN = 'redactwall-native-handoff-ingest-v1\0';
const DISALLOWED_EVENT_KEYS = new Set([
  'body',
  'bytes',
  'content',
  'contentBase64',
  'contentbase64',
  'content_base64',
  'fileBytes',
  'filebytes',
  'file_bytes',
  'prompt',
  'raw',
  'rawText',
  'rawtext',
  'raw_text',
  'text',
]);
const ALLOWED_EVENT_KEYS = new Set([
  'version',
  'id',
  'createdAt',
  'operation',
  'filePath',
  'destination',
  'user',
  'nonce',
  'signature',
]);
const ALLOWED_DESTINATION_KEYS = new Set([
  'app',
  'name',
  'process',
  'url',
]);
let lastClaimPruneMs = 0;
const trustedDirectories = new Set();

function defaultHandoffDir(env = process.env) {
  const resolved = withEnvAliases(env);
  return resolved.ENDPOINT_AGENT_HANDOFF_DIR || DEFAULT_HANDOFF_DIR;
}

function configuredHandoffSecret(opts = {}) {
  const env = withEnvAliases(process.env);
  const value = Object.prototype.hasOwnProperty.call(opts, 'secret')
    ? opts.secret
    : env.ENDPOINT_AGENT_HANDOFF_SECRET;
  return typeof value === 'string' ? value.trim() : '';
}

function assertOwnedDirectory(dir, security) {
  privatePaths.assertPrivatePath(dir, security);
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('native handoff directory must be a real directory');
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new Error('native handoff directory must be owned by the current user');
  }
}

function directoryTrustKey(dir, security) {
  const platform = security.platform || process.platform;
  return `${platform}:${platform === 'win32' ? dir.toLowerCase() : dir}`;
}

function ensurePrivateDirectory(dir, privatePathSecurity = {}) {
  const resolved = path.resolve(dir);
  const security = {
    ...privatePathSecurity,
    fs,
    directory: true,
    label: 'native handoff directory',
    ownerLabel: 'native handoff directory',
  };
  const trustKey = directoryTrustKey(resolved, security);
  if (trustedDirectories.has(trustKey)) {
    assertOwnedDirectory(resolved, security);
    return resolved;
  }
  privatePaths.withPrivateDirectoryMutationLockSync(resolved, () => {
    assertOwnedDirectory(resolved, security);
  }, security);
  trustedDirectories.add(trustKey);
  return resolved;
}

function boundedString(value, fallback, max) {
  if (typeof value !== 'string') return fallback;
  const clean = value.replace(/[\r\n\t]/g, ' ').trim();
  return clean ? clean.slice(0, max) : fallback;
}

function normalizedEventKey(key) {
  return String(key || '').replace(/[^A-Za-z0-9]/g, '').toLowerCase();
}

function assertNoPayloadKeys(value, prefix = 'event') {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (DISALLOWED_EVENT_KEYS.has(key) || DISALLOWED_EVENT_KEYS.has(normalizedEventKey(key))) {
      throw new Error('native handoff event contains a prohibited payload field');
    }
    if (child && typeof child === 'object') {
      assertNoPayloadKeys(child, `${prefix}.${key}`);
    }
  }
}

function assertAllowedKeys(value, allowed, prefix) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(`native handoff ${prefix} contains an unsupported field`);
    }
  }
}

function assertAllowedEventShape(event) {
  assertAllowedKeys(event, ALLOWED_EVENT_KEYS, 'event');
  const destination = event.destination;
  if (destination && typeof destination === 'object') {
    if (Array.isArray(destination)) {
      throw new Error('native handoff event.destination is not allowed');
    }
    assertAllowedKeys(destination, ALLOWED_DESTINATION_KEYS, 'event.destination');
  }
}

function normalizeDestination(destination) {
  if (typeof destination === 'string') {
    // Emit the same {app,process,url} shape as the object path so canonicalEvent
    // is stable whether it runs on a raw or already-normalized event; otherwise a
    // signature computed over a string destination never re-validates.
    return { app: boundedString(destination, 'desktop-ai-app', 80), process: '', url: '' };
  }
  const src = destination && typeof destination === 'object' ? destination : {};
  return {
    app: boundedString(src.app || src.name, 'desktop-ai-app', 80),
    process: boundedString(src.process, '', 80),
    url: boundedString(src.url, '', 200),
  };
}

function publicDestination(destination) {
  const normalized = normalizeDestination(destination);
  return normalized.app || 'desktop-ai-app';
}

function normalizeEvent(event, opts = {}) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new Error('native handoff event must be a JSON object');
  }
  assertNoPayloadKeys(event);
  assertAllowedEventShape(event);
  if (event.version !== EVENT_VERSION) {
    throw new Error('native handoff version is unsupported');
  }
  const operation = boundedString(event.operation, 'upload', 32);
  if (operation !== 'upload') {
    throw new Error('native handoff operation is unsupported');
  }
  const filePath = boundedString(event.filePath, '', 1024);
  if (/^\\\\/.test(filePath)) {
    throw new Error('native handoff filePath must be a local path');
  }
  if (!filePath || !(path.isAbsolute(filePath) || path.win32.isAbsolute(filePath))) {
    throw new Error('native handoff filePath must be absolute');
  }
  const createdAt = boundedString(event.createdAt, '', 64);
  const createdMs = Date.parse(createdAt);
  if (!Number.isFinite(createdMs)) {
    throw new Error('native handoff createdAt is invalid');
  }
  const nowMs = opts.now instanceof Date ? opts.now.getTime() : Date.now();
  const ttlMs = Number.isFinite(Number(opts.ttlMs)) ? Number(opts.ttlMs) : DEFAULT_TTL_MS;
  if (Math.abs(nowMs - createdMs) > ttlMs) {
    throw new Error('native handoff event is outside the allowed time window');
  }
  return {
    version: EVENT_VERSION,
    id: boundedString(event.id, crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'), 120),
    createdAt: new Date(createdMs).toISOString(),
    operation,
    filePath,
    destination: normalizeDestination(event.destination),
    user: boundedString(event.user, '', 160),
    nonce: boundedString(event.nonce, '', 160),
  };
}

function canonicalEvent(event) {
  const normalized = normalizeEvent(event, {
    ttlMs: Number.MAX_SAFE_INTEGER,
    now: new Date(event.createdAt || Date.now()),
  });
  return JSON.stringify({
    version: normalized.version,
    id: normalized.id,
    createdAt: normalized.createdAt,
    operation: normalized.operation,
    filePath: normalized.filePath,
    destination: normalized.destination,
    user: normalized.user,
    nonce: normalized.nonce,
  });
}

function signatureFor(event, secret) {
  const key = typeof secret === 'string' ? secret.trim() : '';
  if (key.length < 32) throw new Error('native handoff secret must be at least 32 characters');
  return crypto.createHmac('sha256', key).update(canonicalEvent(event)).digest('hex');
}

function timingSafeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (!/^[0-9a-f]{64}$/i.test(left) || !/^[0-9a-f]{64}$/i.test(right)) return false;
  const a = Buffer.from(left, 'hex');
  const b = Buffer.from(right, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function signHandoffEvent(event, secret) {
  const normalized = normalizeEvent(event, {
    ttlMs: Number.MAX_SAFE_INTEGER,
    now: new Date(event.createdAt || Date.now()),
  });
  return { ...normalized, signature: signatureFor(normalized, secret) };
}

function validateHandoffEvent(event, opts = {}) {
  const secret = configuredHandoffSecret(opts);
  if (!secret) throw new Error('native handoff secret is not configured');
  const normalized = normalizeEvent(event, opts);
  const expected = signatureFor(normalized, secret);
  if (!timingSafeEqualHex(expected, event.signature)) {
    throw new Error('native handoff signature is invalid');
  }
  return normalized;
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

function readBoundedEventFile(file) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow);
  try {
    const link = fs.lstatSync(file);
    const before = fs.fstatSync(fd);
    if (link.isSymbolicLink() || !before.isFile() || !sameFile(link, before)) {
      throw new Error('native handoff path is not a safe regular file');
    }
    if (before.size > MAX_EVENT_BYTES) throw new Error('native handoff event is too large');
    const body = Buffer.allocUnsafe(MAX_EVENT_BYTES + 1);
    let length = 0;
    while (length <= MAX_EVENT_BYTES) {
      const bytes = fs.readSync(fd, body, length, body.length - length, null);
      if (!bytes) break;
      length += bytes;
    }
    const after = fs.fstatSync(fd);
    if (length > MAX_EVENT_BYTES || after.size > MAX_EVENT_BYTES) throw new Error('native handoff event is too large');
    if (!sameSnapshot(before, after) || length !== after.size || !sameFile(after, fs.statSync(file))) {
      throw new Error('native handoff event changed during inspection');
    }
    return body.subarray(0, length).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function readHandoffFile(file, opts = {}) {
  let body;
  try {
    body = readBoundedEventFile(file);
  } catch (error) {
    if (String(error.message || '').startsWith('native handoff ')) throw error;
    throw new Error('native handoff event is unavailable');
  }
  let parsed;
  try { parsed = JSON.parse(body); } catch { throw new Error('native handoff event JSON is invalid'); }
  return validateHandoffEvent(parsed, opts);
}

function writeExclusiveDurable(file, body) {
  const temp = `${file}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    privatePaths.securePrivatePath(temp, {
      fs,
      directory: false,
      fresh: true,
      label: 'native handoff claim staging file',
      ownerLabel: 'native handoff claim staging file',
    });
    fs.writeFileSync(fd, body, { encoding: 'utf8' });
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    privatePaths.publishFileExclusiveDurably(temp, file, { fs });
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(temp); } catch {}
  }
}

function claimFingerprint(event, secret) {
  return crypto.createHmac('sha256', secret)
    .update(CLAIM_DOMAIN)
    .update(String(event.id || ''))
    .update('\0')
    .update(String(event.nonce || ''))
    .digest('hex');
}

/**
 * Opaque, restart-stable identity for one signature-validated native event.
 * The control plane never receives the path, nonce, event id, or local secret.
 */
function ingestIdempotency(event, opts = {}) {
  const secret = configuredHandoffSecret(opts);
  if (!secret) throw new Error('native handoff secret is not configured');
  return {
    scope: INGEST_IDEMPOTENCY_SCOPE,
    key: crypto.createHmac('sha256', secret)
      .update(INGEST_IDEMPOTENCY_DOMAIN)
      .update(canonicalEvent(event))
      .digest('hex'),
  };
}

function claimFileFor(event, handoffFile, opts = {}) {
  const secret = configuredHandoffSecret(opts);
  if (!secret) throw new Error('native handoff secret is not configured');
  const privatePathSecurity = opts.privatePathSecurity || {};
  const handoffDir = ensurePrivateDirectory(path.dirname(path.resolve(handoffFile)), privatePathSecurity);
  const consumedDir = ensurePrivateDirectory(path.resolve(
    opts.consumedDir || path.join(handoffDir, CONSUMED_DIR_NAME),
  ), privatePathSecurity);
  return path.join(consumedDir, `${claimFingerprint(event, secret)}.claim`);
}

function readHandoffClaim(event, handoffFile, opts = {}) {
  const claimFile = claimFileFor(event, handoffFile, opts);
  let body;
  try { body = readBoundedEventFile(claimFile); }
  catch (error) {
    if (error && error.code === 'ENOENT') return null;
    if (!fs.existsSync(claimFile)) return null;
    throw new Error('native handoff claim is unavailable');
  }
  try {
    const parsed = JSON.parse(body);
    if (!parsed || parsed.version !== EVENT_VERSION) throw new Error('invalid');
    if (!['claimed', 'terminal'].includes(parsed.state)) {
      // Claims written by the pre-terminal-state implementation are permanent
      // consumed markers and must not become replayable after upgrade.
      if (parsed.claimedAt) return { version: EVENT_VERSION, state: 'terminal', decision: 'unknown', status: 'legacy_consumed' };
      throw new Error('invalid');
    }
    return parsed;
  } catch {
    throw new Error('native handoff claim is invalid');
  }
}

function publishClaimState(file, state) {
  const temp = `${file}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    privatePaths.securePrivatePath(temp, {
      fs,
      directory: false,
      fresh: true,
      label: 'native handoff claim staging file',
      ownerLabel: 'native handoff claim staging file',
    });
    fs.writeFileSync(fd, `${JSON.stringify(state)}\n`, { encoding: 'utf8' });
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    privatePaths.publishFileDurably(temp, file, { fs });
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(temp); } catch {}
  }
}

function terminalClaim(result) {
  if (!result || typeof result !== 'object' || typeof result.decision !== 'string') {
    throw new Error('native handoff scan did not reach a terminal decision');
  }
  const decision = boundedString(result.decision, 'block', 32).toLowerCase();
  const status = boundedString(result.status, decision, 80).toLowerCase();
  const recordId = boundedString(result.id, '', 120);
  return {
    version: EVENT_VERSION,
    state: 'terminal',
    decision,
    status,
    recorded: typeof result.id === 'string' && !!result.id,
    ...(recordId ? { recordId } : {}),
    completedAt: new Date().toISOString(),
  };
}

async function withHandoffClaim(event, handoffFile, callback, opts = {}) {
  if (typeof callback !== 'function') throw new TypeError('native handoff claim callback is required');
  const claimFile = claimFileFor(event, handoffFile, opts);
  pruneConsumedClaims(path.dirname(claimFile), opts);
  return fileMutationLock.withFileMutationLock(claimFile, async () => {
    const prior = readHandoffClaim(event, handoffFile, opts);
    if (prior && prior.state === 'terminal') {
      return { claimed: false, claimFile, terminal: prior };
    }
    const claimedAt = prior && prior.claimedAt ? prior.claimedAt : new Date().toISOString();
    publishClaimState(claimFile, {
      version: EVENT_VERSION,
      state: 'claimed',
      claimedAt,
      attemptAt: new Date().toISOString(),
    });
    const result = await callback();
    const terminal = terminalClaim(result);
    publishClaimState(claimFile, terminal);
    return { claimed: true, claimFile, result, terminal, resumed: !!prior };
  }, {
    lockTimeoutMs: opts.claimLockTimeoutMs || 30000,
    lockRetryMs: opts.claimLockRetryMs || 25,
  });
}

function pruneConsumedClaims(dir, opts = {}) {
  const nowMs = Number.isFinite(Number(opts.claimNowMs)) ? Number(opts.claimNowMs) : Date.now();
  if (!opts.forceClaimPrune && nowMs - lastClaimPruneMs < CLAIM_PRUNE_INTERVAL_MS) return 0;
  lastClaimPruneMs = nowMs;
  const requestedTtl = Number(opts.ttlMs);
  const ttlMs = Number.isFinite(requestedTtl) && requestedTtl > 0 ? requestedTtl : DEFAULT_TTL_MS;
  const minimumRetentionMs = Math.max(DEFAULT_TTL_MS * 2, ttlMs * 2);
  const configured = Number(opts.claimRetentionMs);
  const retentionMs = Number.isFinite(configured) && configured >= minimumRetentionMs
    ? configured : Math.max(DEFAULT_CLAIM_RETENTION_MS, minimumRetentionMs);
  let removed = 0;
  for (const entry of fs.readdirSync(dir)) {
    if (!entry.endsWith('.claim')) continue;
    const file = path.join(dir, entry);
    try {
      if (nowMs - fs.lstatSync(file).mtimeMs <= retentionMs) continue;
      fs.rmSync(file, { force: true });
      removed += 1;
    } catch { /* a concurrent claimant or pruner won */ }
  }
  return removed;
}

function claimHandoffEvent(event, handoffFile, opts = {}) {
  const claimFile = claimFileFor(event, handoffFile, opts);
  const consumedDir = path.dirname(claimFile);
  pruneConsumedClaims(consumedDir, opts);
  try {
    writeExclusiveDurable(claimFile, JSON.stringify({ version: EVENT_VERSION, claimedAt: new Date().toISOString() }) + '\n');
    return { claimed: true, claimFile };
  } catch (error) {
    if (error.code === 'EEXIST') return { claimed: false, claimFile };
    throw error;
  }
}

module.exports = {
  EVENT_VERSION,
  MAX_EVENT_BYTES,
  DEFAULT_TTL_MS,
  DEFAULT_CLAIM_RETENTION_MS,
  CONSUMED_DIR_NAME,
  INGEST_IDEMPOTENCY_SCOPE,
  defaultHandoffDir,
  configuredHandoffSecret,
  ensurePrivateDirectory,
  publicDestination,
  signatureFor,
  signHandoffEvent,
  validateHandoffEvent,
  readHandoffFile,
  claimHandoffEvent,
  claimFileFor,
  readHandoffClaim,
  ingestIdempotency,
  withHandoffClaim,
  pruneConsumedClaims,
  _internal: {
    claimFingerprint,
    readBoundedEventFile,
    sameFile,
    sameSnapshot,
    publishClaimState,
    terminalClaim,
    writeExclusiveDurable,
  },
};
