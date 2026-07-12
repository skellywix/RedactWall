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
  const stat = fs.lstatSync(dir, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('native handoff directory must be a real directory');
  }
  if (typeof process.getuid === 'function' && !sameExactStatInteger(stat.uid, process.getuid())) {
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

function exactIntegerValue(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  return null;
}

function exactStatInteger(value, positive = false) {
  const exact = exactIntegerValue(value);
  if (exact === null) return null;
  return (!positive || exact > 0n) && exact >= 0n ? exact : null;
}

function sameExactStatInteger(left, right, positive = false) {
  const exactLeft = exactStatInteger(left, positive);
  const exactRight = exactStatInteger(right, positive);
  return exactLeft !== null && exactRight !== null && exactLeft === exactRight;
}

function sameSnapshotTime(left, right, nsField, msField) {
  const leftNs = left && left[nsField];
  const rightNs = right && right[nsField];
  if (leftNs !== undefined || rightNs !== undefined) {
    const exactLeft = exactIntegerValue(leftNs);
    const exactRight = exactIntegerValue(rightNs);
    return exactLeft !== null && exactRight !== null && exactLeft === exactRight;
  }
  return Number.isFinite(left && left[msField])
    && Number.isFinite(right && right[msField])
    && left[msField] === right[msField];
}

function singleRegularFile(stat, requireLinkCheck = false) {
  if (!stat || typeof stat.isFile !== 'function' || !stat.isFile()) return false;
  if (requireLinkCheck && typeof stat.isSymbolicLink !== 'function') return false;
  if (typeof stat.isSymbolicLink === 'function' && stat.isSymbolicLink()) return false;
  return exactStatInteger(stat.dev, true) !== null
    && exactStatInteger(stat.ino, true) !== null
    && exactStatInteger(stat.nlink) === 1n;
}

function sameFile(left, right) {
  return !!left && !!right
    && sameExactStatInteger(left.dev, right.dev, true)
    && sameExactStatInteger(left.ino, right.ino, true);
}

function sameSnapshot(left, right) {
  return sameFile(left, right)
    && sameExactStatInteger(left.size, right.size)
    && sameSnapshotTime(left, right, 'mtimeNs', 'mtimeMs')
    && sameSnapshotTime(left, right, 'ctimeNs', 'ctimeMs');
}

function initialEventFileSnapshot(file, fd) {
  const link = fs.lstatSync(file, { bigint: true });
  const opened = fs.fstatSync(fd, { bigint: true });
  const size = exactStatInteger(opened.size);
  if (!singleRegularFile(link, true) || !singleRegularFile(opened)
      || size === null || !sameFile(link, opened)) {
    throw new Error('native handoff path is not a safe regular file');
  }
  if (size > BigInt(MAX_EVENT_BYTES)) throw new Error('native handoff event is too large');
  return opened;
}

function readEventBytes(fd) {
  const body = Buffer.allocUnsafe(MAX_EVENT_BYTES + 1);
  let length = 0;
  while (length <= MAX_EVENT_BYTES) {
    const bytes = fs.readSync(fd, body, length, body.length - length, null);
    if (!bytes) break;
    length += bytes;
  }
  return { body, length };
}

function assertEventFileUnchanged(file, fd, before, after, length) {
  const size = exactStatInteger(after.size);
  if (size === null) throw new Error('native handoff event changed during inspection');
  if (length > MAX_EVENT_BYTES || size > BigInt(MAX_EVENT_BYTES)) {
    throw new Error('native handoff event is too large');
  }
  const link = fs.lstatSync(file, { bigint: true });
  const resolved = fs.statSync(file, { bigint: true });
  if (!singleRegularFile(after) || !singleRegularFile(link, true) || !singleRegularFile(resolved)
      || !sameSnapshot(before, after) || BigInt(length) !== size
      || !sameSnapshot(after, link) || !sameSnapshot(after, resolved) || !sameSnapshot(link, resolved)) {
    throw new Error('native handoff event changed during inspection');
  }
  const final = fs.fstatSync(fd, { bigint: true });
  if (!singleRegularFile(final) || !sameSnapshot(after, final)) {
    throw new Error('native handoff event changed during inspection');
  }
  return final;
}

function readBoundedEventFileSnapshot(file) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  const fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow);
  try {
    const before = initialEventFileSnapshot(file, fd);
    const { body, length } = readEventBytes(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    const final = assertEventFileUnchanged(file, fd, before, after, length);
    const exactBody = body.subarray(0, length);
    return {
      body: exactBody.toString('utf8'),
      sha256: crypto.createHash('sha256').update(exactBody).digest('hex'),
      stat: final,
    };
  } finally {
    fs.closeSync(fd);
  }
}

function readBoundedEventFile(file) {
  return readBoundedEventFileSnapshot(file).body;
}

function readHandoffFileSnapshot(file, opts = {}) {
  let snapshot;
  try {
    snapshot = readBoundedEventFileSnapshot(file);
  } catch (error) {
    if (error && error.code === 'ELOOP') {
      throw new Error('native handoff path is not a safe regular file');
    }
    if (String(error.message || '').startsWith('native handoff ')) throw error;
    throw new Error('native handoff event is unavailable');
  }
  let parsed;
  try { parsed = JSON.parse(snapshot.body); }
  catch {
    const error = new Error('native handoff event JSON is invalid');
    error.fileIdentity = eventCleanupIdentity(snapshot);
    throw error;
  }
  try {
    return { event: validateHandoffEvent(parsed, opts), fileIdentity: eventCleanupIdentity(snapshot) };
  } catch (error) {
    error.fileIdentity = eventCleanupIdentity(snapshot);
    throw error;
  }
}

function readHandoffFile(file, opts = {}) {
  return readHandoffFileSnapshot(file, opts).event;
}

function writeExclusiveDurable(file, body) {
  const temp = `${file}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  let fd;
  let publisherOwnsTemp = false;
  let staged = null;
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
    staged = readBoundedEventFileSnapshot(temp);
    publisherOwnsTemp = true;
    try {
      privatePaths.publishFileExclusiveDurably(temp, file, {
        fs,
        consumeSource: true,
        cleanupComponent: 'native-handoff-claim-publication',
        verifyPublished(published) {
          const settled = readBoundedEventFileSnapshot(published);
          if (settled.stat.nlink !== 1n || settled.sha256 !== staged.sha256 || settled.body !== body) {
            throw new Error('native handoff claim changed during exclusive publication');
          }
        },
      });
    } catch (error) {
      try { removeExactNativeArtifact(temp, staged); }
      catch (cleanupError) {
        if (!cleanupError || !cleanupError.cause || cleanupError.cause.code !== 'ENOENT') {
          privatePaths.notifyCommittedCleanupWarning(cleanupError, {
            fs,
            cleanupComponent: 'native-handoff-claim-publication',
          }, 'failed-claim-staging-cleanup');
        }
      }
      throw error;
    }
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    if (!publisherOwnsTemp) try { fs.unlinkSync(temp); } catch {}
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
    privatePaths.publishFileDurably(temp, file, {
      fs,
      cleanupComponent: 'native-handoff-claim-state',
    });
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
    cleanupComponent: 'native-handoff-claim-lock',
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
      const pruned = fileMutationLock.withFileMutationLockSync(file, () => (
        pruneTerminalClaimLocked(file, nowMs, retentionMs)
      ), {
        lockTimeoutMs: Number.isFinite(Number(opts.claimPruneLockTimeoutMs))
          ? Math.max(1, Math.min(100, Math.floor(Number(opts.claimPruneLockTimeoutMs))))
          : 1,
        lockRetryMs: 1,
      });
      if (pruned) removed += 1;
    } catch (error) {
      if (!error || error.code !== 'FILE_MUTATION_LOCK_TIMEOUT') throw error;
    }
  }
  return removed;
}

function claimMtimeMs(stat) {
  if (typeof stat.mtimeNs === 'bigint') return Number(stat.mtimeNs / 1_000_000n);
  return Number(stat.mtimeMs);
}

function normalizedTerminalClaim(body) {
  let parsed;
  try { parsed = JSON.parse(body); } catch { return null; }
  if (!parsed || parsed.version !== EVENT_VERSION) return null;
  if (parsed.state === 'terminal') {
    if (typeof parsed.decision !== 'string' || !parsed.decision
        || typeof parsed.status !== 'string' || !parsed.status
        || !Number.isFinite(Date.parse(parsed.completedAt))) return null;
    return parsed;
  }
  if (!parsed.state && Number.isFinite(Date.parse(parsed.claimedAt))) {
    return { ...parsed, state: 'terminal', status: 'legacy_consumed' };
  }
  return null;
}

function sameClaimArtifact(left, right) {
  return singleRegularFile(left) && singleRegularFile(right)
    && sameFile(left, right)
    && sameExactStatInteger(left.size, right.size)
    && sameSnapshotTime(left, right, 'mtimeNs', 'mtimeMs');
}

function eventCleanupIdentity(snapshot) {
  return {
    stat: snapshot.stat,
    sha256: snapshot.sha256,
  };
}

function sameAcceptedEvent(expected, current) {
  return !!expected && !!current
    && typeof expected.sha256 === 'string'
    && /^[0-9a-f]{64}$/.test(expected.sha256)
    && sameClaimArtifact(expected.stat, current.stat)
    && expected.sha256 === current.sha256;
}

function linkedArtifactStat(file, expectedLinks) {
  const stat = fs.lstatSync(file, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.dev <= 0n || stat.ino <= 0n
      || stat.nlink !== BigInt(expectedLinks)) {
    throw new Error('native handoff retained artifact has no stable identity');
  }
  return stat;
}

function sameLinkedArtifact(left, right) {
  return sameFile(left, right)
    && sameExactStatInteger(left.size, right.size)
    && sameSnapshotTime(left, right, 'mtimeNs', 'mtimeMs');
}

function removeExactNativeLink(file, expected, options = {}) {
  try {
    if (process.platform === 'win32') {
      privatePaths.removeExactPublicationFile(file, expected, { ...options, fs });
    } else {
      const current = linkedArtifactStat(file, Number(expected.nlink));
      if (!sameLinkedArtifact(expected, current)) {
        throw new Error('native handoff retained link changed before cleanup');
      }
      fs.unlinkSync(file);
      privatePaths.fsyncDirectory(path.dirname(file), { ...options, fs });
    }
  } catch (error) {
    if (!error.retainedPath && !error.additionalRetainedPath && !error.removedPath) {
      try { fs.lstatSync(file, { bigint: true }); error.retainedPath = file; }
      catch (inspectError) {
        if (inspectError && inspectError.code === 'ENOENT') error.removedPath = file;
      }
    }
    throw error;
  }
}

function removeExactNativeArtifact(file, snapshot, options = {}) {
  if (process.platform === 'win32') {
    try {
      privatePaths.removeExactPublicationFile(file, snapshot.stat, { ...options, fs });
      return;
    } catch (error) {
      const failure = new Error('native handoff artifact cleanup could not be completed');
      failure.code = 'NATIVE_HANDOFF_CLAIM_CLEANUP';
      for (const field of ['retainedPath', 'additionalRetainedPath', 'removedPath']) {
        if (error && error[field]) failure[field] = error[field];
      }
      if (!failure.retainedPath && !failure.additionalRetainedPath && !failure.removedPath) {
        try { fs.lstatSync(file, { bigint: true }); failure.retainedPath = file; }
        catch (inspectError) {
          if (inspectError && inspectError.code === 'ENOENT') failure.removedPath = file;
        }
      }
      failure.cause = error;
      throw failure;
    }
  }
  const guard = `${file}.unlink-guard.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  let filePresent = true;
  let guardPresent = false;
  try {
    fs.linkSync(file, guard);
    guardPresent = true;
    const source = linkedArtifactStat(file, 2);
    const linkedGuard = linkedArtifactStat(guard, 2);
    if (!sameLinkedArtifact(snapshot.stat, source) || !sameLinkedArtifact(snapshot.stat, linkedGuard)) {
      throw new Error('native handoff cleanup guard changed while linking');
    }
    fs.unlinkSync(file);
    filePresent = false;
    privatePaths.fsyncDirectory(path.dirname(file), { fs });
    const retained = readBoundedEventFileSnapshot(guard);
    if (!sameClaimArtifact(snapshot.stat, retained.stat) || snapshot.body !== retained.body) {
      throw new Error('native handoff cleanup guard changed after source removal');
    }
    fs.unlinkSync(guard);
    guardPresent = false;
    privatePaths.fsyncDirectory(path.dirname(file), { fs });
  } catch (error) {
    const failure = new Error('native handoff artifact cleanup could not be completed');
    failure.code = 'NATIVE_HANDOFF_CLAIM_CLEANUP';
    if (filePresent) failure.retainedPath = file;
    else failure.removedPath = file;
    if (guardPresent) failure.additionalRetainedPath = guard;
    failure.cause = error;
    throw failure;
  }
}

function restoreChangedClaim(quarantine, file) {
  const guard = `${quarantine}.restore.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  let guardPresent = false;
  let quarantinePresent = true;
  try {
    const source = readBoundedEventFileSnapshot(quarantine);
    fs.linkSync(quarantine, file);
    fs.linkSync(quarantine, guard);
    guardPresent = true;
    let target = linkedArtifactStat(file, 3);
    let retained = linkedArtifactStat(guard, 3);
    let sourceLink = linkedArtifactStat(quarantine, 3);
    if (!sameLinkedArtifact(source.stat, target) || !sameLinkedArtifact(source.stat, retained)
        || !sameLinkedArtifact(source.stat, sourceLink)) {
      throw new Error('changed native handoff artifact could not be identity-bound');
    }
    removeExactNativeLink(quarantine, sourceLink);
    quarantinePresent = false;
    target = linkedArtifactStat(file, 2);
    retained = linkedArtifactStat(guard, 2);
    if (!sameLinkedArtifact(source.stat, target) || !sameLinkedArtifact(source.stat, retained)) {
      throw new Error('changed native handoff artifact changed during restoration');
    }
    removeExactNativeLink(guard, retained);
    guardPresent = false;
    target = linkedArtifactStat(file, 1);
    if (!sameLinkedArtifact(source.stat, target)) {
      throw new Error('changed native handoff artifact changed after restoration');
    }
  } catch (error) {
    const failure = new Error('changed native handoff claim was retained during pruning');
    failure.code = 'NATIVE_HANDOFF_CLAIM_CLEANUP';
    if (error.retainedPath) failure.retainedPath = error.retainedPath;
    else if (quarantinePresent) failure.retainedPath = quarantine;
    if (error.additionalRetainedPath) failure.additionalRetainedPath = error.additionalRetainedPath;
    else if (guardPresent) failure.additionalRetainedPath = guard;
    if (error.removedPath) failure.removedPath = error.removedPath;
    failure.cause = error;
    throw failure;
  }
}

function removeAcceptedHandoffFile(file, expected, opts = {}) {
  if (!expected || !singleRegularFile(expected.stat)
      || typeof expected.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(expected.sha256)) {
    return false;
  }
  const quarantine = `${file}.processed.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  try {
    fs.renameSync(file, quarantine);
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    privatePaths.notifyCommittedCleanupWarning(error, {
      ...opts,
      cleanupComponent: 'native-handoff-event-cleanup',
    }, 'event-quarantine');
    return false;
  }
  let current;
  try { current = readBoundedEventFileSnapshot(quarantine); }
  catch (error) {
    error.retainedPath = quarantine;
    privatePaths.notifyCommittedCleanupWarning(error, {
      ...opts,
      cleanupComponent: 'native-handoff-event-cleanup',
    }, 'event-quarantine-verification');
    return false;
  }
  // Renaming can update ctime on Windows even when the exact accepted inode is
  // still present. Bind deletion to identity, size, mtime, and single-link
  // state; the original bounded read already proved the full contents.
  if (!sameAcceptedEvent(expected, current)) {
    try { restoreChangedClaim(quarantine, file); }
    catch (error) {
      privatePaths.notifyCommittedCleanupWarning(error, {
        ...opts,
        cleanupComponent: 'native-handoff-event-cleanup',
      }, 'event-replacement-restoration');
    }
    return false;
  }
  try {
    removeExactNativeArtifact(quarantine, current, opts);
    return true;
  } catch (error) {
    if (!error.retainedPath && !error.additionalRetainedPath && !error.removedPath) {
      error.retainedPath = quarantine;
    }
    privatePaths.notifyCommittedCleanupWarning(error, {
      ...opts,
      cleanupComponent: 'native-handoff-event-cleanup',
    }, 'event-removal');
    return false;
  }
}

function pruneTerminalClaimLocked(file, nowMs, retentionMs) {
  let snapshot;
  try { snapshot = readBoundedEventFileSnapshot(file); }
  catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
  if (!normalizedTerminalClaim(snapshot.body)) return false;
  const mtimeMs = claimMtimeMs(snapshot.stat);
  if (!Number.isFinite(mtimeMs) || nowMs - mtimeMs <= retentionMs) return false;
  const quarantine = `${file}.prune.${process.pid}.${crypto.randomBytes(12).toString('hex')}`;
  fs.renameSync(file, quarantine);
  let quarantined;
  try { quarantined = readBoundedEventFileSnapshot(quarantine); }
  catch (error) {
    const failure = new Error('native handoff claim pruning retained an unverifiable replacement');
    failure.code = 'NATIVE_HANDOFF_CLAIM_CLEANUP';
    failure.retainedPath = quarantine;
    failure.cause = error;
    throw failure;
  }
  if (!sameClaimArtifact(snapshot.stat, quarantined.stat) || snapshot.body !== quarantined.body) {
    restoreChangedClaim(quarantine, file);
    return false;
  }
  removeExactNativeArtifact(quarantine, quarantined);
  return true;
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
  readHandoffFileSnapshot,
  removeAcceptedHandoffFile,
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
