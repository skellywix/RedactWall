'use strict';
const crypto = require('crypto');

const ZERO = '0'.repeat(64);
const CHECKPOINT_VERSION = 1;

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function normalizedKey(key) {
  const value = Buffer.isBuffer(key) ? key : Buffer.from(String(key || ''), 'utf8');
  if (value.length < 32) throw new TypeError('audit authentication key must be at least 32 bytes');
  return value;
}

function hmac(key, value) {
  return crypto.createHmac('sha256', normalizedKey(key)).update(value).digest('hex');
}

function sameHex(left, right) {
  if (!/^[a-f0-9]{64}$/i.test(String(left || '')) || !/^[a-f0-9]{64}$/i.test(String(right || ''))) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

/** Deterministic JSON: object keys sorted recursively so hashes stay stable. */
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

function authenticatedEntry(prevHash, body, key) {
  const unsigned = { ...body, prevHash };
  const hash = sha(canonical(unsigned));
  const mac = hmac(key, canonical({ ...unsigned, hash }));
  return { ...unsigned, hash, mac };
}

function validAuthenticatedEntry(entry, key) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const { hash, mac, ...body } = entry;
  if (sha(canonical(body)) !== hash || !mac) return false;
  return sameHex(mac, hmac(key, canonical({ ...body, hash })));
}

function checkpointBody(count, head, seq = count) {
  if (!Number.isSafeInteger(count) || count < 0) throw new TypeError('audit checkpoint count is invalid');
  if (!Number.isSafeInteger(seq) || seq < 0) throw new TypeError('audit checkpoint sequence is invalid');
  if (!/^[a-f0-9]{64}$/i.test(String(head || ''))) throw new TypeError('audit checkpoint head is invalid');
  return { version: CHECKPOINT_VERSION, count, seq, head: String(head).toLowerCase() };
}

function createCheckpoint(count, head, key, seq = count) {
  const body = checkpointBody(count, head, seq);
  return { ...body, mac: hmac(key, canonical(body)) };
}

function validCheckpoint(checkpoint, key) {
  try {
    if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) return false;
    const body = checkpointBody(checkpoint.count, checkpoint.head, checkpoint.seq);
    if (checkpoint.version !== CHECKPOINT_VERSION) return false;
    return sameHex(checkpoint.mac, hmac(key, canonical(body)));
  } catch {
    return false;
  }
}

function queryContentHash(database, qid) {
  const r = database.prepare('SELECT data FROM queries WHERE id = ?').get(qid);
  return r ? sha(canonical(JSON.parse(r.data))) : null;
}

/**
 * Content-hash a set of query ids in bulk. One SELECT per chunk instead of one
 * per id: on the Postgres bridge every lookup is a blocking round trip, so the
 * old per-id loop (called from several polled routes) froze the event loop at
 * scale. Missing rows are simply absent from the returned map.
 */
function batchQueryContentHashes(database, ids, chunkSize = 500) {
  const hashes = new Map();
  for (let i = 0; i < ids.length; i += chunkSize) {
    const chunk = ids.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(', ');
    const rows = database.prepare(`SELECT id, data FROM queries WHERE id IN (${placeholders})`).all(...chunk);
    for (const r of rows) hashes.set(r.id, sha(canonical(JSON.parse(r.data))));
  }
  return hashes;
}

function verifyAuditChainForDatabase(database, options = {}) {
  const storedRows = database.prepare('SELECT seq, entry FROM audit ORDER BY seq ASC').all();
  const rows = storedRows.map((r) => JSON.parse(r.entry));
  const key = options.key ? normalizedKey(options.key) : null;
  const checkpoint = options.checkpoint || null;
  if (key && checkpoint && !validCheckpoint(checkpoint, key)) {
    return { ok: false, count: rows.length, reason: 'checkpoint-authentication' };
  }
  if (key && !checkpoint && options.allowCheckpointBootstrap !== true) {
    return { ok: false, count: rows.length, reason: 'checkpoint-missing' };
  }
  if (checkpoint && rows.length < checkpoint.count) {
    return { ok: false, count: rows.length, reason: 'checkpoint-truncated' };
  }
  let prev = ZERO;
  for (let index = 0; index < rows.length; index += 1) {
    const e = rows[index];
    const { hash, mac, ...body } = e;
    if (e.prevHash !== prev || sha(canonical(body)) !== hash) {
      return { ok: false, count: rows.length, brokenAt: e.id, reason: 'chain' };
    }
    if (key && mac && !validAuthenticatedEntry(e, key)) {
      return { ok: false, count: rows.length, brokenAt: e.id, reason: 'entry-authentication' };
    }
    const legacyCovered = checkpoint && index < checkpoint.count;
    const bootstrapCovered = !checkpoint && options.allowCheckpointBootstrap === true;
    if (key && !mac && !legacyCovered && !bootstrapCovered) {
      return { ok: false, count: rows.length, brokenAt: e.id, reason: 'entry-authentication-missing' };
    }
    prev = hash;
  }
  if (checkpoint) {
    const checkpointHead = checkpoint.count ? rows[checkpoint.count - 1].hash : ZERO;
    if (!sameHex(checkpoint.head, checkpointHead)) {
      return { ok: false, count: rows.length, reason: 'checkpoint-diverged' };
    }
  }
  const latest = new Map();
  for (const e of rows) if (e.queryId && e.contentHash) latest.set(e.queryId, e);
  const queryIds = database.prepare('SELECT id FROM queries').all().map((row) => row.id);
  for (const queryId of queryIds) {
    if (!latest.has(queryId)) {
      return { ok: false, count: rows.length, reason: 'evidence-unanchored', queryId };
    }
  }
  const liveHashes = batchQueryContentHashes(database, [...latest.keys()]);
  for (const [qid, e] of latest) {
    const live = liveHashes.get(qid);
    if (!live) {
      // The audit entry binds this query's evidence, but the query row is gone.
      // Deletion of bound evidence is tampering — nothing legitimately removes a
      // query row (retention purge keeps the row and re-anchors), so a missing
      // live hash is a verification failure, not a silent pass.
      return { ok: false, count: rows.length, brokenAt: e.id, reason: 'evidence-missing', queryId: qid };
    }
    if (live !== e.contentHash) {
      return { ok: false, count: rows.length, brokenAt: e.id, reason: 'evidence', queryId: qid };
    }
  }
  if (key && typeof options.onVerified === 'function') {
    const lastSeq = storedRows.length ? Number(storedRows[storedRows.length - 1].seq || storedRows.length) : 0;
    options.onVerified(createCheckpoint(rows.length, prev, key, lastSeq));
  }
  return { ok: true, count: rows.length };
}

module.exports = {
  ZERO,
  CHECKPOINT_VERSION,
  sha,
  hmac,
  canonical,
  authenticatedEntry,
  validAuthenticatedEntry,
  createCheckpoint,
  validCheckpoint,
  queryContentHash,
  verifyAuditChainForDatabase,
};
