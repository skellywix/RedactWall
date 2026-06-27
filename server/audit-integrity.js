'use strict';
const crypto = require('crypto');

const ZERO = '0'.repeat(64);

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** Deterministic JSON: object keys sorted recursively so hashes stay stable. */
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

function queryContentHash(database, qid) {
  const r = database.prepare('SELECT data FROM queries WHERE id = ?').get(qid);
  return r ? sha(canonical(JSON.parse(r.data))) : null;
}

function verifyAuditChainForDatabase(database) {
  const rows = database.prepare('SELECT entry FROM audit ORDER BY seq ASC').all().map((r) => JSON.parse(r.entry));
  let prev = ZERO;
  for (const e of rows) {
    const { hash, ...body } = e;
    if (e.prevHash !== prev || sha(canonical(body)) !== hash) {
      return { ok: false, count: rows.length, brokenAt: e.id, reason: 'chain' };
    }
    prev = hash;
  }
  const latest = new Map();
  for (const e of rows) if (e.queryId && e.contentHash) latest.set(e.queryId, e);
  for (const [qid, e] of latest) {
    const live = queryContentHash(database, qid);
    if (live && live !== e.contentHash) {
      return { ok: false, count: rows.length, brokenAt: e.id, reason: 'evidence', queryId: qid };
    }
  }
  return { ok: true, count: rows.length };
}

module.exports = {
  ZERO,
  sha,
  canonical,
  queryContentHash,
  verifyAuditChainForDatabase,
};
