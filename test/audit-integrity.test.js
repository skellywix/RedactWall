'use strict';
/** Tamper-evidence primitives: canonical JSON, sha, and audit-chain verify. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const integrity = require('../server/audit-integrity');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

test('canonical serialization sorts object keys recursively and is order-stable', () => {
  const a = integrity.canonical({ b: 1, a: { d: 4, c: 3 } });
  const b = integrity.canonical({ a: { c: 3, d: 4 }, b: 1 });
  assert.strictEqual(a, b);
  assert.strictEqual(a, '{"a":{"c":3,"d":4},"b":1}');
});

test('canonical handles arrays, nulls, and primitives without reordering arrays', () => {
  assert.strictEqual(integrity.canonical([3, 1, 2]), '[3,1,2]');
  assert.strictEqual(integrity.canonical(null), 'null');
  assert.strictEqual(integrity.canonical('x'), '"x"');
  assert.strictEqual(integrity.canonical(42), '42');
  assert.strictEqual(integrity.canonical([{ b: 2, a: 1 }]), '[{"a":1,"b":2}]');
});

test('sha matches a straight sha256 hex digest and ZERO is 64 zeroes', () => {
  assert.strictEqual(integrity.sha('promptwall'), sha256('promptwall'));
  assert.strictEqual(integrity.ZERO, '0'.repeat(64));
});

// A tiny in-memory stand-in for the better-sqlite3 surface the verifier uses.
function fakeDb({ audit = [], queries = {} }) {
  return {
    prepare(sql) {
      if (/FROM audit/.test(sql)) {
        return { all: () => audit.map((entry) => ({ entry: JSON.stringify(entry) })) };
      }
      return { get: (qid) => (queries[qid] ? { data: JSON.stringify(queries[qid]) } : undefined) };
    },
  };
}

function chainedEntry(prevHash, body) {
  const full = { prevHash, ...body };
  return { ...full, hash: integrity.sha(integrity.canonical(full)) };
}

test('verifyAuditChainForDatabase accepts a well-formed chain', () => {
  const e1 = chainedEntry(integrity.ZERO, { id: 'a1', action: 'CREATED' });
  const e2 = chainedEntry(e1.hash, { id: 'a2', action: 'DENIED' });
  const result = integrity.verifyAuditChainForDatabase(fakeDb({ audit: [e1, e2] }));
  assert.deepStrictEqual(result, { ok: true, count: 2 });
});

test('verifyAuditChainForDatabase flags a broken hash link', () => {
  const e1 = chainedEntry(integrity.ZERO, { id: 'a1', action: 'CREATED' });
  const e2 = chainedEntry('wrong-prev-hash', { id: 'a2', action: 'DENIED' });
  const result = integrity.verifyAuditChainForDatabase(fakeDb({ audit: [e1, e2] }));
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.reason, 'chain');
  assert.strictEqual(result.brokenAt, 'a2');
});

test('verifyAuditChainForDatabase flags edited evidence via contentHash', () => {
  const query = { id: 'q1', status: 'approved', note: 'original' };
  const contentHash = integrity.sha(integrity.canonical(query));
  const e1 = chainedEntry(integrity.ZERO, { id: 'a1', action: 'APPROVED', queryId: 'q1', contentHash });
  const tampered = { ...query, note: 'rewritten' };
  const result = integrity.verifyAuditChainForDatabase(fakeDb({ audit: [e1], queries: { q1: tampered } }));
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.reason, 'evidence');
  assert.strictEqual(result.queryId, 'q1');
});

test('queryContentHash returns the canonical hash or null when absent', () => {
  const query = { id: 'q9', status: 'pending' };
  const db = fakeDb({ queries: { q9: query } });
  assert.strictEqual(integrity.queryContentHash(db, 'q9'), integrity.sha(integrity.canonical(query)));
  assert.strictEqual(integrity.queryContentHash(db, 'missing'), null);
});
