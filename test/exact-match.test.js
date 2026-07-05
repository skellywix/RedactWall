'use strict';
/** Exact Data Match (EDM): salted one-way fingerprints, no plaintext at rest. */
const test = require('node:test');
const assert = require('node:assert');
const D = require('../detection-engine/detect');

const SALT = 'unit-test-salt-abc123';

function watchlist(values, extra = {}) {
  const fingerprints = [];
  for (const v of values) {
    fingerprints.push(D.edmFingerprint(v, SALT));
    const digits = v.replace(/\D/g, '');
    if (digits.length >= 6) fingerprints.push(D.edmFingerprint(digits, SALT));
  }
  return { salt: SALT, fingerprints, enabled: true, ...extra };
}

test('exact match flags a watchlisted id embedded in a sentence', () => {
  const cfg = watchlist(['ACME-MEMBER-77413']);
  const a = D.analyze('Please pull member ACME-MEMBER-77413 for the payoff quote.', { exactMatch: cfg });
  const hit = a.findings.find((f) => f.type === 'EXACT_MATCH');
  assert.ok(hit, 'watchlisted id should be flagged');
  assert.strictEqual(hit.value, 'ACME-MEMBER-77413');
  assert.strictEqual(hit.severity, 4);
});

test('exact match catches a multi-word watchlisted name', () => {
  const cfg = watchlist(['Jonathan Q Public']);
  const a = D.analyze('The account holder Jonathan Q Public called about a wire.', { exactMatch: cfg });
  assert.ok(a.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('exact match normalizes separators for digit values', () => {
  const cfg = watchlist(['900123456']);
  const a = D.analyze('Reference id 900-123-456 needs review.', { exactMatch: cfg });
  assert.ok(a.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('a near-miss value does NOT match', () => {
  const cfg = watchlist(['ACME-MEMBER-77413']);
  const a = D.analyze('Look up member ACME-MEMBER-00000 instead.', { exactMatch: cfg });
  assert.ok(!a.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('no fingerprints configured => EDM never runs', () => {
  const a = D.analyze('member ACME-MEMBER-77413', { exactMatch: { salt: SALT, fingerprints: [] } });
  assert.ok(!a.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('fingerprint is a stable, irreversible 16-hex digest (no plaintext leak)', () => {
  const fp = D.edmFingerprint('ACME-MEMBER-77413', SALT);
  assert.match(fp, /^[0-9a-f]{16}$/);
  assert.strictEqual(fp, D.edmFingerprint('  acme-member-77413 ', SALT), 'normalization is stable');
  assert.notStrictEqual(fp, D.edmFingerprint('ACME-MEMBER-77413', 'different-salt'), 'salt changes the digest');
});

test('EXACT_MATCH is a known, policy-addressable detector id', () => {
  const ids = new Set(D.listDetectors({}).map((d) => d.id));
  assert.ok(ids.has('EXACT_MATCH'));
});
