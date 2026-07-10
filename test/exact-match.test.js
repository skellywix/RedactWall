'use strict';
/** Exact Data Match (EDM): versioned SHA-256 random-ID fingerprints, no plaintext in the pack. */
const test = require('node:test');
const assert = require('node:assert');
const D = require('../detection-engine/detect');

const SALT = 'unit-test-salt-abc123-0123456789abcdef';
const PROFILE = {
  formatVersion: 2,
  algorithm: 'sha256',
  valuePolicy: 'offline-random-id-v1',
  minLen: 20,
  maxWords: 1,
};

function watchlist(values, extra = {}) {
  const fingerprints = [];
  for (const v of values) {
    fingerprints.push(D.edmFingerprint(v, SALT));
    const digits = v.replace(/\D/g, '');
    if (digits.length >= 6) fingerprints.push(D.edmFingerprint(digits, SALT));
  }
  return { ...PROFILE, salt: SALT, fingerprints, enabled: true, ...extra };
}

test('exact match flags a watchlisted id embedded in a sentence', () => {
  const id = '550e8400-e29b-41d4-a716-446655440000';
  const cfg = watchlist([id]);
  const a = D.analyze(`Please pull opaque record ${id} for the payoff quote.`, { exactMatch: cfg });
  const hit = a.findings.find((f) => f.type === 'EXACT_MATCH');
  assert.ok(hit, 'watchlisted id should be flagged');
  assert.strictEqual(hit.value, id);
  assert.strictEqual(hit.severity, 4);
});

test('exact match catches a high-entropy mixed token', () => {
  const token = 'AbCdEfGhIjKlMnOpQrStUv12';
  const cfg = watchlist([token]);
  const a = D.analyze(`The opaque record ${token} was selected.`, { exactMatch: cfg });
  assert.ok(a.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('exact match normalizes separators for digit values', () => {
  const cfg = watchlist(['123456789012345678901234567890']);
  const a = D.analyze('Reference id 1234567890-1234567890-1234567890 needs review.', { exactMatch: cfg });
  assert.ok(a.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('a near-miss value does NOT match', () => {
  const cfg = watchlist(['550e8400-e29b-41d4-a716-446655440000']);
  const a = D.analyze('Look up opaque record 550e8400-e29b-41d4-a716-446655440001 instead.', { exactMatch: cfg });
  assert.ok(!a.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('no fingerprints configured => EDM never runs', () => {
  const a = D.analyze('opaque 550e8400-e29b-41d4-a716-446655440000', {
    exactMatch: { ...PROFILE, salt: SALT, fingerprints: [] },
  });
  assert.ok(!a.findings.some((f) => f.type === 'EXACT_MATCH'));
});

test('fingerprint is a stable salted SHA-256 digest with no plaintext', () => {
  const fp = D.edmFingerprint('550e8400-e29b-41d4-a716-446655440000', SALT);
  assert.match(fp, /^[0-9a-f]{64}$/);
  assert.strictEqual(fp, D.edmFingerprint('  550E8400-E29B-41D4-A716-446655440000 ', SALT), 'normalization is stable');
  assert.notStrictEqual(fp, D.edmFingerprint('550e8400-e29b-41d4-a716-446655440000', 'different-salt'), 'salt changes the digest');
});

test('EDM uses the versioned SHA-256 high-entropy profile and rejects legacy packs', () => {
  const fp = D.edmFingerprint('550e8400-e29b-41d4-a716-446655440000', SALT);
  assert.match(fp, /^[0-9a-f]{64}$/);
  const legacy = D.normalizeExactMatchConfig({
    salt: SALT,
    minLen: 6,
    fingerprints: ['0123456789abcdef'],
    enabled: true,
  });
  assert.strictEqual(legacy.enabled, false);
});

test('EXACT_MATCH is a known, policy-addressable detector id', () => {
  const ids = new Set(D.listDetectors({}).map((d) => d.id));
  assert.ok(ids.has('EXACT_MATCH'));
});
