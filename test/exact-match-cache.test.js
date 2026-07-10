'use strict';
/**
 * The EDM loader must return a STABLE config object across calls so the
 * detection engine's per-object EDM cache (keyed by object identity) hits on
 * the hot path, and must re-read only when the file actually changes.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const PROFILE = {
  formatVersion: 2,
  algorithm: 'sha256',
  valuePolicy: 'offline-random-id-v1',
  minLen: 20,
  maxWords: 1,
};
const SALT = '0123456789abcdef0123456789abcdef';
const FP_A = '01'.repeat(32);
const FP_B = 'ab'.repeat(32);
function pack(overrides = {}) {
  return { ...PROFILE, enabled: true, salt: SALT, fingerprints: [FP_A], ...overrides };
}

const cfgPath = path.join(os.tmpdir(), 'ps-edm-' + crypto.randomBytes(5).toString('hex') + '.json');
process.env.REDACTWALL_EXACT_MATCH_PATH = cfgPath;
fs.writeFileSync(cfgPath, JSON.stringify(pack()));

const edm = require('../server/exact-match');

function writeConfig(file, value) {
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
  const future = new Date(Date.now() + 5000);
  fs.utimesSync(file, future, future);
}

test('exactMatchConfig returns the SAME object across calls (EDM cache stays warm)', () => {
  const a = edm.exactMatchConfig();
  const b = edm.exactMatchConfig();
  assert.ok(a && b);
  assert.strictEqual(a, b, 'identical object identity so analyze() reuses its normalized EDM set');
});

test('the config is re-read after the file changes on disk', () => {
  const before = edm.exactMatchConfig();
  // Change content AND bump mtime so the size/mtime signature differs.
  const nextSalt = 'fedcba9876543210fedcba9876543210';
  fs.writeFileSync(cfgPath, JSON.stringify(pack({ salt: nextSalt, fingerprints: [FP_A, FP_B] })));
  const future = new Date(Date.now() + 5000);
  fs.utimesSync(cfgPath, future, future);
  const after = edm.exactMatchConfig();
  assert.notStrictEqual(after, before, 'a changed watchlist must invalidate the cache');
  assert.strictEqual(after.salt, nextSalt);
});

test('an empty watchlist disables EDM (null) so the hot path skips it', () => {
  fs.writeFileSync(cfgPath, JSON.stringify(pack({ enabled: false, fingerprints: [] })));
  const future = new Date(Date.now() + 10000);
  fs.utimesSync(cfgPath, future, future);
  assert.strictEqual(edm.exactMatchConfig(), null);
});

test('explicit missing and malformed EDM packs fail readiness', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-health-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const missingPath = path.join(dir, 'missing.json');
  const missing = edm.createLoader(missingPath, true);

  assert.strictEqual(missing.exactMatchConfig(), null);
  assert.deepStrictEqual(missing.status(), {
    ok: false,
    configured: true,
    enabled: false,
    fingerprints: 0,
    error: 'configured exact-match pack is missing',
    usingLastKnownGood: false,
  });

  const malformedPath = path.join(dir, 'malformed.json');
  writeConfig(malformedPath, '{not json');
  const malformed = edm.createLoader(malformedPath, true);
  assert.strictEqual(malformed.exactMatchConfig(), null);
  assert.strictEqual(malformed.status().ok, false);
  assert.match(malformed.status().error, /valid JSON/i);
});

test('EDM retains one stable last-known-good object after corruption or disappearance', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-lkg-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'exact-match.json');
  writeConfig(file, pack());
  const loader = edm.createLoader(file, true);
  const good = loader.exactMatchConfig();

  assert.ok(good);
  assert.strictEqual(loader.exactMatchConfig(), good, 'unchanged hot-path config keeps object identity');

  writeConfig(file, '{broken json');
  assert.strictEqual(loader.exactMatchConfig(), good, 'malformed update retains the exact LKG object');
  assert.strictEqual(loader.status().usingLastKnownGood, true);

  fs.rmSync(file);
  assert.strictEqual(loader.exactMatchConfig(), good, 'disappearance retains the exact LKG object');
  assert.deepStrictEqual(loader.status(), {
    ok: false,
    configured: true,
    enabled: true,
    fingerprints: 1,
    error: 'exact-match pack disappeared after a successful load',
    usingLastKnownGood: true,
  });
});

test('nominally enabled EDM packs reject missing salt and every silently dropped fingerprint', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-invalid-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cases = [
    { name: 'legacy-profile', value: { enabled: true, salt: SALT, fingerprints: ['0123456789abcdef'] }, error: /version 2 SHA-256/i },
    { name: 'missing-salt', value: pack({ salt: '' }), error: /salt/i },
    { name: 'invalid-min-len', value: pack({ minLen: 6 }), error: /minLen/i },
    { name: 'invalid-max-words', value: pack({ maxWords: 5 }), error: /maxWords/i },
    { name: 'invalid-fingerprint', value: pack({ fingerprints: ['not-a-fingerprint'] }), error: /fingerprint/i },
    { name: 'non-string-fingerprint', value: pack({ fingerprints: [1234567890123456] }), error: /fingerprint/i },
    { name: 'duplicate-fingerprint', value: pack({ fingerprints: [FP_A, FP_A.toUpperCase()] }), error: /unique/i },
    { name: 'empty-enabled', value: pack({ fingerprints: [] }), error: /fingerprint/i },
  ];

  for (const entry of cases) {
    const file = path.join(dir, `${entry.name}.json`);
    writeConfig(file, entry.value);
    const loader = edm.createLoader(file, true);
    assert.strictEqual(loader.exactMatchConfig(), null, entry.name);
    assert.strictEqual(loader.status().ok, false, entry.name);
    assert.match(loader.status().error, entry.error, entry.name);
  }
});

test('never-seen absent optional native EDM config remains a healthy disabled default', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-optional-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const loader = edm.createLoader(path.join(dir, 'optional.json'), false);

  assert.strictEqual(loader.exactMatchConfig(), null);
  assert.deepStrictEqual(loader.status(), {
    ok: true,
    configured: false,
    enabled: false,
    fingerprints: 0,
    error: null,
    usingLastKnownGood: false,
  });
});

test('optional EDM config treats inspection failures as unhealthy, not absent', () => {
  const deniedFs = {
    ...fs,
    statSync() {
      const error = new Error('synthetic access denial');
      error.code = 'EACCES';
      throw error;
    },
  };
  const loader = edm.createLoader('unreadable.json', false, deniedFs);

  assert.strictEqual(loader.exactMatchConfig(), null);
  assert.deepStrictEqual(loader.status(), {
    ok: false,
    configured: true,
    enabled: false,
    fingerprints: 0,
    error: 'exact-match pack could not be inspected',
    usingLastKnownGood: false,
  });
});

test('EDM retries a transient read failure even when the file signature is unchanged', () => {
  const payload = JSON.stringify(pack());
  let reads = 0;
  const flakyFs = {
    ...fs,
    statSync: () => ({ mtimeMs: 1, ctimeMs: 1, size: payload.length }),
    readFileSync() {
      reads += 1;
      if (reads === 1) {
        const error = new Error('synthetic read failure');
        error.code = 'EIO';
        throw error;
      }
      return payload;
    },
  };
  const loader = edm.createLoader('flaky.json', true, flakyFs);

  assert.strictEqual(loader.exactMatchConfig(), null);
  assert.ok(loader.exactMatchConfig(), 'the unchanged file is retried after transient I/O failure');
  assert.strictEqual(loader.status().ok, true);
  assert.strictEqual(reads, 2);
});
