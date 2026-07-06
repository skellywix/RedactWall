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

const cfgPath = path.join(os.tmpdir(), 'ps-edm-' + crypto.randomBytes(5).toString('hex') + '.json');
process.env.REDACTWALL_EXACT_MATCH_PATH = cfgPath;
fs.writeFileSync(cfgPath, JSON.stringify({ salt: 's', fingerprints: ['0123456789abcdef'] }));

const edm = require('../server/exact-match');

test('exactMatchConfig returns the SAME object across calls (EDM cache stays warm)', () => {
  const a = edm.exactMatchConfig();
  const b = edm.exactMatchConfig();
  assert.ok(a && b);
  assert.strictEqual(a, b, 'identical object identity so analyze() reuses its normalized EDM set');
});

test('the config is re-read after the file changes on disk', () => {
  const before = edm.exactMatchConfig();
  // Change content AND bump mtime so the size/mtime signature differs.
  fs.writeFileSync(cfgPath, JSON.stringify({ salt: 's2', fingerprints: ['0123456789abcdef', 'fedcba9876543210'] }));
  const future = new Date(Date.now() + 5000);
  fs.utimesSync(cfgPath, future, future);
  const after = edm.exactMatchConfig();
  assert.notStrictEqual(after, before, 'a changed watchlist must invalidate the cache');
  assert.strictEqual(after.salt, 's2');
});

test('an empty watchlist disables EDM (null) so the hot path skips it', () => {
  fs.writeFileSync(cfgPath, JSON.stringify({ salt: 's', fingerprints: [] }));
  const future = new Date(Date.now() + 10000);
  fs.utimesSync(cfgPath, future, future);
  assert.strictEqual(edm.exactMatchConfig(), null);
});
