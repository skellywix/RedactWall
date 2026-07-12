'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const edm = require('../scripts/edm-fingerprint');

test('parseCsvLine handles quotes, escaped quotes, and commas in fields', () => {
  assert.deepStrictEqual(edm.parseCsvLine('a,b,c'), ['a', 'b', 'c']);
  assert.deepStrictEqual(edm.parseCsvLine('"Public, Jane",100'), ['Public, Jane', '100']);
  assert.deepStrictEqual(edm.parseCsvLine('"she said ""hi""",x'), ['she said "hi"', 'x']);
});

test('valuesFromCsv extracts a column by header name (skipping the header)', () => {
  const csv = 'Name,Member Number,Branch\n"Public, Jane",900123456,Main\nJohn Doe,900987654,East';
  assert.deepStrictEqual(edm.valuesFromCsv(csv, 'Member Number'), ['900123456', '900987654']);
});

test('valuesFromCsv extracts a column by 1-based index (all rows, no header skip)', () => {
  assert.deepStrictEqual(edm.valuesFromCsv('900123456,Main\n900987654,East', '1'), ['900123456', '900987654']);
});

test('valuesFromCsv throws a clear error for an unknown header', () => {
  assert.throws(() => edm.valuesFromCsv('Name,Branch\nx,y', 'Member Number'), /not found in CSV header/);
});

test('edm-fingerprint --column writes only salted hashes for a high-entropy column, never the plaintext', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-'));
  try {
    const csv = path.join(dir, 'members.csv');
    const out = path.join(dir, 'exact-match.json');
    // The offline-random-id-v1 profile only accepts syntactically random,
    // high-entropy identifiers; enumerable member numbers are covered by
    // built-in/custom detectors instead. --column fingerprints such a column
    // (e.g. a random member-portal token export) without copying plaintext.
    const tokenA = crypto.randomUUID();
    const tokenB = crypto.randomUUID();
    fs.writeFileSync(csv, `Name,Portal Token\nJane,${tokenA}\nJohn,${tokenB}\n`);
    execFileSync('node', ['scripts/edm-fingerprint.js', '--in', csv, '--column', 'Portal Token', '--out', out], {
      cwd: path.join(__dirname, '..'),
    });
    const written = fs.readFileSync(out, 'utf8');
    assert.ok(!written.includes(tokenA), 'plaintext token must not be written');
    assert.ok(!written.includes('Jane'), 'plaintext name must not be written');
    const parsed = JSON.parse(written);
    assert.strictEqual(parsed.enabled, true);
    assert.ok(parsed.fingerprints.length >= 2, 'fingerprints were produced');
    assert.ok(parsed.salt && parsed.salt.length >= 16, 'a salt was written');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('edm-fingerprint --column fails closed for a low-entropy (enumerable) column', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-lowentropy-'));
  try {
    const csv = path.join(dir, 'members.csv');
    const out = path.join(dir, 'exact-match.json');
    // Enumerable member numbers must not enter an offline sensor-visible pack:
    // they are brute-forceable. The v2 profile rejects them and writes nothing.
    fs.writeFileSync(csv, 'Name,Member Number\nJane,900123456\nJohn,900987654\n');
    assert.throws(() => execFileSync('node', [
      'scripts/edm-fingerprint.js', '--in', csv, '--column', 'Member Number', '--out', out,
    ], { cwd: path.join(__dirname, '..'), encoding: 'utf8' }), /offline-random-id-v1/);
    assert.strictEqual(fs.existsSync(out), false, 'no pack is written when values are ineligible');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
