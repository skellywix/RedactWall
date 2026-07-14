'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
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

test('edm-fingerprint --column writes only salted hashes, never the plaintext', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-'));
  try {
    const csv = path.join(dir, 'random-identifiers.csv');
    const out = path.join(dir, 'exact-match.json');
    const first = '550e8400-e29b-41d4-a716-446655440000';
    const second = 'AbCdEfGhIjKlMnOpQrStUv12';
    fs.writeFileSync(csv, `Label,Random Identifier\nJane,${first}\nJohn,${second}\n`);
    execFileSync('node', ['scripts/edm-fingerprint.js', '--in', csv, '--column', 'Random Identifier', '--out', out], {
      cwd: path.join(__dirname, '..'),
    });
    const written = fs.readFileSync(out, 'utf8');
    assert.ok(!written.includes(first), 'plaintext random identifier must not be written');
    assert.ok(!written.includes(second), 'plaintext random identifier must not be written');
    assert.ok(!written.includes('Jane'), 'plaintext name must not be written');
    const parsed = JSON.parse(written);
    assert.strictEqual(parsed.enabled, true);
    assert.ok(parsed.fingerprints.length >= 2, 'fingerprints were produced');
    assert.ok(parsed.salt && parsed.salt.length >= 16, 'a salt was written');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('edm-fingerprint --column rejects enumerable roster values without publishing output', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-reject-'));
  try {
    const csv = path.join(dir, 'members.csv');
    const out = path.join(dir, 'exact-match.json');
    fs.writeFileSync(csv, 'Name,Member Number\nJane,900123456\nJohn,900987654\n');
    assert.throws(() => execFileSync(
      'node',
      ['scripts/edm-fingerprint.js', '--in', csv, '--column', 'Member Number', '--out', out],
      { cwd: path.join(__dirname, '..'), stdio: 'pipe' },
    ));
    assert.strictEqual(fs.existsSync(out), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
