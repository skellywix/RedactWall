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
  assert.deepStrictEqual(edm.valuesFromCsv(csv, 'Member Number'), {
    values: [{ value: '900123456', line: 2 }, { value: '900987654', line: 3 }],
    skipped: [],
  });
});

test('valuesFromCsv extracts a column by 1-based index (all rows, no header skip)', () => {
  assert.deepStrictEqual(edm.valuesFromCsv('900123456,Main\n900987654,East', '1'), {
    values: [{ value: '900123456', line: 1 }, { value: '900987654', line: 2 }],
    skipped: [],
  });
});

test('valuesFromCsv reports true source lines across blank lines', () => {
  const csv = 'Member Number\n900123456\n\n900987654';
  assert.deepStrictEqual(edm.valuesFromCsv(csv, 'Member Number').values.map((v) => v.line), [2, 4]);
});

test('valuesFromCsv throws for an unknown header without echoing header cells', () => {
  try {
    edm.valuesFromCsv('Name,Branch\nJane,900123456', 'Member Number');
    assert.fail('expected an unknown-header error');
  } catch (e) {
    assert.match(e.message, /not found in CSV header \(2 columns\)/);
    assert.ok(!e.message.includes('Jane') && !e.message.includes('900123456') && !e.message.includes('Branch'),
      'error must not echo file contents');
  }
});

test('valuesFromCsv rejects duplicate matching headers as ambiguous', () => {
  assert.throws(() => edm.valuesFromCsv('ID,id\n,900123456', 'id'), /matches 2 CSV header columns/);
});

test('valuesFromCsv fails closed on structural quote problems', () => {
  assert.throws(() => edm.valuesFromCsv('ID\n"unterminated', 'ID'), /CSV row 2: quote not closed/);
  assert.throws(() => edm.valuesFromCsv('ID\nab"cd', 'ID'), /CSV row 2: quote opened mid-field/);
  // An embedded newline in a quoted field surfaces as an unclosed quote.
  assert.throws(() => edm.valuesFromCsv('ID,Note\n900123456,"line1\nline2"', 'ID'), /quote not closed/);
});

test('valuesFromCsv fails closed on empty selected cells unless sparse is allowed', () => {
  const csv = 'Name,Member Number\nJane,\nJohn,900987654';
  assert.throws(() => edm.valuesFromCsv(csv, 'Member Number'), /empty or missing selected column/);
  assert.deepStrictEqual(edm.valuesFromCsv(csv, 'Member Number', { allowSparse: true }), {
    values: [{ value: '900987654', line: 3 }],
    skipped: [2],
  });
});

test('valuesFromCsv treats an out-of-range index as skipped rows, not silent success', () => {
  assert.throws(() => edm.valuesFromCsv('a,b\nc,d', '9'), /empty or missing selected column/);
  assert.deepStrictEqual(edm.valuesFromCsv('a,b\nc,d', '9', { allowSparse: true }), { values: [], skipped: [1, 2] });
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

test('edm-fingerprint --column fails closed on empty cells; --allow-sparse skips and reports them', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-sparse-'));
  try {
    const csv = path.join(dir, 'random-identifiers.csv');
    const out = path.join(dir, 'exact-match.json');
    fs.writeFileSync(csv, 'Label,Random Identifier\nJane,550e8400-e29b-41d4-a716-446655440000\nJohn,\n');
    assert.throws(() => execFileSync(
      'node',
      ['scripts/edm-fingerprint.js', '--in', csv, '--column', 'Random Identifier', '--out', out],
      { cwd: path.join(__dirname, '..'), stdio: 'pipe' },
    ), /empty or missing selected column/);
    assert.strictEqual(fs.existsSync(out), false);
    const stdout = execFileSync(
      'node',
      ['scripts/edm-fingerprint.js', '--in', csv, '--column', 'Random Identifier', '--allow-sparse', '--out', out],
      { cwd: path.join(__dirname, '..') },
    ).toString();
    assert.match(stdout, /rows skipped \(empty selected column\): 1/);
    assert.ok(JSON.parse(fs.readFileSync(out, 'utf8')).fingerprints.length >= 1);
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
