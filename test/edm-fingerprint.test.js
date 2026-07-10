'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const detector = require('../detection-engine/detect');
const privatePaths = require('../server/private-path');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'edm-fingerprint.js');
const SALT = '0123456789abcdef0123456789abcdef0123456789abcdef';
const UUID = '550e8400-e29b-41d4-a716-446655440000';

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-edm-cli-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return {
    dir,
    input: path.join(dir, 'input.txt'),
    output: path.join(dir, 'exact-match.json'),
  };
}

function run(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 15_000,
  });
}

test('EDM SHA-256 fingerprint matches the platform cryptographic implementation', () => {
  const normalized = UUID.toLowerCase();
  const expected = crypto.createHash('sha256').update(`${SALT}\0${normalized}`).digest('hex');
  assert.strictEqual(detector.edmFingerprint(UUID, SALT), expected);
});

test('offline EDM accepts only syntactically high-entropy random identifiers', () => {
  for (const value of [
    UUID,
    '0123456789abcdef01234567',
    '123456789012345678901234567890',
    'AbCdEfGhIjKlMnOpQrStUv12',
  ]) assert.strictEqual(detector.edmValueEligibility(value).ok, true, value);

  for (const value of [
    '123456',
    '900123456',
    'ACME-MEMBER-77413',
    'Jonathan Q Public',
  ]) assert.strictEqual(detector.edmValueEligibility(value).ok, false, value);
});

test('CLI rejects enumerable identifiers without writing a pack or echoing plaintext', (t) => {
  const f = fixture(t);
  const plaintext = 'ACME-MEMBER-77413';
  fs.writeFileSync(f.input, `${plaintext}\n123456\n`);
  const result = run(['--in', f.input, '--out', f.output, '--salt', SALT]);

  assert.notStrictEqual(result.status, 0);
  assert.match(result.stderr, /offline-random-id-v1/);
  assert.strictEqual(result.stderr.includes(plaintext), false);
  assert.strictEqual(fs.existsSync(f.output), false);
});

test('CLI writes a private versioned SHA-256 pack and no plaintext values', (t) => {
  const f = fixture(t);
  const token = 'AbCdEfGhIjKlMnOpQrStUv12';
  fs.writeFileSync(f.input, `${UUID}\n${token}\n`);
  const result = run(['--in', f.input, '--out', f.output, '--salt', SALT]);

  assert.strictEqual(result.status, 0, result.stderr);
  const raw = fs.readFileSync(f.output, 'utf8');
  const pack = JSON.parse(raw);
  assert.deepStrictEqual({
    formatVersion: pack.formatVersion,
    algorithm: pack.algorithm,
    valuePolicy: pack.valuePolicy,
    minLen: pack.minLen,
    maxWords: pack.maxWords,
  }, {
    formatVersion: 2,
    algorithm: 'sha256',
    valuePolicy: 'offline-random-id-v1',
    minLen: 20,
    maxWords: 1,
  });
  assert.strictEqual(pack.fingerprints.length, 3, 'UUID plus its compact form and the mixed token');
  assert.ok(pack.fingerprints.every((value) => /^[0-9a-f]{64}$/.test(value)));
  assert.strictEqual(raw.includes(UUID), false);
  assert.strictEqual(raw.includes(token), false);
  assert.doesNotThrow(() => privatePaths.assertPrivatePath(f.output, { label: 'test EDM pack' }));
});

test('CLI refuses legacy packs and preserves their exact bytes', (t) => {
  const f = fixture(t);
  const legacy = '{"salt":"legacy","fingerprints":["0123456789abcdef"]}\n';
  fs.writeFileSync(f.output, legacy);
  fs.writeFileSync(f.input, `${UUID}\n`);
  const result = run(['--in', f.input, '--out', f.output, '--salt', SALT]);

  assert.notStrictEqual(result.status, 0);
  assert.match(result.stderr, /unsafe legacy profile/);
  assert.strictEqual(fs.readFileSync(f.output, 'utf8'), legacy);
});
