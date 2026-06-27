'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const env = require('../server/env');

test('parseEnv supports comments, export prefix, and quoted values', () => {
  const parsed = env.parseEnv(`
    # comment
    export PORT=4100
    ADMIN_PASSWORD="value with # hash"
    SENTINEL_SECRET='literal\\nsecret'
    INGEST_API_KEY=abc123 # trailing comment
  `);
  assert.deepStrictEqual(parsed.errors, []);
  assert.strictEqual(parsed.parsed.PORT, '4100');
  assert.strictEqual(parsed.parsed.ADMIN_PASSWORD, 'value with # hash');
  assert.strictEqual(parsed.parsed.SENTINEL_SECRET, 'literal\\nsecret');
  assert.strictEqual(parsed.parsed.INGEST_API_KEY, 'abc123');
});

test('loadEnv keeps existing process values unless override is requested', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-env-test-'));
  const file = path.join(dir, '.env');
  fs.writeFileSync(file, 'PORT=4000\nADMIN_PASSWORD=from-file\n');
  const target = { PORT: '9999' };

  const first = env.loadEnv(file, { env: target });
  assert.strictEqual(first.loaded, true);
  assert.deepStrictEqual(first.skipped, ['PORT']);
  assert.strictEqual(target.PORT, '9999');
  assert.strictEqual(target.ADMIN_PASSWORD, 'from-file');

  env.loadEnv(file, { env: target, override: true });
  assert.strictEqual(target.PORT, '4000');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('loadEnv returns a safe empty result for missing files', () => {
  const result = env.loadEnv(path.join(os.tmpdir(), 'missing-promptsentinel-env'), { env: {} });
  assert.strictEqual(result.loaded, false);
  assert.deepStrictEqual(result.keys, []);
});

test('default env path can be redirected for endpoint installs', () => {
  const old = process.env.SENTINEL_ENV_PATH;
  process.env.SENTINEL_ENV_PATH = path.join(os.tmpdir(), 'endpoint-agent.env');
  try {
    assert.strictEqual(env.defaultEnvPath(), process.env.SENTINEL_ENV_PATH);
  } finally {
    if (old === undefined) delete process.env.SENTINEL_ENV_PATH;
    else process.env.SENTINEL_ENV_PATH = old;
  }
});

test('copied example admin password is still reported as default', () => {
  const out = execFileSync(process.execPath, ['-e', `
process.env.ADMIN_PASSWORD = 'ChangeMe!2026';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
const auth = require('./server/auth');
process.stdout.write(String(auth.ADMIN_PASSWORD_IS_DEFAULT));
`], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env },
    encoding: 'utf8',
  });
  assert.strictEqual(out, 'true');
});
