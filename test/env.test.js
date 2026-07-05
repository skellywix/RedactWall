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
    REDACTWALL_SECRET='literal\\nsecret'
    INGEST_API_KEY=abc123 # trailing comment
  `);
  assert.deepStrictEqual(parsed.errors, []);
  assert.strictEqual(parsed.parsed.PORT, '4100');
  assert.strictEqual(parsed.parsed.ADMIN_PASSWORD, 'value with # hash');
  assert.strictEqual(parsed.parsed.REDACTWALL_SECRET, 'literal\\nsecret');
  assert.strictEqual(parsed.parsed.INGEST_API_KEY, 'abc123');
});

test('parseEnv reports invalid keys without loading their values', () => {
  const parsed = env.parseEnv('BROKEN\n1BAD=secret\nGOOD=value\\#literal # comment\n');
  assert.deepStrictEqual(parsed.errors, [
    { line: 1, error: 'missing equals sign' },
    { line: 2, error: 'invalid key' },
  ]);
  assert.strictEqual(parsed.parsed['1BAD'], undefined);
  assert.strictEqual(parsed.parsed.GOOD, 'value\\#literal');
});

test('withEnvAliases returns an aliased copy without mutating the source', () => {
  const source = { PROMPTWALL_URL: 'https://promptwall.example.test' };
  const copy = env.withEnvAliases(source);
  assert.strictEqual(copy.REDACTWALL_URL, 'https://promptwall.example.test');
  assert.strictEqual(source.REDACTWALL_URL, undefined);
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

test('loadEnv maps legacy PromptWall/Sentinel aliases without overwriting configured RedactWall keys', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-env-alias-test-'));
  const file = path.join(dir, '.env');
  fs.writeFileSync(file, [
    'PROMPTWALL_DB_PATH=/var/lib/redactwall/redactwall.db',
    'REDACTWALL_SECRET=redactwall-session-secret',
    'PROMPTWALL_SECRET=legacy-session-secret',
    'SENTINEL_DATA_KEY=legacy-data-key',
    'REDACTWALL_INGEST_API_KEY=redactwall-ingest-key',
    'REDACTWALL_SCIM_BEARER_TOKEN=redactwall-scim-token',
    'REDACTWALL_OIDC_ISSUER=https://login.example.test',
    'REDACTWALL_OIDC_CLIENT_ID=redactwall-console',
    'REDACTWALL_OIDC_CLIENT_SECRET=redactwall-oidc-secret',
    'REDACTWALL_OIDC_REDIRECT_URI=https://redactwall.example.test/auth/oidc/callback',
    'SENTINEL_URL=https://redactwall.customer.example',
    'REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET=redactwall-handoff-secret',
    'REDACTWALL_ENDPOINT_AGENT_HANDOFF_DIR=C:/RedactWall/handoff',
    'REDACTWALL_ENDPOINT_AGENT_OCR_COMMAND=C:/Program Files/Tesseract-OCR/tesseract.exe',
    'REDACTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON=["{file}","stdout"]',
    'REDACTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS=20000',
    'REDACTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS=250000',
    'REDACTWALL_ENDPOINT_AGENT_APPROVED_AI_TOOLS=cursor,claude_desktop',
  ].join('\n'));
  const target = { REDACTWALL_DATA_KEY: '' };

  const result = env.loadEnv(file, { env: target });
  assert.strictEqual(result.loaded, true);
  assert.strictEqual(target.REDACTWALL_DB_PATH, '/var/lib/redactwall/redactwall.db');
  assert.strictEqual(target.REDACTWALL_SECRET, 'redactwall-session-secret');
  assert.strictEqual(target.REDACTWALL_DATA_KEY, 'legacy-data-key');
  assert.strictEqual(target.INGEST_API_KEY, 'redactwall-ingest-key');
  assert.strictEqual(target.SCIM_BEARER_TOKEN, 'redactwall-scim-token');
  assert.strictEqual(target.OIDC_ISSUER, 'https://login.example.test');
  assert.strictEqual(target.OIDC_CLIENT_ID, 'redactwall-console');
  assert.strictEqual(target.OIDC_CLIENT_SECRET, 'redactwall-oidc-secret');
  assert.strictEqual(target.OIDC_REDIRECT_URI, 'https://redactwall.example.test/auth/oidc/callback');
  assert.strictEqual(target.REDACTWALL_URL, 'https://redactwall.customer.example');
  assert.strictEqual(target.ENDPOINT_AGENT_HANDOFF_SECRET, 'redactwall-handoff-secret');
  assert.strictEqual(target.ENDPOINT_AGENT_HANDOFF_DIR, 'C:/RedactWall/handoff');
  assert.strictEqual(target.ENDPOINT_AGENT_OCR_COMMAND, 'C:/Program Files/Tesseract-OCR/tesseract.exe');
  assert.strictEqual(target.ENDPOINT_AGENT_OCR_ARGS_JSON, '["{file}","stdout"]');
  assert.strictEqual(target.ENDPOINT_AGENT_OCR_TIMEOUT_MS, '20000');
  assert.strictEqual(target.ENDPOINT_AGENT_OCR_MAX_CHARS, '250000');
  assert.strictEqual(target.ENDPOINT_AGENT_APPROVED_AI_TOOLS, 'cursor,claude_desktop');
  assert.ok(result.aliases.some((item) => item.key === 'REDACTWALL_DB_PATH' && item.source === 'PROMPTWALL_DB_PATH'));
  assert.ok(result.aliases.some((item) => item.key === 'REDACTWALL_URL' && item.source === 'SENTINEL_URL'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('loadEnv returns a safe empty result for missing files', () => {
  const target = { REDACTWALL_URL: 'https://redactwall.example.test' };
  const result = env.loadEnv(path.join(os.tmpdir(), 'missing-redactwall-env'), { env: target });
  assert.strictEqual(result.loaded, false);
  assert.deepStrictEqual(result.keys, []);
  assert.strictEqual(target.REDACTWALL_URL, 'https://redactwall.example.test');
});

test('default env path can be redirected for endpoint installs', () => {
  const old = process.env.REDACTWALL_ENV_PATH;
  process.env.REDACTWALL_ENV_PATH = path.join(os.tmpdir(), 'endpoint-agent.env');
  try {
    assert.strictEqual(env.defaultEnvPath(), process.env.REDACTWALL_ENV_PATH);
  } finally {
    if (old === undefined) delete process.env.REDACTWALL_ENV_PATH;
    else process.env.REDACTWALL_ENV_PATH = old;
  }
});

test('default env path accepts legacy PromptWall and Sentinel env path aliases', () => {
  const oldRedactWall = process.env.REDACTWALL_ENV_PATH;
  const oldPromptWall = process.env.PROMPTWALL_ENV_PATH;
  const oldSentinel = process.env.SENTINEL_ENV_PATH;
  delete process.env.REDACTWALL_ENV_PATH;
  process.env.PROMPTWALL_ENV_PATH = path.join(os.tmpdir(), 'promptwall.env');
  process.env.SENTINEL_ENV_PATH = path.join(os.tmpdir(), 'sentinel.env');
  try {
    assert.strictEqual(env.defaultEnvPath(), process.env.PROMPTWALL_ENV_PATH);
    delete process.env.PROMPTWALL_ENV_PATH;
    assert.strictEqual(env.defaultEnvPath(), process.env.SENTINEL_ENV_PATH);
  } finally {
    if (oldRedactWall === undefined) delete process.env.REDACTWALL_ENV_PATH;
    else process.env.REDACTWALL_ENV_PATH = oldRedactWall;
    if (oldPromptWall === undefined) delete process.env.PROMPTWALL_ENV_PATH;
    else process.env.PROMPTWALL_ENV_PATH = oldPromptWall;
    if (oldSentinel === undefined) delete process.env.SENTINEL_ENV_PATH;
    else process.env.SENTINEL_ENV_PATH = oldSentinel;
  }
});

test('copied example admin password is still reported as default', () => {
  const out = execFileSync(process.execPath, ['-e', `
process.env.ADMIN_PASSWORD = 'ChangeMe!2026';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
const auth = require('./server/auth');
process.stdout.write(String(auth.ADMIN_PASSWORD_IS_DEFAULT));
`], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env },
    encoding: 'utf8',
  });
  assert.strictEqual(out, 'true');
});
