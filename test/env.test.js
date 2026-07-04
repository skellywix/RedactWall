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
  assert.strictEqual(copy.SENTINEL_URL, 'https://promptwall.example.test');
  assert.strictEqual(source.SENTINEL_URL, undefined);
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

test('loadEnv maps PromptWall aliases without overwriting configured legacy keys', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-env-alias-test-'));
  const file = path.join(dir, '.env');
  fs.writeFileSync(file, [
    'PROMPTWALL_DB_PATH=/var/lib/promptwall/promptwall.db',
    'PROMPTWALL_SECRET=promptwall-session-secret',
    'PROMPTWALL_DATA_KEY=promptwall-data-key',
    'PROMPTWALL_INGEST_API_KEY=promptwall-ingest-key',
    'PROMPTWALL_SCIM_BEARER_TOKEN=promptwall-scim-token',
    'PROMPTWALL_OIDC_ISSUER=https://login.example.test',
    'PROMPTWALL_OIDC_CLIENT_ID=promptwall-console',
    'PROMPTWALL_OIDC_CLIENT_SECRET=promptwall-oidc-secret',
    'PROMPTWALL_OIDC_REDIRECT_URI=https://promptwall.example.test/auth/oidc/callback',
    'PROMPTWALL_URL=https://promptwall.customer.example',
    'PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET=promptwall-handoff-secret',
    'PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR=C:/PromptWall/handoff',
    'PROMPTWALL_ENDPOINT_AGENT_OCR_COMMAND=C:/Program Files/Tesseract-OCR/tesseract.exe',
    'PROMPTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON=["{file}","stdout"]',
    'PROMPTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS=20000',
    'PROMPTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS=250000',
    'PROMPTWALL_ENDPOINT_AGENT_APPROVED_AI_TOOLS=cursor,claude_desktop',
    'SENTINEL_SECRET=legacy-session-secret',
  ].join('\n'));
  const target = { SENTINEL_DATA_KEY: '' };

  const result = env.loadEnv(file, { env: target });
  assert.strictEqual(result.loaded, true);
  assert.strictEqual(target.SENTINEL_DB_PATH, '/var/lib/promptwall/promptwall.db');
  assert.strictEqual(target.SENTINEL_SECRET, 'legacy-session-secret');
  assert.strictEqual(target.SENTINEL_DATA_KEY, 'promptwall-data-key');
  assert.strictEqual(target.INGEST_API_KEY, 'promptwall-ingest-key');
  assert.strictEqual(target.SCIM_BEARER_TOKEN, 'promptwall-scim-token');
  assert.strictEqual(target.OIDC_ISSUER, 'https://login.example.test');
  assert.strictEqual(target.OIDC_CLIENT_ID, 'promptwall-console');
  assert.strictEqual(target.OIDC_CLIENT_SECRET, 'promptwall-oidc-secret');
  assert.strictEqual(target.OIDC_REDIRECT_URI, 'https://promptwall.example.test/auth/oidc/callback');
  assert.strictEqual(target.SENTINEL_URL, 'https://promptwall.customer.example');
  assert.strictEqual(target.ENDPOINT_AGENT_HANDOFF_SECRET, 'promptwall-handoff-secret');
  assert.strictEqual(target.ENDPOINT_AGENT_HANDOFF_DIR, 'C:/PromptWall/handoff');
  assert.strictEqual(target.ENDPOINT_AGENT_OCR_COMMAND, 'C:/Program Files/Tesseract-OCR/tesseract.exe');
  assert.strictEqual(target.ENDPOINT_AGENT_OCR_ARGS_JSON, '["{file}","stdout"]');
  assert.strictEqual(target.ENDPOINT_AGENT_OCR_TIMEOUT_MS, '20000');
  assert.strictEqual(target.ENDPOINT_AGENT_OCR_MAX_CHARS, '250000');
  assert.strictEqual(target.ENDPOINT_AGENT_APPROVED_AI_TOOLS, 'cursor,claude_desktop');
  assert.ok(result.aliases.some((item) => item.key === 'SENTINEL_DB_PATH' && item.source === 'PROMPTWALL_DB_PATH'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('loadEnv returns a safe empty result for missing files', () => {
  const target = { PROMPTWALL_URL: 'https://promptwall.example.test' };
  const result = env.loadEnv(path.join(os.tmpdir(), 'missing-promptwall-env'), { env: target });
  assert.strictEqual(result.loaded, false);
  assert.deepStrictEqual(result.keys, []);
  assert.strictEqual(target.SENTINEL_URL, 'https://promptwall.example.test');
});

test('default env path can be redirected for endpoint installs', () => {
  const old = process.env.SENTINEL_ENV_PATH;
  const oldPromptWall = process.env.PROMPTWALL_ENV_PATH;
  process.env.SENTINEL_ENV_PATH = path.join(os.tmpdir(), 'endpoint-agent.env');
  try {
    assert.strictEqual(env.defaultEnvPath(), process.env.SENTINEL_ENV_PATH);
  } finally {
    if (old === undefined) delete process.env.SENTINEL_ENV_PATH;
    else process.env.SENTINEL_ENV_PATH = old;
    if (oldPromptWall === undefined) delete process.env.PROMPTWALL_ENV_PATH;
    else process.env.PROMPTWALL_ENV_PATH = oldPromptWall;
  }
});

test('default env path accepts PromptWall env path alias', () => {
  const old = process.env.SENTINEL_ENV_PATH;
  const oldPromptWall = process.env.PROMPTWALL_ENV_PATH;
  delete process.env.SENTINEL_ENV_PATH;
  process.env.PROMPTWALL_ENV_PATH = path.join(os.tmpdir(), 'promptwall.env');
  try {
    assert.strictEqual(env.defaultEnvPath(), process.env.PROMPTWALL_ENV_PATH);
  } finally {
    if (old === undefined) delete process.env.SENTINEL_ENV_PATH;
    else process.env.SENTINEL_ENV_PATH = old;
    if (oldPromptWall === undefined) delete process.env.PROMPTWALL_ENV_PATH;
    else process.env.PROMPTWALL_ENV_PATH = oldPromptWall;
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
