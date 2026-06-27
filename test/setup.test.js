'use strict';
/** First-run setup config generation. */
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseEnv } = require('../server/env');
const {
  buildEnv,
  mergeEnv,
  parseArgs,
  renderEnv,
  statusFromEnv,
} = require('../scripts/setup');

const ROOT = path.join(__dirname, '..');
const SETUP_ENV_KEYS = [
  'PORT',
  'NODE_ENV',
  'HTTPS',
  'COOKIE_SECURE',
  'SENTINEL_DB_PATH',
  'SENTINEL_SAAS_MODE',
  'SENTINEL_TENANT_ID',
  'SENTINEL_SEAT_LIMIT',
  'SENTINEL_REQUIRE_TENANT_CONTEXT',
  'SENTINEL_REQUIRE_USER_IDENTITY',
  'ADMIN_USER',
  'ADMIN_PASSWORD',
  'ADMIN_TOTP_SECRET',
  'SENTINEL_SECRET',
  'SENTINEL_DATA_KEY',
  'INGEST_API_KEY',
  'SENTINEL_REQUEST_TIMEOUT_MS',
  'SIEM_WEBHOOK_URL',
  'SIEM_WEBHOOK_TOKEN',
  'SIEM_ALERT_MIN_RISK',
  'SIEM_ALERT_MIN_SEVERITY',
  'AUDITOR_USER',
  'AUDITOR_PASSWORD',
  'SENTINEL_ENV_PATH',
];

function childEnv() {
  const env = { ...process.env };
  for (const key of SETUP_ENV_KEYS) delete env[key];
  return env;
}

test('production setup env passes deployment preflight', () => {
  const env = buildEnv({ production: true });
  const status = statusFromEnv(env);

  assert.strictEqual(env.NODE_ENV, 'production');
  assert.strictEqual(env.HTTPS, 'true');
  assert.strictEqual(env.COOKIE_SECURE, 'true');
  assert.notStrictEqual(env.ADMIN_PASSWORD, 'ChangeMe!2026');
  assert.match(env.ADMIN_TOTP_SECRET, /^[A-Z2-7]{16,}$/);
  assert.notStrictEqual(env.INGEST_API_KEY, 'dev-ingest-key');
  assert.ok(env.SENTINEL_SECRET.length >= 32);
  assert.ok(env.SENTINEL_DATA_KEY.length >= 32);
  assert.strictEqual(env.SENTINEL_SAAS_MODE, 'false');
  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'ok');
});

test('mergeEnv replaces placeholders but preserves custom values', () => {
  const merged = mergeEnv({
    ADMIN_PASSWORD: 'ChangeMe!2026',
    ADMIN_TOTP_SECRET: '',
    INGEST_API_KEY: 'dev-ingest-key',
    SENTINEL_SECRET: '',
    SIEM_WEBHOOK_URL: 'https://soc.example.test/hook',
  }, {
    ADMIN_PASSWORD: 'generated-pass',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'generated-key',
    SENTINEL_SECRET: 'generated-secret',
    SIEM_WEBHOOK_URL: '',
  });

  assert.strictEqual(merged.ADMIN_PASSWORD, 'generated-pass');
  assert.strictEqual(merged.ADMIN_TOTP_SECRET, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(merged.INGEST_API_KEY, 'generated-key');
  assert.strictEqual(merged.SENTINEL_SECRET, 'generated-secret');
  assert.strictEqual(merged.SIEM_WEBHOOK_URL, 'https://soc.example.test/hook');
});

test('renderEnv quotes only values that need quoting', () => {
  const rendered = renderEnv({
    PORT: '4000',
    ADMIN_PASSWORD: 'has space',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'ps_ingest_safe',
  });

  assert.match(rendered, /^PORT=4000$/m);
  assert.match(rendered, /^ADMIN_PASSWORD="has space"$/m);
  assert.match(rendered, /^ADMIN_TOTP_SECRET=JBSWY3DPEHPK3PXP$/m);
  assert.match(rendered, /^INGEST_API_KEY=ps_ingest_safe$/m);
});

test('parseArgs supports check and alternate env file', () => {
  const opts = parseArgs(['--check', '--skip-install', '--env', 'demo.env']);
  assert.strictEqual(opts.check, true);
  assert.strictEqual(opts.skipInstall, true);
  assert.match(opts.envPath, /demo\.env$/);
});

test('production setup, mfa enrollment, and setup check work end to end without setup leaking secrets', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-setup-prod-'));
  const envPath = path.join(dir, 'pilot.env');
  const dbPath = path.join(dir, 'sentinel.db').replace(/\\/g, '/');
  fs.writeFileSync(envPath, `SENTINEL_DB_PATH=${dbPath}\n`);
  const env = childEnv();

  const setupOut = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'setup.js'),
    '--production',
    '--skip-install',
    '--env',
    envPath,
  ], { cwd: ROOT, encoding: 'utf8', env });

  const parsed = parseEnv(fs.readFileSync(envPath, 'utf8')).parsed;
  assert.match(parsed.ADMIN_TOTP_SECRET, /^[A-Z2-7]{16,}$/);
  assert.match(parsed.ADMIN_PASSWORD, /^Ps-/);
  assert.match(parsed.INGEST_API_KEY, /^ps_ingest_/);
  assert.strictEqual(parsed.SENTINEL_DB_PATH, dbPath);
  assert.strictEqual(fs.existsSync(dbPath), true);
  assert.match(setupOut, /Preflight: ok \(ready\)/);
  assert.strictEqual(setupOut.includes(parsed.ADMIN_TOTP_SECRET), false);
  assert.strictEqual(setupOut.includes(parsed.ADMIN_PASSWORD), false);
  assert.strictEqual(setupOut.includes(parsed.INGEST_API_KEY), false);

  const mfaOut = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'mfa-uri.js'),
    '--env',
    envPath,
    '--issuer',
    'PromptSentinel Smoke',
  ], { cwd: ROOT, encoding: 'utf8', env });
  const uriLine = mfaOut.split(/\r?\n/).find((line) => line.startsWith('otpauth://'));
  assert.ok(uriLine);
  const uri = new URL(uriLine);
  assert.strictEqual(uri.searchParams.get('secret'), parsed.ADMIN_TOTP_SECRET);
  assert.strictEqual(uri.searchParams.get('issuer'), 'PromptSentinel Smoke');
  assert.strictEqual(mfaOut.includes(parsed.ADMIN_PASSWORD), false);
  assert.strictEqual(mfaOut.includes(parsed.INGEST_API_KEY), false);

  const checkOut = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'setup.js'),
    '--check',
    '--skip-install',
    '--env',
    envPath,
  ], { cwd: ROOT, encoding: 'utf8', env });
  assert.match(checkOut, /Preflight: ok \(ready\)/);
  assert.strictEqual(checkOut.includes(parsed.ADMIN_TOTP_SECRET), false);
  assert.strictEqual(checkOut.includes(parsed.ADMIN_PASSWORD), false);
  assert.strictEqual(checkOut.includes(parsed.INGEST_API_KEY), false);
});
