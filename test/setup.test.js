'use strict';
/** First-run setup config generation. */
const test = require('node:test');
const assert = require('node:assert');
const {
  buildEnv,
  mergeEnv,
  parseArgs,
  renderEnv,
  statusFromEnv,
} = require('../scripts/setup');

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
