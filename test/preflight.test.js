'use strict';
/** Production preflight must block unsafe deployment configuration. */
const test = require('node:test');
const assert = require('node:assert');
const preflight = require('../src/preflight');

const unsafe = {
  adminPasswordIsDefault: true,
  ingestKeyIsDefault: true,
  secretSource: 'generated',
  dataCryptoEnabled: false,
  cookieSecure: false,
};

test('development preflight keeps demos runnable but reports warnings', () => {
  const status = preflight.configStatus({ env: { NODE_ENV: 'development' }, ...unsafe });
  assert.strictEqual(status.production, false);
  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'warnings');
  assert.ok(status.checks.some((c) => c.id === 'admin_password' && !c.ok && c.severity === 'warning'));
});

test('production preflight blocks unsafe deployment defaults', () => {
  const status = preflight.configStatus({ env: { NODE_ENV: 'production' }, ...unsafe });
  assert.strictEqual(status.production, true);
  assert.strictEqual(status.ready, false);
  assert.strictEqual(status.level, 'blocked');
  assert.deepStrictEqual(
    preflight.summarizeFailures(status).map((line) => line.split(':')[0]),
    [
      'admin_password',
      'admin_password_strength',
      'ingest_key',
      'ingest_key_strength',
      'session_secret',
      'session_secret_strength',
      'raw_prompt_encryption',
      'data_key_strength',
      'secure_cookie',
      'sqlite_local_disk',
    ],
  );
});

test('production preflight passes with stable secrets and secure cookies', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptsentinel/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SENTINEL_SECRET: 's'.repeat(32),
      SENTINEL_DATA_KEY: 'd'.repeat(32),
    },
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  });
  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'ok');
  assert.ok(status.checks.every((c) => c.ok));
});

test('production preflight accepts a strong optional auditor login', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptsentinel/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      AUDITOR_USER: 'auditor',
      AUDITOR_PASSWORD: 'long-auditor-password',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SENTINEL_SECRET: 's'.repeat(32),
      SENTINEL_DATA_KEY: 'd'.repeat(32),
    },
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  });
  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'ok');
  assert.ok(status.checks.every((c) => c.ok));
});

test('production preflight blocks weak or partial auditor login config', () => {
  const base = {
    NODE_ENV: 'production',
    SENTINEL_DB_PATH: '/var/lib/promptsentinel/sentinel.db',
    ADMIN_PASSWORD: 'long-admin-password',
    INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    SENTINEL_SECRET: 's'.repeat(32),
    SENTINEL_DATA_KEY: 'd'.repeat(32),
  };
  const common = {
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  };
  const partial = preflight.configStatus({
    env: { ...base, AUDITOR_USER: 'auditor' },
    ...common,
  });
  assert.strictEqual(partial.ready, false);
  assert.deepStrictEqual(
    preflight.summarizeFailures(partial).map((line) => line.split(':')[0]),
    ['auditor_credentials', 'auditor_password_strength'],
  );

  const weak = preflight.configStatus({
    env: { ...base, AUDITOR_USER: 'auditor', AUDITOR_PASSWORD: 'short' },
    ...common,
  });
  assert.strictEqual(weak.ready, false);
  assert.deepStrictEqual(
    preflight.summarizeFailures(weak).map((line) => line.split(':')[0]),
    ['auditor_password_strength'],
  );

  const duplicate = preflight.configStatus({
    env: { ...base, ADMIN_USER: 'admin', AUDITOR_USER: 'admin', AUDITOR_PASSWORD: 'long-auditor-password' },
    ...common,
  });
  assert.strictEqual(duplicate.ready, false);
  assert.deepStrictEqual(
    preflight.summarizeFailures(duplicate).map((line) => line.split(':')[0]),
    ['auditor_user_distinct'],
  );
});

test('production preflight blocks custom but short secrets', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptsentinel/sentinel.db',
      ADMIN_PASSWORD: 'short-pass',
      INGEST_API_KEY: 'short-ingest-key',
      SENTINEL_SECRET: 'short-session-secret',
      SENTINEL_DATA_KEY: 'short-data-key',
    },
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  });
  assert.strictEqual(status.ready, false);
  assert.deepStrictEqual(
    preflight.summarizeFailures(status).map((line) => line.split(':')[0]),
    ['admin_password_strength', 'ingest_key_strength', 'session_secret_strength', 'data_key_strength'],
  );
});

test('production preflight blocks short auditor password when auditor login is configured', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptsentinel/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      AUDITOR_USER: 'auditor',
      AUDITOR_PASSWORD: 'short-auditor',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SENTINEL_SECRET: 's'.repeat(32),
      SENTINEL_DATA_KEY: 'd'.repeat(32),
    },
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  });
  assert.strictEqual(status.ready, false);
  assert.deepStrictEqual(
    preflight.summarizeFailures(status).map((line) => line.split(':')[0]),
    ['auditor_password_strength'],
  );
});

test('development preflight warns on weak custom secrets without blocking demos', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      SENTINEL_DB_PATH: '/tmp/promptsentinel/sentinel.db',
      ADMIN_PASSWORD: 'short-pass',
      INGEST_API_KEY: 'short-ingest-key',
      SENTINEL_SECRET: 'short-session-secret',
      SENTINEL_DATA_KEY: 'short-data-key',
    },
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: false,
  });
  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'warnings');
  assert.ok(status.checks.some((c) => c.id === 'admin_password_strength' && !c.ok && c.severity === 'warning'));
});

test('development preflight warns on weak auditor login without blocking demos', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      SENTINEL_DB_PATH: '/tmp/promptsentinel/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      AUDITOR_USER: 'auditor',
      AUDITOR_PASSWORD: 'short',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SENTINEL_SECRET: 's'.repeat(32),
      SENTINEL_DATA_KEY: 'd'.repeat(32),
    },
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: false,
  });
  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'warnings');
  assert.ok(status.checks.some((c) => c.id === 'auditor_password_strength' && !c.ok && c.severity === 'warning'));
});

test('production preflight blocks cloud-synced sqlite paths', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: 'C:\\Users\\Pilot\\OneDrive - Credit Union\\sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SENTINEL_SECRET: 's'.repeat(32),
      SENTINEL_DATA_KEY: 'd'.repeat(32),
    },
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  });
  const check = status.checks.find((c) => c.id === 'sqlite_local_disk');
  assert.strictEqual(status.ready, false);
  assert.strictEqual(check.ok, false);
  assert.strictEqual(check.severity, 'error');
  assert.match(check.remediation, /OneDrive/);
});

test('sqlite path classifier catches network and common cloud folders', () => {
  assert.strictEqual(preflight.cloudSyncedPathReason('\\\\fileserver\\share\\sentinel.db'), 'network share');
  assert.strictEqual(preflight.cloudSyncedPathReason('/Users/pilot/Dropbox/sentinel.db'), 'Dropbox');
  assert.strictEqual(preflight.cloudSyncedPathReason('/Users/pilot/Google Drive/sentinel.db'), 'Google Drive');
  assert.strictEqual(preflight.cloudSyncedPathReason('/var/lib/promptsentinel/sentinel.db'), null);
});

test('boolean env parsing accepts common true values only', () => {
  assert.strictEqual(preflight.bool('true'), true);
  assert.strictEqual(preflight.bool('1'), true);
  assert.strictEqual(preflight.bool('yes'), true);
  assert.strictEqual(preflight.bool('false'), false);
  assert.strictEqual(preflight.bool('0'), false);
});
