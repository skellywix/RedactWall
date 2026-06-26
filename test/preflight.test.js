'use strict';
/** Production preflight must block unsafe defaults only in production mode. */
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
    ['admin_password', 'ingest_key', 'session_secret', 'raw_prompt_encryption', 'secure_cookie', 'sqlite_local_disk'],
  );
});

test('production preflight passes with stable secrets and secure cookies', () => {
  const status = preflight.configStatus({
    env: { NODE_ENV: 'production', SENTINEL_DB_PATH: '/var/lib/promptsentinel/sentinel.db' },
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

test('production preflight blocks cloud-synced sqlite paths', () => {
  const status = preflight.configStatus({
    env: { NODE_ENV: 'production', SENTINEL_DB_PATH: 'C:\\Users\\Pilot\\OneDrive - Credit Union\\sentinel.db' },
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
