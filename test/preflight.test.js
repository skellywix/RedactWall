'use strict';
/** Production preflight must block unsafe deployment configuration. */
const test = require('node:test');
const assert = require('node:assert');
const preflight = require('../server/preflight');

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
      'admin_mfa',
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
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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

test('production preflight accepts PromptWall runtime aliases', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      PROMPTWALL_DB_PATH: '/var/lib/promptwall/promptwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      PROMPTWALL_INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      PROMPTWALL_SECRET: 's'.repeat(32),
      PROMPTWALL_DATA_KEY: 'd'.repeat(32),
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

test('production preflight blocks incomplete SaaS tenant configuration', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      SENTINEL_SAAS_MODE: 'true',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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
    ['saas_tenant_id', 'saas_seat_limit'],
  );
});

test('production preflight passes complete SaaS tenant configuration', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      SENTINEL_SAAS_MODE: 'true',
      SENTINEL_TENANT_ID: 'cu-acme',
      SENTINEL_SEAT_LIMIT: '25',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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

test('preflight detects SaaS settings passed directly by setup tooling', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SENTINEL_SECRET: 's'.repeat(32),
      SENTINEL_DATA_KEY: 'd'.repeat(32),
    },
    tenantId: 'cu-acme',
    seatLimit: '25',
    requireTenantContext: 'true',
    requireUserIdentity: 'true',
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  });
  assert.strictEqual(status.ready, true);
});

test('production preflight accepts a strong optional auditor login', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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

test('production preflight accepts a strong optional approver login', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      APPROVER_USER: 'approver',
      APPROVER_PASSWORD: 'long-approver-password',
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

test('production preflight accepts a strong optional scim bearer token', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SCIM_BEARER_TOKEN: 'scim_' + 's'.repeat(32),
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

test('production preflight blocks short scim bearer token when scim is configured', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SCIM_BEARER_TOKEN: 'short',
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
    ['scim_bearer_token_strength'],
  );
});

test('production preflight accepts complete OIDC login backed by SCIM', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SCIM_BEARER_TOKEN: 'scim_' + 's'.repeat(32),
      OIDC_ISSUER: 'https://login.customer.example',
      OIDC_CLIENT_ID: 'promptwall-console',
      OIDC_CLIENT_SECRET: 'oidc_' + 'o'.repeat(32),
      OIDC_REDIRECT_URI: 'https://promptwall.customer.example/auth/oidc/callback',
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

test('production preflight blocks partial or weak OIDC login config', () => {
  const base = {
    NODE_ENV: 'production',
    SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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
    env: { ...base, OIDC_ISSUER: 'https://login.customer.example' },
    ...common,
  });
  assert.deepStrictEqual(
    preflight.summarizeFailures(partial).map((line) => line.split(':')[0]),
    ['oidc_config', 'oidc_client_secret_strength', 'oidc_scim_users'],
  );

  const weak = preflight.configStatus({
    env: {
      ...base,
      SCIM_BEARER_TOKEN: 'scim_' + 's'.repeat(32),
      OIDC_ISSUER: 'https://login.customer.example',
      OIDC_CLIENT_ID: 'promptwall-console',
      OIDC_CLIENT_SECRET: 'short',
      OIDC_REDIRECT_URI: 'https://promptwall.customer.example/auth/oidc/callback',
    },
    ...common,
  });
  assert.deepStrictEqual(
    preflight.summarizeFailures(weak).map((line) => line.split(':')[0]),
    ['oidc_client_secret_strength'],
  );

  const incompleteEndpoints = preflight.configStatus({
    env: {
      ...base,
      SCIM_BEARER_TOKEN: 'scim_' + 's'.repeat(32),
      OIDC_ISSUER: 'https://login.customer.example',
      OIDC_CLIENT_ID: 'promptwall-console',
      OIDC_CLIENT_SECRET: 'oidc_' + 'o'.repeat(32),
      OIDC_REDIRECT_URI: 'https://promptwall.customer.example/auth/oidc/callback',
      OIDC_TOKEN_ENDPOINT: 'https://login.customer.example/token',
    },
    ...common,
  });
  assert.deepStrictEqual(
    preflight.summarizeFailures(incompleteEndpoints).map((line) => line.split(':')[0]),
    ['oidc_endpoints'],
  );
});

test('production preflight blocks weak or partial approver login config', () => {
  const base = {
    NODE_ENV: 'production',
    SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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
    env: { ...base, APPROVER_USER: 'approver' },
    ...common,
  });
  assert.strictEqual(partial.ready, false);
  assert.deepStrictEqual(
    preflight.summarizeFailures(partial).map((line) => line.split(':')[0]),
    ['approver_credentials', 'approver_password_strength'],
  );

  const weak = preflight.configStatus({
    env: { ...base, APPROVER_USER: 'approver', APPROVER_PASSWORD: 'short' },
    ...common,
  });
  assert.strictEqual(weak.ready, false);
  assert.deepStrictEqual(
    preflight.summarizeFailures(weak).map((line) => line.split(':')[0]),
    ['approver_password_strength'],
  );

  const duplicate = preflight.configStatus({
    env: { ...base, ADMIN_USER: 'admin', APPROVER_USER: 'admin', APPROVER_PASSWORD: 'long-approver-password' },
    ...common,
  });
  assert.strictEqual(duplicate.ready, false);
  assert.deepStrictEqual(
    preflight.summarizeFailures(duplicate).map((line) => line.split(':')[0]),
    ['approver_user_distinct'],
  );
});

test('production preflight blocks weak or partial auditor login config', () => {
  const base = {
    NODE_ENV: 'production',
    SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'short-pass',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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

test('production preflight blocks invalid admin mfa secret', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'not-valid-!@#',
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
    ['admin_mfa_secret'],
  );
});

test('production preflight blocks short auditor password when auditor login is configured', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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

test('production preflight blocks short approver password when approver login is configured', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: '/var/lib/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      APPROVER_USER: 'approver',
      APPROVER_PASSWORD: 'short-approver',
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
    ['approver_password_strength'],
  );
});

test('development preflight warns on weak custom secrets without blocking demos', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      SENTINEL_DB_PATH: '/tmp/promptwall/sentinel.db',
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

test('development preflight warns on invalid admin mfa secret without blocking demos', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      SENTINEL_DB_PATH: '/tmp/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'not-valid-!@#',
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
  assert.ok(status.checks.some((c) => c.id === 'admin_mfa_secret' && !c.ok && c.severity === 'warning'));
});

test('development preflight warns on weak auditor login without blocking demos', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      SENTINEL_DB_PATH: '/tmp/promptwall/sentinel.db',
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

test('development preflight warns on weak approver login without blocking demos', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      SENTINEL_DB_PATH: '/tmp/promptwall/sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      APPROVER_USER: 'approver',
      APPROVER_PASSWORD: 'short',
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
  assert.ok(status.checks.some((c) => c.id === 'approver_password_strength' && !c.ok && c.severity === 'warning'));
});

test('production preflight blocks cloud-synced sqlite paths', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      SENTINEL_DB_PATH: 'C:\\Users\\Pilot\\OneDrive - Credit Union\\sentinel.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
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
  assert.strictEqual(preflight.cloudSyncedPathReason('/var/lib/promptwall/sentinel.db'), null);
});

test('boolean env parsing accepts common true values only', () => {
  assert.strictEqual(preflight.bool('true'), true);
  assert.strictEqual(preflight.bool('1'), true);
  assert.strictEqual(preflight.bool('yes'), true);
  assert.strictEqual(preflight.bool('false'), false);
  assert.strictEqual(preflight.bool('0'), false);
});
