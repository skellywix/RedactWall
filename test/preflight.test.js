'use strict';
/** Production preflight must block unsafe deployment configuration. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
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

test('a configured malformed custom detector pack always blocks readiness', () => {
  const status = preflight.configStatus({
    env: { NODE_ENV: 'development' },
    customDetectorsStatus: { ok: false, error: 'detector pack is not valid JSON' },
  });
  const check = status.checks.find((item) => item.id === 'custom_detectors');

  assert.strictEqual(check.ok, false);
  assert.strictEqual(check.severity, 'error');
  assert.strictEqual(status.ready, false);
});

test('configured policy and exact-match integrity failures always block readiness', () => {
  const status = preflight.configStatus({
    env: { NODE_ENV: 'development' },
    policyStatus: { ok: false, error: 'configured policy file is missing' },
    exactMatchStatus: { ok: false, error: 'configured exact-match pack is missing' },
  });

  for (const id of ['policy_file', 'exact_match']) {
    const check = status.checks.find((item) => item.id === id);
    assert.strictEqual(check.ok, false, id);
    assert.strictEqual(check.severity, 'error', id);
  }
  assert.strictEqual(status.ready, false);
});

test('an unavailable durable policy-signing identity always blocks readiness', () => {
  const status = preflight.configStatus({
    env: { NODE_ENV: 'development' },
    policySigningKeyStatus: { ok: false, persistent: false, reason: 'read_only' },
  });
  const check = status.checks.find((item) => item.id === 'policy_signing_key');
  assert.strictEqual(check.ok, false);
  assert.strictEqual(check.severity, 'error');
  assert.strictEqual(status.ready, false);
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

test('runtime preflight requires one valid non-conflicting license customer binding', () => {
  const checkBinding = (env) => {
    const status = preflight.configStatus({
      env: { NODE_ENV: 'production', ...env },
      requireLicenseBinding: true,
    });
    return {
      status,
      check: status.checks.find((item) => item.id === 'license_customer_binding'),
    };
  };

  for (const env of [
    {},
    { REDACTWALL_LICENSE_CUSTOMER_ID: 'billing@example.test' },
    { REDACTWALL_LICENSE_CUSTOMER_ID: 'cu-one', REDACTWALL_TENANT_ID: 'cu-two' },
  ]) {
    const { status, check } = checkBinding(env);
    assert.strictEqual(check.ok, false);
    assert.strictEqual(check.severity, 'error');
    assert.ok(preflight.summarizeFailures(status).some((line) => line.startsWith('license_customer_binding:')));
  }

  assert.strictEqual(checkBinding({ REDACTWALL_LICENSE_CUSTOMER_ID: 'cu-one' }).check.ok, true);
  assert.strictEqual(checkBinding({ REDACTWALL_TENANT_ID: 'cu-one' }).check.ok, true);
  assert.strictEqual(checkBinding({
    REDACTWALL_LICENSE_CUSTOMER_ID: 'cu-one',
    REDACTWALL_TENANT_ID: 'cu-one',
  }).check.ok, true);
});

test('connected-license preflight requires an authenticated dedicated verdict trust root', () => {
  const insecure = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      REDACTWALL_LICENSE_SERVER_URL: 'https://license.vendor.example/heartbeat',
    },
  });
  for (const id of ['connected_license_auth', 'connected_license_verdict_key']) {
    const check = insecure.checks.find((item) => item.id === id);
    assert.strictEqual(check.ok, false, id);
    assert.strictEqual(check.severity, 'error', id);
  }
  assert.strictEqual(insecure.ready, false);

  for (const suffix of ['?token=secret', '#fragment']) {
    const parameterized = preflight.configStatus({
      env: {
        NODE_ENV: 'development',
        REDACTWALL_LICENSE_SERVER_URL: `https://license.vendor.example/heartbeat${suffix}`,
      },
    });
    assert.strictEqual(parameterized.checks.find((item) => item.id === 'connected_license_url').ok, false);
  }

  const { publicKey: licenseRoot } = crypto.generateKeyPairSync('ed25519');
  const reused = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      REDACTWALL_LICENSE_SERVER_URL: 'https://license.vendor.example/heartbeat',
      REDACTWALL_LICENSE_SERVER_TOKEN: 'rwls_customer_0123456789abcdef0123456789',
      REDACTWALL_LICENSE_PUBLIC_KEY: licenseRoot.export({ type: 'spki', format: 'pem' }),
      REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY: licenseRoot.export({ type: 'spki', format: 'pem' }),
    },
  });
  assert.strictEqual(reused.checks.find((item) => item.id === 'connected_license_verdict_key').ok, false);

  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const secure = preflight.configStatus({
    env: {
      NODE_ENV: 'development',
      REDACTWALL_LICENSE_SERVER_URL: 'https://license.vendor.example/heartbeat',
      REDACTWALL_LICENSE_SERVER_TOKEN: 'rwls_customer_0123456789abcdef0123456789',
      REDACTWALL_LICENSE_PUBLIC_KEY: licenseRoot.export({ type: 'spki', format: 'pem' }),
      REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY: publicKey.export({ type: 'spki', format: 'pem' }),
    },
  });
  assert.strictEqual(secure.checks.find((item) => item.id === 'connected_license_url').ok, true);
  assert.strictEqual(secure.checks.find((item) => item.id === 'connected_license_auth').ok, true);
  assert.strictEqual(secure.checks.find((item) => item.id === 'connected_license_verdict_key').ok, true);
});

test('public invite URL preflight rejects cleartext production origins and warns on malformed development values', () => {
  const production = preflight.configStatus({
    env: { NODE_ENV: 'production', REDACTWALL_PUBLIC_URL: 'http://redactwall.example.test' },
  });
  const productionCheck = production.checks.find((item) => item.id === 'public_url');
  assert.strictEqual(productionCheck.ok, false);
  assert.strictEqual(productionCheck.severity, 'error');
  assert.ok(preflight.summarizeFailures(production).some((line) => line.startsWith('public_url:')));

  const development = preflight.configStatus({
    env: { NODE_ENV: 'development', REDACTWALL_PUBLIC_URL: 'javascript://redactwall.example.test' },
  });
  const developmentCheck = development.checks.find((item) => item.id === 'public_url');
  assert.strictEqual(developmentCheck.ok, false);
  assert.strictEqual(developmentCheck.severity, 'warning');
  assert.strictEqual(development.ready, true);

  const secure = preflight.configStatus({
    env: { NODE_ENV: 'production', REDACTWALL_PUBLIC_URL: 'https://redactwall.example.test/console' },
  });
  assert.strictEqual(secure.checks.find((item) => item.id === 'public_url').ok, true);
});

test('production preflight passes with stable secrets and secure cookies', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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

test('production preflight accepts RedactWall runtime aliases', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      REDACTWALL_INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      REDACTWALL_SAAS_MODE: 'true',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      REDACTWALL_SAAS_MODE: 'true',
      REDACTWALL_TENANT_ID: 'cu-acme',
      REDACTWALL_SEAT_LIMIT: '25',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      AUDITOR_USER: 'auditor',
      AUDITOR_PASSWORD: 'long-auditor-password',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      APPROVER_USER: 'approver',
      APPROVER_PASSWORD: 'long-approver-password',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SCIM_BEARER_TOKEN: 'scim_' + 's'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SCIM_BEARER_TOKEN: 'short',
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      SCIM_BEARER_TOKEN: 'scim_' + 's'.repeat(32),
      OIDC_ISSUER: 'https://login.customer.example',
      OIDC_CLIENT_ID: 'redactwall-console',
      OIDC_CLIENT_SECRET: 'oidc_' + 'o'.repeat(32),
      OIDC_REDIRECT_URI: 'https://redactwall.customer.example/auth/oidc/callback',
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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

test('production preflight rejects cleartext URLs in every OIDC URL field', () => {
  const base = {
    NODE_ENV: 'production',
    REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    SCIM_BEARER_TOKEN: 'scim_' + 's'.repeat(32),
    OIDC_ISSUER: 'https://login.customer.example',
    OIDC_CLIENT_ID: 'redactwall-console',
    OIDC_CLIENT_SECRET: 'oidc_' + 'o'.repeat(32),
    OIDC_REDIRECT_URI: 'https://redactwall.customer.example/auth/oidc/callback',
    OIDC_AUTHORIZATION_ENDPOINT: 'https://login.customer.example/authorize',
    OIDC_TOKEN_ENDPOINT: 'https://login.customer.example/token',
    OIDC_JWKS_URI: 'https://login.customer.example/jwks',
    REDACTWALL_SECRET: 's'.repeat(32),
    REDACTWALL_DATA_KEY: 'd'.repeat(32),
  };
  const common = {
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  };

  for (const key of [
    'OIDC_ISSUER',
    'OIDC_REDIRECT_URI',
    'OIDC_AUTHORIZATION_ENDPOINT',
    'OIDC_TOKEN_ENDPOINT',
    'OIDC_JWKS_URI',
  ]) {
    const status = preflight.configStatus({
      env: { ...base, [key]: base[key].replace('https://', 'http://') },
      ...common,
    });
    const httpsCheck = status.checks.find((item) => item.id === 'oidc_https');
    assert.strictEqual(httpsCheck && httpsCheck.ok, false, key);
    assert.strictEqual(status.ready, false, key);
  }

  const embeddedSecret = 'preflight-embedded-provider-secret';
  for (const key of [
    'OIDC_ISSUER',
    'OIDC_REDIRECT_URI',
    'OIDC_AUTHORIZATION_ENDPOINT',
    'OIDC_TOKEN_ENDPOINT',
    'OIDC_JWKS_URI',
  ]) {
    const credential = new URL(base[key]);
    credential.username = 'provider';
    credential.password = embeddedSecret;
    for (const unsafe of [credential.toString(), `${base[key]}?hidden=value`, `${base[key]}#fragment`]) {
      const status = preflight.configStatus({ env: { ...base, [key]: unsafe }, ...common });
      assert.strictEqual(status.checks.find((item) => item.id === 'oidc_https').ok, false, key);
      assert.strictEqual(status.ready, false, key);
      assert.doesNotMatch(JSON.stringify(status), new RegExp(embeddedSecret));
    }
  }
});

test('production preflight blocks partial or weak OIDC login config', () => {
  const base = {
    NODE_ENV: 'production',
    REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    REDACTWALL_SECRET: 's'.repeat(32),
    REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      OIDC_CLIENT_ID: 'redactwall-console',
      OIDC_CLIENT_SECRET: 'short',
      OIDC_REDIRECT_URI: 'https://redactwall.customer.example/auth/oidc/callback',
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
      OIDC_CLIENT_ID: 'redactwall-console',
      OIDC_CLIENT_SECRET: 'oidc_' + 'o'.repeat(32),
      OIDC_REDIRECT_URI: 'https://redactwall.customer.example/auth/oidc/callback',
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
    REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    REDACTWALL_SECRET: 's'.repeat(32),
    REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
    REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    REDACTWALL_SECRET: 's'.repeat(32),
    REDACTWALL_DATA_KEY: 'd'.repeat(32),
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

test('production preflight blocks weak, partial, or duplicate operator login config', () => {
  const base = {
    NODE_ENV: 'production',
    REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
    ADMIN_USER: 'admin',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    REDACTWALL_SECRET: 's'.repeat(32),
    REDACTWALL_DATA_KEY: 'd'.repeat(32),
  };
  const common = {
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  };
  const cases = [
    [{ ...base, OPERATOR_USER: 'operator' }, ['operator_credentials', 'operator_password_strength']],
    [{ ...base, OPERATOR_USER: 'operator', OPERATOR_PASSWORD: 'short' }, ['operator_password_strength']],
    [{ ...base, OPERATOR_USER: 'ADMIN', OPERATOR_PASSWORD: 'long-operator-password' }, ['operator_user_distinct']],
  ];
  for (const [env, expected] of cases) {
    const status = preflight.configStatus({ env, ...common });
    assert.strictEqual(status.ready, false);
    assert.deepStrictEqual(
      preflight.summarizeFailures(status).map((line) => line.split(':')[0]),
      expected,
    );
  }

  const strong = preflight.configStatus({
    env: { ...base, OPERATOR_USER: 'operator', OPERATOR_PASSWORD: 'long-operator-password' },
    ...common,
  });
  assert.strictEqual(strong.ready, true);
});

test('production preflight blocks custom but short secrets', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'short-pass',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'short-ingest-key',
      REDACTWALL_SECRET: 'short-session-secret',
      REDACTWALL_DATA_KEY: 'short-data-key',
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'not-valid-!@#',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      AUDITOR_USER: 'auditor',
      AUDITOR_PASSWORD: 'short-auditor',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      APPROVER_USER: 'approver',
      APPROVER_PASSWORD: 'short-approver',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/tmp/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'short-pass',
      INGEST_API_KEY: 'short-ingest-key',
      REDACTWALL_SECRET: 'short-session-secret',
      REDACTWALL_DATA_KEY: 'short-data-key',
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
      REDACTWALL_DB_PATH: '/tmp/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'not-valid-!@#',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/tmp/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      AUDITOR_USER: 'auditor',
      AUDITOR_PASSWORD: 'short',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
      REDACTWALL_DB_PATH: '/tmp/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      APPROVER_USER: 'approver',
      APPROVER_PASSWORD: 'short',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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

test('production Postgres preflight skips SQLite paths and requires a TLS connection URL', () => {
  const common = {
    NODE_ENV: 'production',
    REDACTWALL_TENANT_ID: 'cu-production',
    REDACTWALL_SAAS_MODE: 'true',
    REDACTWALL_SEAT_LIMIT: '100',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    REDACTWALL_SECRET: 's'.repeat(32),
    REDACTWALL_DATA_KEY: 'd'.repeat(32),
  };
  const inputs = {
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  };
  const password = 'database-password-must-not-leak';

  const { REDACTWALL_TENANT_ID: _tenant, ...unscopedCommon } = common;
  const unscoped = preflight.configStatus({
    env: {
      ...unscopedCommon,
      REDACTWALL_DB_DRIVER: 'postgres',
      REDACTWALL_DATABASE_URL: `postgresql://redactwall:${password}@db.internal:5432/redactwall?sslmode=require`,
    },
    ...inputs,
  });
  assert.strictEqual(unscoped.ready, false);
  assert.strictEqual(unscoped.checks.find((item) => item.id === 'postgres_tenant_context').ok, false);

  for (const driver of ['postgres', 'postgresql', 'pg']) {
    for (const protocol of ['postgres:', 'postgresql:']) {
      for (const sslmode of ['require', 'verify-ca', 'verify-full']) {
        const status = preflight.configStatus({
          env: {
            ...common,
            REDACTWALL_DB_DRIVER: driver,
            REDACTWALL_DATABASE_URL: `${protocol}//redactwall:${password}@db.internal:5432/redactwall?sslmode=${sslmode}`,
          },
          ...inputs,
        });
        assert.strictEqual(status.ready, true, `${driver} ${protocol} ${sslmode}`);
        assert.strictEqual(status.checks.find((item) => item.id === 'sqlite_local_disk').ok, true);
        assert.strictEqual(status.checks.find((item) => item.id === 'postgres_tls').ok, true);
        assert.doesNotMatch(JSON.stringify(status), new RegExp(password));
      }
    }
  }

  for (const databaseUrl of [
    '',
    'https://db.internal/redactwall?sslmode=require',
    `postgresql://redactwall:${password}@db.internal:5432/redactwall`,
    `postgresql://redactwall:${password}@db.internal:5432/redactwall?sslmode=prefer`,
    `postgresql://redactwall:${password}@db.internal:5432/redactwall?sslmode=require#fragment-secret`,
    `postgresql://redactwall@db.internal:5432/redactwall?sslmode=require&password=first&password=second`,
    `postgresql://redactwall:${password}@db.internal:5432/redactwall?sslmode=require&hostaddr=203.0.113.9`,
    `postgresql://redactwall:${password}@db.internal:5432/path-db?sslmode=require&dbname=other-db`,
    `postgresql://redactwall:${password}@db.internal:5432/redactwall?sslmode=require&passfile=%2Fprivate%2Fpgpass`,
  ]) {
    const status = preflight.configStatus({
      env: {
        ...common,
        REDACTWALL_DB_DRIVER: 'postgres',
        REDACTWALL_DATABASE_URL: databaseUrl,
      },
      ...inputs,
    });
    const postgresCheck = status.checks.find((item) => item.id === 'postgres_tls');
    assert.strictEqual(status.ready, false, databaseUrl || 'missing URL');
    assert.strictEqual(postgresCheck && postgresCheck.ok, false, databaseUrl || 'missing URL');
    assert.doesNotMatch(JSON.stringify(status), new RegExp(password));
  }
});

test('production preflight rejects an explicit unsupported database driver', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_DRIVER: 'postgress',
      REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
    },
    adminPasswordIsDefault: false,
    ingestKeyIsDefault: false,
    secretSource: 'env',
    dataCryptoEnabled: true,
    cookieSecure: true,
  });
  const driverCheck = status.checks.find((item) => item.id === 'db_driver');

  assert.strictEqual(status.ready, false);
  assert.strictEqual(driverCheck && driverCheck.ok, false);
});

test('production preflight blocks cloud-synced sqlite paths', () => {
  const status = preflight.configStatus({
    env: {
      NODE_ENV: 'production',
      REDACTWALL_DB_PATH: 'C:\\Users\\Pilot\\OneDrive - Credit Union\\redactwall.db',
      ADMIN_PASSWORD: 'long-admin-password',
      ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
      INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
      REDACTWALL_SECRET: 's'.repeat(32),
      REDACTWALL_DATA_KEY: 'd'.repeat(32),
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
  assert.strictEqual(preflight.cloudSyncedPathReason('\\\\fileserver\\share\\redactwall.db'), 'network share');
  assert.strictEqual(preflight.cloudSyncedPathReason('/Users/pilot/Dropbox/redactwall.db'), 'Dropbox');
  assert.strictEqual(preflight.cloudSyncedPathReason('/Users/pilot/Google Drive/redactwall.db'), 'Google Drive');
  assert.strictEqual(preflight.cloudSyncedPathReason('/var/lib/redactwall/redactwall.db'), null);
});

test('boolean env parsing accepts common true values only', () => {
  assert.strictEqual(preflight.bool('true'), true);
  assert.strictEqual(preflight.bool('1'), true);
  assert.strictEqual(preflight.bool('yes'), true);
  assert.strictEqual(preflight.bool('false'), false);
  assert.strictEqual(preflight.bool('0'), false);
});
