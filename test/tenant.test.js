'use strict';
const test = require('node:test');
const assert = require('node:assert');
const tenant = require('../server/tenant');

function fakeDb(users = []) {
  return {
    seatStats() {
      return { seatsUsed: users.length, users: users.map((user) => ({ user })) };
    },
  };
}

const saasEnv = {
  SENTINEL_SAAS_MODE: 'true',
  SENTINEL_TENANT_ID: 'cu-acme',
  SENTINEL_SEAT_LIMIT: '1',
};

test('tenant config normalizes SaaS settings', () => {
  const cfg = tenant.config({
    SENTINEL_SAAS_MODE: 'true',
    SENTINEL_TENANT_ID: ' CU-Acme ',
    SENTINEL_SEAT_LIMIT: '25',
  });
  assert.strictEqual(cfg.saasMode, true);
  assert.strictEqual(cfg.tenantId, 'cu-acme');
  assert.strictEqual(cfg.seatLimit, 25);
  assert.strictEqual(cfg.seatLimitValid, true);
  assert.strictEqual(cfg.requireTenantContext, true);
  assert.strictEqual(cfg.requireUserIdentity, true);
});

test('tenant config accepts PromptWall SaaS env aliases', () => {
  const cfg = tenant.config({
    PROMPTWALL_SAAS_MODE: 'true',
    PROMPTWALL_TENANT_ID: ' CU-Acme ',
    PROMPTWALL_SEAT_LIMIT: '25',
  });
  assert.strictEqual(cfg.saasMode, true);
  assert.strictEqual(cfg.tenantId, 'cu-acme');
  assert.strictEqual(cfg.seatLimit, 25);
  assert.strictEqual(cfg.seatLimitValid, true);
  assert.strictEqual(cfg.requireTenantContext, true);
  assert.strictEqual(cfg.requireUserIdentity, true);
});

test('tenant config fails closed when SaaS settings are partially present', () => {
  const cfg = tenant.config({
    SENTINEL_TENANT_ID: 'cu-acme',
    SENTINEL_SAAS_MODE: 'false',
  });

  assert.strictEqual(cfg.saasMode, true);
  assert.strictEqual(cfg.requireTenantContext, true);
  assert.strictEqual(cfg.requireUserIdentity, true);
});

test('tenant config treats requirement flags as SaaS mode', () => {
  const cfg = tenant.config({
    SENTINEL_REQUIRE_TENANT_CONTEXT: 'true',
  });

  assert.strictEqual(cfg.saasMode, true);
  assert.strictEqual(cfg.requireTenantContext, true);
  assert.strictEqual(cfg.requireUserIdentity, true);
});

test('non-SaaS sensor access passes through optional org id', () => {
  assert.deepStrictEqual(tenant.validateSensorAccess({
    body: { orgId: 'pilot-org', user: '' },
    db: fakeDb(),
    env: {},
  }), {
    ok: true,
    orgId: 'pilot-org',
  });
});

test('SaaS sensor access requires tenant and managed user identity', () => {
  const missingTenant = tenant.validateSensorAccess({
    body: { user: 'analyst@example.test' },
    db: fakeDb(),
    env: saasEnv,
  });
  assert.strictEqual(missingTenant.ok, false);
  assert.strictEqual(missingTenant.status, 'tenant_context_required');

  const unmanaged = tenant.validateSensorAccess({
    body: { orgId: 'cu-acme', user: 'unattributed@unmanaged' },
    db: fakeDb(),
    env: saasEnv,
  });
  assert.strictEqual(unmanaged.ok, false);
  assert.strictEqual(unmanaged.status, 'user_identity_required');
});

test('SaaS sensor access fails closed without a valid configured tenant id', () => {
  for (const tenantId of [undefined, '', 'Invalid Tenant!']) {
    const env = {
      SENTINEL_SAAS_MODE: 'true',
      SENTINEL_SEAT_LIMIT: '1',
    };
    if (tenantId !== undefined) env.SENTINEL_TENANT_ID = tenantId;
    const result = tenant.validateSensorAccess({
      body: { orgId: 'cu-acme', user: 'analyst@example.test' },
      db: fakeDb(),
      env,
    });
    const label = tenantId === undefined ? 'missing' : tenantId;
    assert.strictEqual(result.ok, false, label);
    assert.strictEqual(result.statusCode, 503, label);
    assert.strictEqual(result.status, 'tenant_not_configured', label);
    assert.strictEqual(result.audit, false, label);
  }
});

test('SaaS sensor access rejects cross-tenant events', () => {
  const result = tenant.validateSensorAccess({
    body: { orgId: 'other-cu', user: 'analyst@example.test' },
    db: fakeDb(),
    env: saasEnv,
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.statusCode, 403);
  assert.strictEqual(result.status, 'tenant_mismatch');
});

test('SaaS seat limit allows known users and blocks new users', () => {
  const known = tenant.validateSensorAccess({
    body: { orgId: 'cu-acme', user: 'analyst@example.test' },
    db: fakeDb(['analyst@example.test']),
    env: saasEnv,
  });
  assert.strictEqual(known.ok, true);
  assert.strictEqual(known.orgId, 'cu-acme');

  const blocked = tenant.validateSensorAccess({
    body: { orgId: 'cu-acme', user: 'new-user@example.test' },
    db: fakeDb(['analyst@example.test']),
    env: saasEnv,
  });
  assert.strictEqual(blocked.ok, false);
  assert.strictEqual(blocked.statusCode, 402);
  assert.strictEqual(blocked.status, 'seat_limit_blocked');
  assert.strictEqual(blocked.audit, true);
});

test('SaaS sensor access fails closed when paid seat limit is missing or invalid', () => {
  for (const seatLimit of [undefined, '', '0', '-1', '1.5', 'not-a-number']) {
    const env = {
      SENTINEL_SAAS_MODE: 'true',
      SENTINEL_TENANT_ID: 'cu-acme',
    };
    if (seatLimit !== undefined) {
      env.SENTINEL_SEAT_LIMIT = seatLimit;
    }
    const result = tenant.validateSensorAccess({
      body: { orgId: 'cu-acme', user: 'analyst@example.test' },
      db: fakeDb(),
      env,
    });
    const label = seatLimit === undefined ? 'missing' : seatLimit;
    assert.strictEqual(result.ok, false, label);
    assert.strictEqual(result.statusCode, 503, label);
    assert.strictEqual(result.status, 'seat_limit_not_configured', label);
    assert.strictEqual(result.audit, false, label);
  }

  const report = tenant.seatReport(fakeDb(['analyst@example.test']), {
    SENTINEL_SAAS_MODE: 'true',
    SENTINEL_TENANT_ID: 'cu-acme',
    SENTINEL_SEAT_LIMIT: 'not-a-number',
  });
  assert.strictEqual(report.saasMode, true);
  assert.strictEqual(report.seatLimit, 0);
  assert.strictEqual(report.seatLimitValid, false);
});
