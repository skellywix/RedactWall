'use strict';
const test = require('node:test');
const assert = require('node:assert');
const tenant = require('../src/tenant');

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
