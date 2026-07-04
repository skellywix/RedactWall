'use strict';
/**
 * SaaS/customer tenancy helpers.
 *
 * The current commercial-safe shape is a customer-silo deployment: one
 * PromptWall stack per paying customer. These checks make that stack behave
 * like a tenant-bound SaaS instance without weakening the existing audit store.
 */

const UNKNOWN_USERS = new Set(['', 'unknown', 'unattributed@unmanaged']);
const TENANT_ID = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const { withEnvAliases } = require('./env');

function bool(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').toLowerCase());
}

function normalizeTenantId(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeUser(value) {
  return String(value || '').trim().toLowerCase();
}

function hasSeatLimit(value) {
  return value != null && String(value).trim() !== '';
}

function validSeatLimit(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0;
}

function parseSeatLimit(value) {
  if (value == null || value === '') return 0;
  if (!validSeatLimit(value)) return 0;
  const n = Number(value);
  return n;
}

function validTenantId(value) {
  return TENANT_ID.test(normalizeTenantId(value));
}

function isBillableUser(value) {
  const user = normalizeUser(value);
  return !UNKNOWN_USERS.has(user);
}

function config(env = process.env) {
  const resolved = withEnvAliases(env);
  const tenantId = normalizeTenantId(resolved.SENTINEL_TENANT_ID);
  const explicitSaasMode = bool(resolved.SENTINEL_SAAS_MODE);
  const requireTenantContext = bool(resolved.SENTINEL_REQUIRE_TENANT_CONTEXT);
  const requireUserIdentity = bool(resolved.SENTINEL_REQUIRE_USER_IDENTITY);
  const seatLimitConfigured = hasSeatLimit(resolved.SENTINEL_SEAT_LIMIT);
  const seatLimitValid = seatLimitConfigured && validSeatLimit(resolved.SENTINEL_SEAT_LIMIT);
  const seatLimit = parseSeatLimit(resolved.SENTINEL_SEAT_LIMIT);
  const saasMode = explicitSaasMode || !!tenantId || seatLimitConfigured || requireTenantContext || requireUserIdentity;
  return {
    saasMode,
    tenantId,
    tenantIdValid: !tenantId || validTenantId(tenantId),
    seatLimit,
    seatLimitConfigured,
    seatLimitValid,
    requireTenantContext: requireTenantContext || saasMode,
    requireUserIdentity: requireUserIdentity || saasMode,
  };
}

function seatReport(db, env = process.env) {
  const cfg = config(env);
  const orgId = cfg.tenantId || null;
  const stats = db && typeof db.seatStats === 'function'
    ? db.seatStats({ orgId })
    : { users: [], seatsUsed: 0 };
  const seatsUsed = Number(stats.seatsUsed || 0);
  const seatLimit = cfg.seatLimit || 0;
  return {
    tenantId: cfg.tenantId || null,
    saasMode: cfg.saasMode,
    seatLimit,
    seatLimitValid: !cfg.saasMode || cfg.seatLimitValid,
    seatsUsed,
    seatsRemaining: seatLimit ? Math.max(0, seatLimit - seatsUsed) : null,
    overLimit: !!(seatLimit && seatsUsed > seatLimit),
    users: stats.users || [],
  };
}

function deactivatedIdentityResult(user, cfg) {
  return {
    ok: false,
    statusCode: 403,
    status: 'user_deactivated',
    action: 'USER_DEACTIVATED',
    message: 'user identity is deactivated',
    audit: true,
    orgId: cfg.tenantId || null,
    user,
  };
}

function validateSensorAccess({ body = {}, db, env = process.env } = {}) {
  const cfg = config(env);
  const sensorUser = normalizeUser(body.user);
  if (sensorUser && db && typeof db.scimIdentityInactive === 'function' && db.scimIdentityInactive(sensorUser)) {
    return deactivatedIdentityResult(sensorUser, cfg);
  }
  if (!cfg.saasMode) {
    return { ok: true, orgId: body.orgId || null };
  }

  if (!cfg.tenantId || !cfg.tenantIdValid) {
    return {
      ok: false,
      statusCode: 503,
      status: 'tenant_not_configured',
      action: 'TENANT_NOT_CONFIGURED',
      message: 'tenant is not configured',
      audit: false,
    };
  }

  if (!cfg.seatLimitValid) {
    return {
      ok: false,
      statusCode: 503,
      status: 'seat_limit_not_configured',
      action: 'SEAT_LIMIT_NOT_CONFIGURED',
      message: 'seat limit is not configured',
      audit: false,
    };
  }

  const suppliedOrg = normalizeTenantId(body.orgId);
  if (cfg.requireTenantContext && !suppliedOrg) {
    return {
      ok: false,
      statusCode: 400,
      status: 'tenant_context_required',
      action: 'TENANT_CONTEXT_REQUIRED',
      message: 'tenant context required',
      audit: false,
    };
  }
  if (suppliedOrg && suppliedOrg !== cfg.tenantId) {
    return {
      ok: false,
      statusCode: 403,
      status: 'tenant_mismatch',
      action: 'TENANT_MISMATCH',
      message: 'tenant mismatch',
      audit: false,
    };
  }

  if (cfg.requireUserIdentity && !isBillableUser(sensorUser)) {
    return {
      ok: false,
      statusCode: 400,
      status: 'user_identity_required',
      action: 'USER_IDENTITY_REQUIRED',
      message: 'managed user identity required',
      audit: false,
    };
  }

  if (cfg.seatLimit > 0 && isBillableUser(sensorUser)) {
    const report = seatReport(db, env);
    const known = report.users.some((item) => normalizeUser(item.user) === sensorUser);
    if (!known && report.seatsUsed >= cfg.seatLimit) {
      return {
        ok: false,
        statusCode: 402,
        status: 'seat_limit_blocked',
        action: 'SEAT_LIMIT_BLOCKED',
        message: 'seat limit exceeded',
        audit: true,
        orgId: cfg.tenantId,
        user: sensorUser,
        seatLimit: cfg.seatLimit,
        seatsUsed: report.seatsUsed,
      };
    }
  }

  return { ok: true, orgId: cfg.tenantId };
}

module.exports = {
  config,
  isBillableUser,
  normalizeTenantId,
  normalizeUser,
  parseSeatLimit,
  seatReport,
  validateSensorAccess,
  validTenantId,
};
