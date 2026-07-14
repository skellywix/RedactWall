'use strict';
/**
 * SaaS/customer tenancy helpers.
 *
 * The current commercial-safe shape is a customer-silo deployment: one
 * RedactWall stack per paying customer. These checks make that stack behave
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
  const tenantId = normalizeTenantId(resolved.REDACTWALL_TENANT_ID);
  const explicitSaasMode = bool(resolved.REDACTWALL_SAAS_MODE);
  const requireTenantContext = bool(resolved.REDACTWALL_REQUIRE_TENANT_CONTEXT);
  const requireUserIdentity = bool(resolved.REDACTWALL_REQUIRE_USER_IDENTITY);
  const seatLimitConfigured = hasSeatLimit(resolved.REDACTWALL_SEAT_LIMIT);
  const seatLimitValid = seatLimitConfigured && validSeatLimit(resolved.REDACTWALL_SEAT_LIMIT);
  const seatLimit = parseSeatLimit(resolved.REDACTWALL_SEAT_LIMIT);
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

function configWithSeatOverride(env, seatLimitOverride) {
  const cfg = config(env);
  if (seatLimitOverride === undefined) return cfg;
  const valid = Number.isSafeInteger(seatLimitOverride)
    && seatLimitOverride >= 0 && seatLimitOverride <= 1_000_000;
  return {
    ...cfg,
    saasMode: true,
    seatLimit: valid ? seatLimitOverride : 0,
    seatLimitConfigured: true,
    seatLimitValid: valid,
    requireTenantContext: true,
    requireUserIdentity: true,
  };
}

function checkedSeatStats(db, orgId) {
  if (!db || typeof db.seatStats !== 'function') {
    return { valid: false, seatsUsed: 0, users: [] };
  }
  let stats;
  try { stats = db.seatStats({ orgId }); }
  catch { return { valid: false, seatsUsed: 0, users: [] }; }
  const users = stats && Array.isArray(stats.users) ? stats.users : null;
  const seatsUsed = stats && stats.seatsUsed;
  const normalizedUsers = users && users.map((item) => (
    item && typeof item === 'object' && !Array.isArray(item)
      && typeof item.user === 'string' ? normalizeUser(item.user) : ''
  ));
  const uniqueUsers = normalizedUsers && new Set(normalizedUsers);
  const valid = !!stats && typeof stats === 'object' && !Array.isArray(stats)
    && Number.isSafeInteger(seatsUsed) && seatsUsed >= 0 && seatsUsed <= 1_000_000
    && Array.isArray(users) && normalizedUsers.every(isBillableUser)
    && uniqueUsers.size === users.length && seatsUsed === users.length;
  return valid
    ? { valid: true, seatsUsed, users }
    : { valid: false, seatsUsed: 0, users: [] };
}

function seatReport(db, env = process.env, options = {}) {
  const cfg = configWithSeatOverride(env, options.seatLimitOverride);
  const orgId = cfg.tenantId || null;
  const stats = checkedSeatStats(db, orgId);
  const seatsUsed = stats.seatsUsed;
  const seatLimit = cfg.seatLimit || 0;
  return {
    tenantId: cfg.tenantId || null,
    saasMode: cfg.saasMode,
    seatLimit,
    seatLimitConfigured: cfg.seatLimitConfigured,
    seatLimitValid: !cfg.saasMode || cfg.seatLimitValid,
    seatStateValid: stats.valid,
    seatsUsed,
    seatsRemaining: stats.valid && cfg.seatLimitConfigured
      ? Math.max(0, seatLimit - seatsUsed) : null,
    overLimit: !stats.valid || !!(cfg.seatLimitConfigured && seatsUsed > seatLimit),
    users: stats.users,
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

function releasedSeatResult(user, cfg, seatsUsed) {
  return {
    ok: false,
    statusCode: 403,
    status: 'seat_released',
    action: 'SEAT_RELEASED_BLOCK',
    message: 'license seat is released',
    audit: true,
    orgId: cfg.tenantId || null,
    user,
    seatLimit: cfg.seatLimit || 0,
    seatsUsed: Number(seatsUsed || 0),
  };
}

function validateSensorAccess({
  body = {}, db, env = process.env, seatLimitOverride = undefined,
} = {}) {
  const cfg = configWithSeatOverride(env, seatLimitOverride);
  const sensorUser = normalizeUser(body.user);
  if (sensorUser && db && typeof db.scimIdentityInactive === 'function' && db.scimIdentityInactive(sensorUser)) {
    return deactivatedIdentityResult(sensorUser, cfg);
  }
  // A seat release is an explicit administrator access decision, not merely a
  // SaaS billing annotation. Enforce it before the standalone fast path too.
  if (sensorUser && db && typeof db.getLicenseSeatAssignment === 'function') {
    const assignment = db.getLicenseSeatAssignment(sensorUser);
    if (assignment && assignment.status === 'released') {
      return releasedSeatResult(
        sensorUser, cfg, seatReport(db, env, { seatLimitOverride }).seatsUsed,
      );
    }
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

  if (cfg.seatLimitConfigured && isBillableUser(sensorUser)) {
    const report = seatReport(db, env, { seatLimitOverride });
    if (!report.seatStateValid) {
      return {
        ok: false,
        statusCode: 503,
        status: 'seat_state_invalid',
        action: 'SEAT_STATE_INVALID',
        message: 'seat state is invalid',
        audit: false,
        orgId: cfg.tenantId,
      };
    }
    const known = report.users.some((item) => normalizeUser(item.user) === sensorUser);
    if (cfg.seatLimit === 0 || (!known && report.seatsUsed >= cfg.seatLimit)) {
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
