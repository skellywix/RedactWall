'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const { systemBootClock } = require('./system-boot-clock');

const STATE_VERSION = 1;
const ENTITLEMENT_SIGNING_KEY_ID_RE = /^rw-entitlement-[a-f0-9]{64}$/;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const FAILURE_CLASSES = new Set([null, ...protocol.FAILURE_CLASSES]);
const RESTRICTION_RANK = Object.freeze({ active: 0, paused: 1, revoked: 2 });

function initialState(customerId, deploymentId) {
  assertBinding(customerId, deploymentId);
  return {
    stateVersion: STATE_VERSION,
    customerId,
    deploymentId,
    connectedEver: false,
    highWaterIntact: true,
    entitlementVersion: 0,
    entitlementDigest: null,
    signingKeyId: null,
    entitlement: null,
    appliedAt: null,
    lastContactAt: null,
    trustedTimeMs: 0,
    monotonicBootId: null,
    monotonicContactMs: null,
    monotonicFallbackDeadlineMs: null,
    failureClass: null,
  };
}

function restoreState(value, expected = {}) {
  const state = checkedState(value);
  if (expected.customerId && state.customerId !== expected.customerId) throw stateError('customer_mismatch');
  if (expected.deploymentId && state.deploymentId !== expected.deploymentId) throw stateError('deployment_mismatch');
  if (!state.entitlement) return state;
  const parsed = protocol.assertChannel(state.entitlement, protocol.CHANNEL_KINDS.ENTITLEMENT);
  if (parsed.customerId !== state.customerId || parsed.deploymentId !== state.deploymentId) {
    throw stateError('state_binding_invalid');
  }
  const digest = protocol.payloadDigest(parsed, protocol.CHANNEL_KINDS.ENTITLEMENT);
  if (digest !== state.entitlementDigest || parsed.entitlementVersion !== state.entitlementVersion) {
    throw stateError('state_high_water_invalid');
  }
  return { ...state, entitlement: parsed };
}

function applyEntitlement(stateValue, candidate, options = {}) {
  const state = restoreState(stateValue);
  const entitlement = protocol.assertChannel(candidate, protocol.CHANNEL_KINDS.ENTITLEMENT);
  if (!ENTITLEMENT_SIGNING_KEY_ID_RE.test(String(options.keyId || ''))) {
    throw stateError('verified_signing_key_required');
  }
  assertEntitlementBinding(state, entitlement);
  const nowMs = options.nowMs ?? Date.now();
  const clock = monotonicClock(options.clock);
  assertTrustedTime(state, nowMs);
  assertEntitlementFresh(entitlement, nowMs);
  assertVersionContinuity(state, entitlement);
  assertRestoreAuthority(state.entitlement, entitlement);

  const decision = protocol.entitlementDecision(entitlement, currentAuthority(state));
  if (decision.action === 'reject') throw stateError(decision.reason);
  if (decision.action === 'acknowledge') {
    return duplicateResult(state, entitlement, decision.digest, options, nowMs, clock);
  }

  const next = appliedState(state, entitlement, decision.digest, options.keyId, nowMs, clock);
  return {
    state: next,
    acknowledgement: acknowledgement(next, 'applied', 'success', 'applied', options, nowMs),
    auditActions: ['CONNECTED_ENTITLEMENT_APPLIED', 'CONNECTED_ENTITLEMENT_ACK_QUEUED'],
    idempotent: false,
  };
}

function recordFailure(stateValue, failureClass, options = {}) {
  const state = restoreState(stateValue);
  if (!FAILURE_CLASSES.has(failureClass) || failureClass === null) throw stateError('failure_class_invalid');
  const nowMs = options.nowMs ?? Date.now();
  if (nowMs + MAX_CLOCK_SKEW_MS < state.trustedTimeMs) {
    return { ...state, failureClass: 'clock_rollback', highWaterIntact: state.highWaterIntact };
  }
  return {
    ...state,
    failureClass,
    trustedTimeMs: options.preserveTrustedTime === true
      ? state.trustedTimeMs : Math.max(state.trustedTimeMs, nowMs),
  };
}

function disposition(stateValue, options = {}, trusted = {}) {
  let state;
  try { state = restoreState(stateValue); } catch { return blocked('connected_state_invalid'); }
  const nowMs = options.nowMs ?? Date.now();
  if (!state.connectedEver || !state.entitlement) return blocked('connected_enrollment_required');
  if (!state.highWaterIntact) return blocked('connected_state_invalid');
  if (nowMs + MAX_CLOCK_SKEW_MS < state.trustedTimeMs) return blocked('clock_rollback');
  if (state.entitlement.status === 'paused') return blocked('vendor_paused', state);
  if (state.entitlement.status === 'revoked') return blocked('vendor_revoked', state);
  const monotonic = monotonicDisposition(state, options.clock);
  if (!monotonic.ok) return blocked(monotonic.reason, state);
  if (!state.failureClass && nowMs <= Date.parse(state.entitlement.expiresAt)) return allowed(state);
  return fallbackResult(
    state,
    nowMs,
    monotonic.nowMs,
    options.offlineLicenseText,
    trusted,
  );
}

function fallbackResult(state, nowMs, monotonicNowMs, offlineLicenseText, trusted) {
  const fallback = protocol.fallbackDisposition({
    connectedEver: state.connectedEver,
    highWaterIntact: state.highWaterIntact,
    entitlement: state.entitlement,
    failureClass: state.failureClass || 'expired',
    trustedTimeMs: state.trustedTimeMs,
  }, nowMs);
  if (fallback.mode !== 'degraded_fallback') return blocked(fallback.reason, state);
  if (monotonicNowMs > state.monotonicFallbackDeadlineMs) {
    return blocked('fallback_expired_monotonic', state);
  }
  const offlinePayload = verifiedOfflinePayload(state, offlineLicenseText, trusted, nowMs);
  if (!offlinePayload) return blocked('offline_fallback_unavailable', state);
  return {
    protectedEgress: 'allow',
    mode: fallback.mode,
    reason: fallback.reason,
    fallbackDeadline: new Date(fallback.deadline).toISOString(),
    authority: clampOfflineAuthority(state.entitlement, offlinePayload),
  };
}

function allowed(state) {
  return {
    protectedEgress: 'allow',
    mode: 'connected',
    reason: null,
    fallbackDeadline: state.entitlement.fallbackUntil,
    authority: authorityFromEntitlement(state.entitlement),
  };
}

function blocked(reason, state = null) {
  return {
    protectedEgress: 'block',
    mode: reason === 'vendor_paused' ? 'paused' : (reason === 'vendor_revoked' ? 'revoked' : 'blocked'),
    reason,
    fallbackDeadline: state?.entitlement?.fallbackUntil || null,
    authority: state?.entitlement ? authorityFromEntitlement(state.entitlement) : null,
  };
}

function clampOfflineAuthority(entitlement, offlinePayload = null) {
  const connected = authorityFromEntitlement(entitlement);
  if (!offlinePayload || typeof offlinePayload !== 'object') return connected;
  const offlineFeatures = Array.isArray(offlinePayload.features) ? new Set(offlinePayload.features) : new Set();
  const features = connected.features.filter((feature) => offlineFeatures.has(feature));
  const offlineSeats = Number.isSafeInteger(offlinePayload.seats) && offlinePayload.seats >= 0
    ? offlinePayload.seats : 0;
  return {
    plan: lowerPlan(connected.plan, offlinePayload.plan),
    seats: Math.min(connected.seats, offlineSeats),
    features,
  };
}

function authorityFromEntitlement(entitlement) {
  return {
    plan: entitlement.plan,
    seats: entitlement.seats,
    features: [...entitlement.features],
  };
}

function lowerPlan(connected, offline) {
  if (connected === 'standard' || offline !== 'enterprise') return 'standard';
  return 'enterprise';
}

function checkedState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw stateError('state_invalid');
  const allowed = new Set(Object.keys(initialState(value.customerId, value.deploymentId)));
  if (Object.keys(value).some((key) => !allowed.has(key))) throw stateError('state_unknown_field');
  if (value.stateVersion !== STATE_VERSION || typeof value.connectedEver !== 'boolean'
      || typeof value.highWaterIntact !== 'boolean') throw stateError('state_invalid');
  if (!Number.isSafeInteger(value.entitlementVersion) || value.entitlementVersion < 0) throw stateError('state_invalid');
  if (value.signingKeyId !== null && !ENTITLEMENT_SIGNING_KEY_ID_RE.test(value.signingKeyId)) {
    throw stateError('state_invalid');
  }
  if (!Number.isSafeInteger(value.trustedTimeMs) || value.trustedTimeMs < 0) throw stateError('state_invalid');
  if (!validMonotonicState(value)) throw stateError('state_invalid');
  if (!FAILURE_CLASSES.has(value.failureClass)) throw stateError('state_invalid');
  if (!validNullableTime(value.appliedAt) || !validNullableTime(value.lastContactAt)) throw stateError('state_invalid');
  if (value.entitlement === null && (value.entitlementVersion !== 0
      || value.entitlementDigest !== null || value.signingKeyId !== null)) {
    throw stateError('state_high_water_invalid');
  }
  return { ...value };
}

function validNullableTime(value) {
  return value === null || (typeof value === 'string' && Number.isFinite(Date.parse(value)));
}

function assertBinding(customerId, deploymentId) {
  if (!isDeploymentId(deploymentId)) throw stateError('deployment_invalid');
  const probe = {
    schemaVersion: 1,
    messageId: crypto.randomUUID(),
    customerId,
    deploymentId,
    kind: protocol.CHANNEL_KINDS.HEARTBEAT,
    heartbeatNonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    plan: 'standard',
    seatsUsed: 0,
    seatLimit: 0,
    version: '0.0.0',
    sentAt: new Date(0).toISOString(),
    lastAppliedEntitlementVersion: 0,
    lastAppliedRegistryGeneration: 0,
    lastAppliedPolicyVersion: 0,
    lastAppliedCatalogVersion: 0,
  };
  protocol.assertChannel(probe, protocol.CHANNEL_KINDS.HEARTBEAT);
}

function assertEntitlementBinding(state, entitlement) {
  if (state.customerId !== entitlement.customerId) throw stateError('customer_mismatch');
  if (state.deploymentId !== entitlement.deploymentId) throw stateError('deployment_mismatch');
}

function assertTrustedTime(state, nowMs) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw stateError('time_invalid');
  if (nowMs + MAX_CLOCK_SKEW_MS < state.trustedTimeMs) throw stateError('clock_rollback');
}

function assertEntitlementFresh(entitlement, nowMs) {
  const issuedAt = Date.parse(entitlement.issuedAt);
  const expiresAt = Date.parse(entitlement.expiresAt);
  if (issuedAt > nowMs + MAX_CLOCK_SKEW_MS) throw stateError('future_entitlement');
  if (expiresAt < nowMs - MAX_CLOCK_SKEW_MS) throw stateError('expired');
}

function assertRestoreAuthority(previous, next) {
  if (!previous || RESTRICTION_RANK[next.status] >= RESTRICTION_RANK[previous.status]) return;
  if (next.status === 'active' && next.reasonCode === 'manual_restore') return;
  throw stateError('explicit_restriction_latched');
}

function assertVersionContinuity(state, entitlement) {
  if (!state.entitlement) {
    if (entitlement.entitlementVersion !== 1 || entitlement.previousVersion !== 0) {
      throw stateError('version_gap');
    }
    return;
  }
  if (entitlement.entitlementVersion > state.entitlementVersion
      && entitlement.previousVersion !== state.entitlementVersion) throw stateError('version_gap');
}

function currentAuthority(state) {
  if (!state.entitlement) return null;
  return { version: state.entitlementVersion, digest: state.entitlementDigest };
}

function appliedState(state, entitlement, digest, keyId, nowMs, clock) {
  const now = new Date(nowMs).toISOString();
  return {
    ...state,
    connectedEver: true,
    highWaterIntact: true,
    entitlementVersion: entitlement.entitlementVersion,
    entitlementDigest: digest,
    signingKeyId: keyId,
    entitlement,
    appliedAt: now,
    lastContactAt: now,
    trustedTimeMs: Math.max(state.trustedTimeMs, nowMs, Date.parse(entitlement.issuedAt)),
    monotonicBootId: clock.bootId,
    monotonicContactMs: clock.nowMs,
    monotonicFallbackDeadlineMs: fallbackMonotonicDeadline(entitlement, nowMs, clock.nowMs),
    failureClass: null,
  };
}

function duplicateResult(state, entitlement, digest, options, nowMs, clock) {
  const next = {
    ...state,
    signingKeyId: options.keyId || state.signingKeyId,
    lastContactAt: new Date(nowMs).toISOString(),
    trustedTimeMs: Math.max(state.trustedTimeMs, nowMs, Date.parse(entitlement.issuedAt)),
    monotonicBootId: clock.bootId,
    monotonicContactMs: clock.nowMs,
    monotonicFallbackDeadlineMs: fallbackMonotonicDeadline(entitlement, nowMs, clock.nowMs),
    failureClass: null,
  };
  return {
    state: next,
    acknowledgement: acknowledgement(next, 'applied', 'success', 'already_applied', options, nowMs, digest),
    auditActions: ['CONNECTED_ENTITLEMENT_ACK_QUEUED'],
    idempotent: true,
    entitlement,
  };
}

function validMonotonicState(value) {
  const empty = value.monotonicBootId === null
    && value.monotonicContactMs === null
    && value.monotonicFallbackDeadlineMs === null;
  if (empty) return value.entitlement === null;
  return typeof value.monotonicBootId === 'string'
    && /^[a-f0-9]{32}$/.test(value.monotonicBootId)
    && Number.isSafeInteger(value.monotonicContactMs) && value.monotonicContactMs >= 0
    && Number.isSafeInteger(value.monotonicFallbackDeadlineMs)
    && value.monotonicFallbackDeadlineMs >= value.monotonicContactMs;
}

function monotonicClock(value) {
  if (value !== undefined) {
    if (!value || typeof value !== 'object'
        || !/^[a-f0-9]{32}$/.test(String(value.bootId || ''))
        || !Number.isSafeInteger(value.nowMs) || value.nowMs < 0) throw stateError('monotonic_clock_invalid');
    return { bootId: value.bootId, nowMs: value.nowMs };
  }
  try { return systemBootClock(); }
  catch { throw stateError('monotonic_clock_unavailable'); }
}

function monotonicDisposition(state, value) {
  let clock;
  try { clock = monotonicClock(value); } catch { return { ok: false, reason: 'monotonic_clock_invalid' }; }
  if (state.monotonicBootId !== clock.bootId) return { ok: false, reason: 'connected_boot_changed' };
  if (clock.nowMs < state.monotonicContactMs) return { ok: false, reason: 'monotonic_clock_rollback' };
  return { ok: true, nowMs: clock.nowMs };
}

function fallbackMonotonicDeadline(entitlement, nowMs, monotonicNowMs) {
  if (!entitlement.fallbackUntil) return monotonicNowMs;
  const remaining = Math.max(0, Date.parse(entitlement.fallbackUntil) - nowMs);
  return monotonicNowMs + Math.min(protocol.MAX_FALLBACK_WINDOW_MS, remaining);
}

function verifiedOfflinePayload(state, offlineLicenseText, trusted, nowMs) {
  if (typeof offlineLicenseText !== 'string' || !canonicalOfflineLicenseText(offlineLicenseText)) return null;
  if (!trusted || typeof trusted.offlinePublicKey !== 'function') return null;
  let publicKeyPem;
  try { publicKeyPem = trusted.offlinePublicKey(); } catch { return null; }
  if (typeof publicKeyPem !== 'string' || !publicKeyPem) return null;
  const license = require('./license');
  const verified = license.verifyLicenseText(offlineLicenseText, {
    publicKeyPem,
    expectedCustomerId: state.customerId,
  });
  if (!verified.ok || license.evaluate(verified.payload, nowMs) !== 'active') return null;
  if (verified.payload.status !== 'active'
      || verified.payload.customerId !== state.customerId
      || !isDeploymentId(verified.payload.deploymentId)
      || verified.payload.deploymentId !== state.deploymentId) return null;
  return verified.payload;
}

function canonicalOfflineLicenseText(value) {
  const raw = String(value || '').trim();
  const parts = raw.split('.');
  if (parts.length !== 2 || !parts.every((part) => /^[A-Za-z0-9+/]+={0,2}$/.test(part))) return false;
  try {
    const payload = Buffer.from(parts[0], 'base64');
    const signature = Buffer.from(parts[1], 'base64');
    return payload.length > 0 && payload.length <= 16 * 1024
      && signature.length === 64
      && payload.toString('base64') === parts[0]
      && signature.toString('base64') === parts[1];
  } catch { return false; }
}

function acknowledgement(state, stage, outcome, reasonCode, options, nowMs, digest = state.entitlementDigest) {
  return protocol.assertChannel({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: (options.randomUUID || crypto.randomUUID)(),
    customerId: state.customerId,
    deploymentId: state.deploymentId,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    targetVersion: state.entitlementVersion,
    targetDigest: digest,
    lifecycleStage: stage,
    outcome,
    reasonCode,
    recordedAt: new Date(nowMs).toISOString(),
  }, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
}

function stateError(code) {
  const error = new Error('connected entitlement state rejected');
  error.code = code;
  return error;
}

module.exports = {
  STATE_VERSION,
  MAX_CLOCK_SKEW_MS,
  initialState,
  restoreState,
  applyEntitlement,
  recordFailure,
  disposition,
  clampOfflineAuthority,
};
