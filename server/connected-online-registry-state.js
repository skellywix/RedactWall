'use strict';

const VERDICT_DOMAIN = 'redactwall.connected-license-verdict.v2';
const STATE_VERSION = 1;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const DEPLOYMENT_ID_RE = /^dep_[a-f0-9]{32}$/;
const KEY_ID_RE = /^rw-online-verdict-[a-f0-9]{64}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const ISO_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const PAYLOAD_KEYS = Object.freeze([
  'customerId', 'deploymentId', 'issuedAt', 'keyId', 'kind',
  'registryGeneration', 'registryStateDigest', 'status',
]);

function initialState(customerId, deploymentId) {
  assertBinding(customerId, deploymentId);
  return Object.freeze({
    stateVersion: STATE_VERSION,
    customerId,
    deploymentId,
    connectedEver: false,
    highWaterIntact: true,
    registryGeneration: 0,
    registryStateDigest: null,
    status: null,
    verdictPayload: null,
    signedEnvelopeDigest: null,
    signingKeyId: null,
    signingKeyFingerprint: null,
    signatureDomain: null,
    issuedAt: null,
    acceptedAt: null,
    lastContactAt: null,
    trustedTimeMs: 0,
  });
}

function restoreState(value, expected = {}) {
  const state = checkedState(value);
  if (expected.customerId && state.customerId !== expected.customerId) {
    throw registryError('registry_customer_mismatch');
  }
  if (expected.deploymentId && state.deploymentId !== expected.deploymentId) {
    throw registryError('registry_deployment_mismatch');
  }
  return state;
}

function applyVerifiedRegistryVerdict(stateValue, verifiedValue, options = {}) {
  const context = applyContext(stateValue, verifiedValue, options);
  if (context.progression === 'exact_replay') return replayResult(context.current);
  return appliedResult(context);
}

function applyContext(stateValue, verifiedValue, options) {
  const current = restoreState(stateValue);
  if (!current.highWaterIntact) throw registryError('registry_state_high_water_invalid');
  const verified = checkedVerification(verifiedValue);
  const candidate = verified.payload;
  if (candidate.customerId !== current.customerId) throw registryError('registry_customer_mismatch');
  if (candidate.deploymentId !== current.deploymentId) throw registryError('registry_deployment_mismatch');
  const nowMs = checkedNow(options.nowMs);
  const issuedAtMs = Date.parse(candidate.issuedAt);
  if (nowMs + MAX_CLOCK_SKEW_MS < current.trustedTimeMs) {
    throw registryError('registry_clock_rollback');
  }
  if (Math.abs(issuedAtMs - nowMs) > MAX_CLOCK_SKEW_MS) throw registryError('registry_clock_skew');
  const progression = progressionFor(current, verified, issuedAtMs);
  return { current, verified, candidate, nowMs, issuedAtMs, progression };
}

function replayResult(current) {
  return Object.freeze({
    state: current,
    idempotent: true,
    contactAdvanced: false,
    restored: false,
    auditAction: 'CONNECTED_REGISTRY_VERDICT_REPLAYED',
  });
}

function appliedResult(context) {
  const { current, verified, candidate, nowMs, issuedAtMs, progression } = context;
  const now = new Date(nowMs).toISOString();
  const restored = current.status === 'revoked' && candidate.status === 'active';
  const next = {
    ...current,
    connectedEver: true,
    highWaterIntact: true,
    registryGeneration: candidate.registryGeneration,
    registryStateDigest: candidate.registryStateDigest,
    status: candidate.status,
    verdictPayload: candidate,
    signedEnvelopeDigest: verified.signedEnvelopeDigest,
    signingKeyId: verified.signingKeyId,
    signingKeyFingerprint: verified.signingKeyFingerprint,
    signatureDomain: verified.signatureDomain,
    issuedAt: candidate.issuedAt,
    acceptedAt: now,
    lastContactAt: now,
    trustedTimeMs: Math.max(current.trustedTimeMs, nowMs, issuedAtMs),
  };
  return Object.freeze({
    state: checkedState(next),
    idempotent: progression === 'refresh',
    contactAdvanced: true,
    restored,
    auditAction: progression === 'refresh'
      ? 'CONNECTED_REGISTRY_VERDICT_REFRESHED'
      : restored ? 'CONNECTED_REGISTRY_VERDICT_RESTORED'
        : candidate.status === 'revoked'
          ? 'CONNECTED_REGISTRY_VERDICT_REVOKED'
          : 'CONNECTED_REGISTRY_VERDICT_APPLIED',
  });
}

function progressionFor(current, verified, issuedAtMs) {
  const candidate = verified.payload;
  if (!current.connectedEver) return 'advance';
  if (candidate.registryGeneration < current.registryGeneration) {
    throw registryError('registry_generation_stale');
  }
  const currentIssuedAtMs = Date.parse(current.issuedAt);
  if (candidate.registryGeneration === current.registryGeneration) {
    if (candidate.registryStateDigest !== current.registryStateDigest
        || candidate.status !== current.status) {
      throw registryError('registry_generation_conflict');
    }
    if (issuedAtMs < currentIssuedAtMs) throw registryError('registry_verdict_replay');
    if (issuedAtMs === currentIssuedAtMs) {
      if (verified.signedEnvelopeDigest !== current.signedEnvelopeDigest
          || verified.signingKeyId !== current.signingKeyId
          || verified.signingKeyFingerprint !== current.signingKeyFingerprint) {
        throw registryError('registry_generation_conflict');
      }
      return 'exact_replay';
    }
    return 'refresh';
  }
  if (issuedAtMs < currentIssuedAtMs) throw registryError('registry_verdict_replay');
  return 'advance';
}

function combineConnectedDisposition(stateValue, entitlementDisposition) {
  let registry;
  try { registry = restoreState(stateValue); }
  catch { return blocked('registry_state_invalid', 0, null); }
  if (!registry.connectedEver || registry.registryGeneration < 1) {
    return blocked('registry_enrollment_required', 0, null);
  }
  if (!registry.highWaterIntact) {
    return blocked('registry_state_invalid', registry.registryGeneration, registry.registryStateDigest);
  }
  if (registry.status === 'revoked') {
    return blocked(
      'vendor_registry_revoked', registry.registryGeneration, registry.registryStateDigest,
      'revoked',
    );
  }
  const entitlement = checkedDisposition(entitlementDisposition);
  if (!entitlement) {
    return blocked(
      'entitlement_state_invalid', registry.registryGeneration, registry.registryStateDigest,
    );
  }
  return Object.freeze({
    ...entitlement,
    onlineRegistryGeneration: registry.registryGeneration,
    onlineRegistryStateDigest: registry.registryStateDigest,
  });
}

function registryGenerationForHeartbeat(stateValue) {
  if (stateValue === null || stateValue === undefined) return 0;
  const state = restoreState(stateValue);
  return state.connectedEver ? state.registryGeneration : 0;
}

function checkedVerification(value) {
  if (!plainRecord(value) || !exactKeys(value, [
    'payload', 'signatureDomain', 'signedEnvelopeDigest',
    'signingKeyFingerprint', 'signingKeyId',
  ])) throw registryError('registry_verification_invalid');
  const payload = checkedPayload(value.payload);
  if (value.signatureDomain !== VERDICT_DOMAIN
      || !SHA256_RE.test(String(value.signedEnvelopeDigest || ''))
      || !KEY_ID_RE.test(String(value.signingKeyId || ''))
      || !SHA256_RE.test(String(value.signingKeyFingerprint || ''))
      || payload.keyId !== value.signingKeyId
      || value.signingKeyId !== `rw-online-verdict-${value.signingKeyFingerprint}`) {
    throw registryError('registry_verification_invalid');
  }
  return Object.freeze({
    payload,
    signatureDomain: value.signatureDomain,
    signedEnvelopeDigest: value.signedEnvelopeDigest,
    signingKeyId: value.signingKeyId,
    signingKeyFingerprint: value.signingKeyFingerprint,
  });
}

function checkedPayload(value) {
  if (!plainRecord(value) || !exactKeys(value, PAYLOAD_KEYS)
      || value.kind !== VERDICT_DOMAIN
      || !['active', 'revoked'].includes(value.status)
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !DEPLOYMENT_ID_RE.test(String(value.deploymentId || ''))
      || !validIsoTime(value.issuedAt)
      || !Number.isSafeInteger(value.registryGeneration) || value.registryGeneration < 1
      || !SHA256_RE.test(String(value.registryStateDigest || ''))) {
    throw registryError('registry_payload_invalid');
  }
  return Object.freeze(Object.fromEntries(PAYLOAD_KEYS.map((key) => [key, value[key]])));
}

function checkedState(value) {
  if (!plainRecord(value)) throw registryError('registry_state_invalid');
  const baseline = initialState(value.customerId, value.deploymentId);
  if (!exactKeys(value, Object.keys(baseline))) throw registryError('registry_state_unknown_field');
  assertStateHeader(value);
  if (!value.connectedEver) return checkedEmptyState(value);
  return checkedConnectedState(value);
}

function assertStateHeader(value) {
  if (value.stateVersion !== STATE_VERSION || typeof value.connectedEver !== 'boolean'
      || typeof value.highWaterIntact !== 'boolean'
      || !Number.isSafeInteger(value.registryGeneration) || value.registryGeneration < 0
      || !Number.isSafeInteger(value.trustedTimeMs) || value.trustedTimeMs < 0) {
    throw registryError('registry_state_invalid');
  }
}

function checkedEmptyState(value) {
  const empty = value.registryGeneration === 0 && value.registryStateDigest === null
    && value.status === null && value.verdictPayload === null
    && value.signedEnvelopeDigest === null && value.signingKeyId === null
    && value.signingKeyFingerprint === null && value.signatureDomain === null
    && value.issuedAt === null && value.acceptedAt === null && value.lastContactAt === null;
  if (!empty) throw registryError('registry_state_high_water_invalid');
  return Object.freeze({ ...value });
}

function checkedConnectedState(value) {
  let payload;
  try { payload = checkedPayload(value.verdictPayload); }
  catch { throw registryError('registry_state_high_water_invalid'); }
  if (!value.highWaterIntact || payload.customerId !== value.customerId
      || payload.deploymentId !== value.deploymentId
      || payload.registryGeneration !== value.registryGeneration
      || payload.registryStateDigest !== value.registryStateDigest
      || payload.status !== value.status || payload.issuedAt !== value.issuedAt
      || payload.keyId !== value.signingKeyId
      || value.signatureDomain !== VERDICT_DOMAIN
      || !SHA256_RE.test(String(value.signedEnvelopeDigest || ''))
      || !KEY_ID_RE.test(String(value.signingKeyId || ''))
      || !SHA256_RE.test(String(value.signingKeyFingerprint || ''))
      || !validIsoTime(value.acceptedAt) || !validIsoTime(value.lastContactAt)) {
    throw registryError('registry_state_high_water_invalid');
  }
  return Object.freeze({ ...value, verdictPayload: payload });
}

function assertBinding(customerId, deploymentId) {
  if (!CUSTOMER_ID_RE.test(String(customerId || ''))
      || !DEPLOYMENT_ID_RE.test(String(deploymentId || ''))) {
    throw registryError('registry_binding_invalid');
  }
}

function checkedNow(value) {
  const nowMs = value === undefined ? Date.now() : Number(value);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw registryError('registry_time_invalid');
  return nowMs;
}

function checkedDisposition(value) {
  const allowed = ['authority', 'fallbackDeadline', 'mode', 'protectedEgress', 'reason'];
  if (!plainRecord(value) || Object.keys(value).some((key) => !allowed.includes(key))
      || !['allow', 'block'].includes(value.protectedEgress)
      || !/^[a-z][a-z0-9_-]{0,47}$/.test(String(value.mode || ''))
      || (value.reason !== null
        && !/^[a-z][a-z0-9_.:-]{0,79}$/.test(String(value.reason || '')))
      || (Object.hasOwn(value, 'fallbackDeadline')
        && value.fallbackDeadline !== null && !validIsoTime(value.fallbackDeadline))) return null;
  const authority = checkedEntitlementAuthority(value.authority);
  if (value.authority !== null && !authority) return null;
  if (value.protectedEgress === 'allow' && !authority) return null;
  const output = {
    protectedEgress: value.protectedEgress,
    mode: value.mode,
    reason: value.reason,
    authority,
  };
  if (Object.hasOwn(value, 'fallbackDeadline')) output.fallbackDeadline = value.fallbackDeadline;
  return output;
}

function checkedEntitlementAuthority(value) {
  if (value === null) return null;
  if (!plainRecord(value) || !exactKeys(value, ['features', 'plan', 'seats'])
      || !['standard', 'enterprise'].includes(value.plan)
      || !Number.isSafeInteger(value.seats) || value.seats < 0 || value.seats > 1_000_000
      || !Array.isArray(value.features) || value.features.length > 128) return null;
  const features = [];
  for (const item of value.features) {
    if (!/^[a-z0-9][a-z0-9_.-]{0,63}$/.test(String(item || ''))) return null;
    features.push(item);
  }
  if (new Set(features).size !== features.length) return null;
  return Object.freeze({ plan: value.plan, seats: value.seats, features: Object.freeze([...features]) });
}

function blocked(reason, generation, digest, mode = 'blocked') {
  return Object.freeze({
    protectedEgress: 'block',
    mode,
    reason,
    authority: null,
    onlineRegistryGeneration: generation,
    onlineRegistryStateDigest: digest,
  });
}

function validIsoTime(value) {
  return typeof value === 'string' && ISO_TIME_RE.test(value) && Number.isFinite(Date.parse(value));
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function registryError(code) {
  const error = new Error('connected online registry state rejected');
  error.code = code;
  return error;
}

module.exports = Object.freeze({
  MAX_CLOCK_SKEW_MS,
  STATE_VERSION,
  VERDICT_DOMAIN,
  applyVerifiedRegistryVerdict,
  combineConnectedDisposition,
  initialState,
  registryGenerationForHeartbeat,
  restoreState,
});
