'use strict';

const { isDeploymentId } = require('./deployment-identity');
const connectedConfig = require('./connected-license-config');
const onlineVerdict = require('./connected-online-verdict');
const { createVendorControlClient } = require('./vendor-control-client');
const { createVendorControlConnector } = require('./vendor-control-connector');

const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const FEATURE_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const REASON_RE = /^[a-z][a-z0-9_.:-]{0,79}$/;
const ISO_MILLISECOND_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_SEATS = 1_000_000;
const SERVICE_READY_RESTRICTIONS = new Set([
  'vendor_paused',
  'vendor_revoked',
  'vendor_registry_revoked',
  'fallback_expired',
  'fallback_expired_monotonic',
  'offline_fallback_unavailable',
  'fallback_failure_not_transport',
  'vendor_state_blocks_fallback',
  'connected_ack_backlog',
]);

function createConnectedLicenseRuntime(options = {}) {
  const ctx = checkedOptions(options);
  const lifecycle = { started: false, stopped: false, stopPromise: null };

  const runtime = {
    configurationHealth: () => ({ ok: true, connected: true }),
    disposition: () => currentDisposition(ctx),
    protectedEgressAllowed: () => currentDisposition(ctx).protectedEgress === 'allow',
    ordinaryLicensedActionAllowed: () => currentDisposition(ctx).protectedEgress === 'allow',
    publicStatus: () => publicStatus(ctx),
    featureEnabled: (feature) => featureEnabled(ctx, feature),
    seatAuthority: () => seatAuthority(ctx),
    safeHeartbeatSnapshot: () => safeHeartbeatSnapshot(ctx),
    readiness: () => readiness(ctx),
    serviceReadiness: () => serviceReadiness(ctx),
    start: () => start(ctx, lifecycle),
    stop: () => stop(ctx, lifecycle),
    synchronize: () => synchronize(ctx, lifecycle),
    sendDiagnostic: (value) => outbound(ctx, lifecycle, 'sendDiagnostic', value),
    sendShadowCandidate: (value) => outbound(ctx, lifecycle, 'sendShadowCandidate', value),
  };
  runtime.requireWritable = restrictionMiddleware(runtime);
  runtime.requireProtectedEgress = restrictionMiddleware(runtime);
  return Object.freeze(runtime);
}

function createConnectedLicenseRuntimeFromEnvironment(options = {}) {
  const env = options.env || process.env;
  const scope = connectedConfig.connectedScopeFromEnv(env, (customerId, deploymentId) => {
    if (typeof customerId !== 'string' || !CUSTOMER_ID_RE.test(customerId)
        || !isDeploymentId(deploymentId)) throw new TypeError();
  });
  const verification = connectedConfig.connectedVerificationKeys(env);
  const onlineKeys = onlineVerdictKeys(env);
  const db = connectedDb(options.db);
  const offlineLicenseText = offlineReader(options);
  const clientFactory = options.clientFactory || createVendorControlClient;
  const connectorFactory = options.connectorFactory || createVendorControlConnector;
  const client = clientFactory(clientOptions(env, scope, verification, onlineKeys, options));
  let connector;
  const proxy = connectorProxy(() => connector);
  const runtime = createConnectedLicenseRuntime({
    ...scope,
    store: db.store,
    connector: proxy,
    now: options.now,
    offlineLicenseText,
    seatsUsed: () => db.seatsUsed(scope.customerId),
    packageVersion: options.packageVersion,
    policyVersion: options.policyVersion,
    catalogVersion: options.catalogVersion,
  });
  connector = connectorFactory({
    ...scope,
    client,
    store: db.store,
    safeSnapshot: runtime.safeHeartbeatSnapshot,
    diagnosticsEnabled: exactEnvBoolean(env.REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED),
    shadowIntelligenceEnabled: exactEnvBoolean(
      env.REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED,
    ),
    heartbeatIntervalMs: env.REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS,
    now: options.now,
    offlineLicenseText,
  });
  return runtime;
}

function connectedLicenseMode(env = process.env) {
  const explicit = String(env.REDACTWALL_LICENSE_MODE || '').trim().toLowerCase();
  return explicit ? explicit === 'connected' : Boolean(env.REDACTWALL_LICENSE_SERVER_URL);
}

function onlineVerdictKeys(env) {
  const current = connectedConfig.connectedPublicKey(
    env, 'REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY', 'REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64',
  );
  if (!current) throw runtimeError('CONNECTED_REGISTRY_KEY_REQUIRED');
  const keyring = new Map([[onlineVerdict.keyIdForPublicKey(current), current]]);
  const next = connectedConfig.connectedPublicKey(
    env,
    'REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY',
    'REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64',
  );
  if (next) keyring.set(onlineVerdict.keyIdForPublicKey(next), next);
  if (keyring.size > 2 || (next && keyring.size !== 2)) {
    throw runtimeError('CONNECTED_REGISTRY_KEY_ID_DUPLICATE');
  }
  return keyring;
}

function clientOptions(env, scope, verification, onlineKeys, options) {
  const tokens = {
    heartbeat: env.REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN,
    acknowledgement: env.REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN,
  };
  if (env.REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN) {
    tokens.diagnostic = env.REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN;
  }
  if (env.REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN) {
    tokens.shadowCandidate = env.REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN;
  }
  return {
    baseUrl: env.REDACTWALL_LICENSE_SERVER_URL,
    tokens,
    ...scope,
    timeoutMs: optionalInteger(env.REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS),
    onlineVerdictPublicKeys: onlineKeys,
    entitlementPublicKeys: verification.publicKeys,
    offlineKeyFingerprint: verification.offlineKeyFingerprint,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.now ? { now: options.now } : {}),
  };
}

function connectedDb(value) {
  const store = checkedMethods(value, [
    'applyConnectedHeartbeatResponse', 'recordConnectedEntitlementFailure',
    'connectedHeartbeatState', 'connectedLicensingDisposition',
    'pendingConnectedAcknowledgements', 'connectedAcknowledgementHealth',
    'recordConnectedAcknowledgementResult',
  ], 'database');
  if (!value || typeof value.seatStats !== 'function') {
    throw new TypeError('connected runtime database is invalid');
  }
  return Object.freeze({
    store: Object.freeze({
      applyHeartbeatResponse: store.applyConnectedHeartbeatResponse,
      recordFailure: store.recordConnectedEntitlementFailure,
      getState: store.connectedHeartbeatState,
      disposition: store.connectedLicensingDisposition,
      listPendingAcknowledgements: store.pendingConnectedAcknowledgements,
      acknowledgementHealth: store.connectedAcknowledgementHealth,
      recordAckResult: store.recordConnectedAcknowledgementResult,
    }),
    seatsUsed: (customerId) => checkedSeatCount(Reflect.apply(
      value.seatStats, undefined, [{ orgId: customerId }],
    )),
  });
}

function checkedSeatCount(value) {
  return checkedSeatNumber(value?.seatsUsed);
}

function offlineReader(options) {
  if (options.offlineLicenseText !== undefined) {
    return receiverless(options.offlineLicenseText, null, 'offlineLicenseText');
  }
  const license = options.license;
  if (!license || typeof license.licensePath !== 'function'
      || typeof license.readTrustedLicenseText !== 'function') {
    throw new TypeError('connected runtime offline fallback reader is invalid');
  }
  return () => {
    try {
      return Reflect.apply(license.readTrustedLicenseText, undefined, [
        Reflect.apply(license.licensePath, undefined, []),
      ]);
    } catch { return null; }
  };
}

function connectorProxy(current) {
  const call = (method, args) => {
    const connector = current();
    if (!connector || typeof connector[method] !== 'function') {
      throw new TypeError('connected runtime connector initialization failed');
    }
    return Reflect.apply(connector[method], undefined, args);
  };
  return Object.freeze(Object.fromEntries([
    'start', 'stop', 'synchronize', 'readiness', 'sendDiagnostic', 'sendShadowCandidate',
  ].map((method) => [method, (...args) => call(method, args)])));
}

function exactEnvBoolean(value) {
  if (value === true || value === 'true') return true;
  if (value === false || value === 'false') return false;
  throw new TypeError('connected runtime consent is invalid');
}

function optionalInteger(value) {
  if (value === undefined || value === null || value === '') return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) throw new TypeError('connected runtime timeout is invalid');
  return parsed;
}

function runtimeError(code) {
  const error = new Error('connected runtime configuration is invalid');
  error.code = code;
  return error;
}

function checkedOptions(options) {
  const customerId = options.customerId;
  const deploymentId = options.deploymentId;
  if (typeof customerId !== 'string' || !CUSTOMER_ID_RE.test(customerId)
      || !isDeploymentId(deploymentId)) throw new TypeError('connected runtime scope is invalid');
  const store = checkedMethods(options.store, ['getState', 'disposition'], 'store');
  const connector = checkedMethods(options.connector, [
    'start', 'stop', 'synchronize', 'readiness', 'sendDiagnostic', 'sendShadowCandidate',
  ], 'connector');
  return Object.freeze({
    customerId,
    deploymentId,
    store,
    connector,
    now: receiverless(options.now, Date.now, 'now'),
    offlineLicenseText: receiverless(options.offlineLicenseText, () => null, 'offlineLicenseText'),
    seatsUsed: receiverless(options.seatsUsed, () => 0, 'seatsUsed'),
    policyVersion: receiverless(options.policyVersion, () => 0, 'policyVersion'),
    catalogVersion: receiverless(options.catalogVersion, () => 0, 'catalogVersion'),
    packageVersion: checkedVersion(options.packageVersion),
  });
}

function checkedMethods(value, methods, label) {
  if (!value || methods.some((name) => typeof value[name] !== 'function')) {
    throw new TypeError(`connected runtime ${label} is invalid`);
  }
  return Object.freeze(Object.fromEntries(
    methods.map((name) => [name, (...args) => Reflect.apply(value[name], undefined, args)]),
  ));
}

function currentDisposition(ctx) {
  try {
    return normalizedDisposition(ctx.store.disposition(
      ctx.customerId,
      ctx.deploymentId,
      { nowMs: checkedNonnegativeInteger(ctx.now()), offlineLicenseText: ctx.offlineLicenseText() },
    ));
  } catch { return blockedDisposition(); }
}

function normalizedDisposition(value) {
  if (!plainRecord(value) || !Object.hasOwn(value, 'authority')) return blockedDisposition();
  if (Object.hasOwn(value, 'initialAcknowledgementRequired')
      && typeof value.initialAcknowledgementRequired !== 'boolean') return blockedDisposition();
  const authority = normalizedAuthority(value.authority);
  if (value.authority !== null && !authority) return blockedDisposition();
  const fallbackDeadline = normalizedDeadline(value.fallbackDeadline);
  if (Object.hasOwn(value, 'fallbackDeadline') && value.fallbackDeadline !== null
      && !fallbackDeadline) return blockedDisposition();
  if (!validDispositionPair(value, authority, fallbackDeadline)) return blockedDisposition();
  const normalized = {
    protectedEgress: value.protectedEgress,
    mode: value.mode,
    reason: value.reason,
    authority,
    ...(value.initialAcknowledgementRequired === true
      ? { initialAcknowledgementRequired: true } : {}),
  };
  if (Object.hasOwn(value, 'fallbackDeadline')) normalized.fallbackDeadline = fallbackDeadline;
  return Object.freeze(normalized);
}

function validDispositionPair(value, authority, fallbackDeadline) {
  if (value.protectedEgress === 'allow') {
    if (!authority || !fallbackDeadline) return false;
    if (value.mode === 'connected') return value.reason === null;
    return value.mode === 'degraded_fallback' && value.reason === 'vendor_unreachable';
  }
  if (value.protectedEgress !== 'block' || !REASON_RE.test(String(value.reason || ''))) return false;
  if (value.mode === 'paused') return value.reason === 'vendor_paused';
  if (value.mode === 'revoked') {
    return ['vendor_revoked', 'vendor_registry_revoked'].includes(value.reason);
  }
  return value.mode === 'blocked'
    && !['vendor_paused', 'vendor_revoked', 'vendor_registry_revoked'].includes(value.reason);
}

function normalizedDeadline(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string' || !ISO_MILLISECOND_UTC_RE.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? value : null;
}

function blockedDisposition() {
  return Object.freeze({
    protectedEgress: 'block', mode: 'blocked', reason: 'connected_state_invalid', authority: null,
  });
}

function normalizedAuthority(value) {
  if (!plainRecord(value) || !['standard', 'enterprise'].includes(value.plan)
      || !Number.isSafeInteger(value.seats) || value.seats < 0 || value.seats > MAX_SEATS
      || !Array.isArray(value.features) || value.features.length > 128) return null;
  if (value.features.some((item) => typeof item !== 'string' || !FEATURE_RE.test(item))
      || new Set(value.features).size !== value.features.length) return null;
  return Object.freeze({ plan: value.plan, seats: value.seats, features: Object.freeze([...value.features]) });
}

function connectedState(ctx) {
  try {
    const value = ctx.store.getState(ctx.customerId, ctx.deploymentId);
    return plainRecord(value) ? value : null;
  } catch { return null; }
}

function signedAuthority(ctx) {
  const state = connectedState(ctx);
  const entitlement = state?.entitlement?.entitlement;
  const authority = entitlement && normalizedAuthority(entitlement);
  return { state, authority };
}

function featureEnabled(ctx, feature) {
  if (typeof feature !== 'string' || !FEATURE_RE.test(feature)) return false;
  const authority = currentDisposition(ctx).authority;
  return Boolean(authority && authority.features.includes(feature));
}

function seatAuthority(ctx) {
  const authority = currentDisposition(ctx).authority;
  return authority
    ? { configured: true, seatLimit: authority.seats, source: 'connected_entitlement' }
    : { configured: true, seatLimit: 0, source: 'connected_entitlement' };
}

function safeHeartbeatSnapshot(ctx) {
  const { authority } = signedAuthority(ctx);
  return {
    plan: authority?.plan || 'standard',
    seatsUsed: checkedSeatNumber(ctx.seatsUsed()),
    seatLimit: authority?.seats || 0,
    version: ctx.packageVersion,
    lastAppliedPolicyVersion: checkedNonnegativeInteger(ctx.policyVersion()),
    lastAppliedCatalogVersion: checkedNonnegativeInteger(ctx.catalogVersion()),
  };
}

function publicStatus(ctx) {
  const disposition = currentDisposition(ctx);
  const state = connectedState(ctx);
  const authority = disposition.authority;
  const projection = state?.acknowledgedAuthority;
  return {
    state: publicState(disposition),
    connected: true,
    managedExternally: true,
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    plan: authority?.plan || null,
    seats: authority?.seats ?? null,
    features: authority ? [...authority.features] : [],
    entitlementVersion: projection?.acknowledged?.entitlementVersion || 0,
    registryGeneration: projection?.acknowledged?.registryGeneration || 0,
    appliedEntitlementVersion: state?.entitlement?.entitlementVersion || 0,
    appliedRegistryGeneration: state?.registry?.registryGeneration || 0,
    effectivePairDigest: projection?.acknowledged?.pairDigest || null,
    lastContactAt: state?.registry?.lastContactAt || state?.entitlement?.lastContactAt || null,
    fallbackUntil: disposition.fallbackDeadline || null,
    reason: disposition.reason,
  };
}

function publicState(disposition) {
  if (disposition.protectedEgress === 'allow') {
    return disposition.mode === 'degraded_fallback' ? 'degraded_fallback' : 'active';
  }
  if (['paused', 'revoked'].includes(disposition.mode)) return disposition.mode;
  return 'restricted';
}

function readiness(ctx) {
  let connector;
  try { connector = ctx.connector.readiness(); }
  catch { return { ok: false, connected: false, reason: 'connected_state_invalid' }; }
  if (!connector || connector.ok !== true) return connector || {
    ok: false, connected: false, reason: 'connected_state_invalid',
  };
  const disposition = currentDisposition(ctx);
  if (disposition.initialAcknowledgementRequired === true) {
    return {
      ...connector,
      ok: false,
      mode: disposition.mode,
      reason: 'connected_initial_acknowledgement_pending',
      ...(disposition.reason !== 'connected_initial_acknowledgement_pending'
        ? { enforcementReason: disposition.reason } : {}),
    };
  }
  if (disposition.protectedEgress !== 'allow') {
    return { ...connector, ok: false, mode: disposition.mode, reason: disposition.reason };
  }
  return { ...connector, ok: true, mode: disposition.mode, reason: disposition.reason };
}

function serviceReadiness(ctx) {
  const licensing = readiness(ctx);
  const serviceReady = licensing.ok === true
    || (licensing.connected === true && SERVICE_READY_RESTRICTIONS.has(licensing.reason));
  return { ...licensing, serviceReady };
}

function restrictionMiddleware(runtime) {
  return (_req, res, next) => {
    const disposition = runtime.disposition();
    if (disposition.protectedEgress === 'allow') return next();
    return res.status(403).json({
      error: 'license_restricted',
      reason: REASON_RE.test(String(disposition.reason || ''))
        ? disposition.reason : 'connected_state_invalid',
    });
  };
}

function start(ctx, lifecycle) {
  if (lifecycle.stopped) return { ok: false, reason: 'connector_stopped' };
  if (!lifecycle.started) {
    ctx.connector.start();
    lifecycle.started = true;
  }
  return { ok: true };
}

function stop(ctx, lifecycle) {
  if (lifecycle.stopPromise) return lifecycle.stopPromise;
  lifecycle.stopped = true;
  lifecycle.stopPromise = Promise.resolve().then(() => ctx.connector.stop());
  return lifecycle.stopPromise;
}

function synchronize(ctx, lifecycle) {
  if (lifecycle.stopped) return Promise.resolve({ ok: false, reason: 'connector_stopped' });
  return ctx.connector.synchronize();
}

function outbound(ctx, lifecycle, method, value) {
  if (lifecycle.stopped) return Promise.resolve({ ok: false, reason: 'connector_stopped' });
  return ctx.connector[method](value);
}

function checkedVersion(value) {
  if (typeof value !== 'string' || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
    throw new TypeError('connected runtime version is invalid');
  }
  return value;
}

function checkedNonnegativeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError('connected runtime counter is invalid');
  }
  return value;
}

function checkedSeatNumber(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SEATS) {
    throw new TypeError('connected runtime seat count is invalid');
  }
  return value;
}

function receiverless(value, fallback, name) {
  const callback = value === undefined || value === null ? fallback : value;
  if (typeof callback !== 'function') throw new TypeError(`connected runtime ${name} callback is invalid`);
  return (...args) => Reflect.apply(callback, undefined, args);
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

module.exports = Object.freeze({
  connectedLicenseMode,
  createConnectedLicenseRuntime,
  createConnectedLicenseRuntimeFromEnvironment,
});
