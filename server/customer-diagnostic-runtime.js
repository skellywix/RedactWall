'use strict';

const crypto = require('node:crypto');
const connectedConfig = require('./connected-license-config');
const { createCustomerDiagnosticOutbox } = require('./customer-diagnostic-outbox');
const {
  createCustomerDiagnosticIntegrityAuthorityFromEnvironment,
} = require('./customer-diagnostic-integrity');

const POLL_BASE_MS = 5_000;
const POLL_MAX_MS = 60 * 60 * 1000;
const POLL_JITTER_MS = 1_000;
const DEFAULT_SENDER_TIMEOUT_MS = 8_000;
const MAX_SENDER_TIMEOUT_MS = 30_000;
const DEFAULT_BATCH_SIZE = 20;
const PRODUCER_ERROR_MESSAGE = 'customer diagnostic producer input rejected';

const CONNECTOR_EVENTS = Object.freeze({
  timeout: Object.freeze({
    component: 'connector', code: 'CONNECTOR_TIMEOUT', severity: 'warning',
    outcome: 'retrying', durationBucket: '5-30s', retryState: 'scheduled',
  }),
  authentication: Object.freeze({
    component: 'connector', code: 'CONNECTOR_AUTH_FAILED', severity: 'error',
    outcome: 'blocked', durationBucket: '<10ms', retryState: 'exhausted',
  }),
  protocol: Object.freeze({
    component: 'connector', code: 'CONNECTOR_PROTOCOL_REJECTED', severity: 'error',
    outcome: 'blocked', durationBucket: '10-100ms', retryState: 'exhausted',
  }),
});
const RECOVERY_EVENTS = Object.freeze({
  connector: Object.freeze({ component: 'connector', code: 'CONNECTOR_TIMEOUT' }),
  entitlement: Object.freeze({ component: 'licensing', code: 'ENTITLEMENT_REJECTED' }),
  queue: Object.freeze({ component: 'connector', code: 'QUEUE_BACKLOG' }),
});
const BACKLOG_BUCKETS = new Set(['21-100', '100+']);

function createCustomerDiagnosticRuntime(options = {}) {
  const consent = checkedConsent(options.consent);
  if (!consent) return disabledRuntime();
  const ctx = checkedContext(options);
  const lifecycle = {
    started: false,
    stopping: false,
    stopped: false,
    timer: null,
    active: null,
    failures: 0,
  };
  const health = { failureCode: null };
  const runtime = {
    status: () => publicStatus(ctx, lifecycle, health),
    readiness: () => Object.freeze({ ok: true, ...publicStatus(ctx, lifecycle, health) }),
    connectorFailure: (kind) => produce(ctx, health, connectorEvent(kind)),
    entitlementRejected: () => produce(ctx, health, entitlementEvent()),
    queueBacklog: (bucket) => produce(ctx, health, backlogEvent(bucket)),
    recovery: (kind) => produce(ctx, health, recoveryEvent(kind)),
    drain: () => drain(ctx, lifecycle, health),
    start: () => start(ctx, lifecycle, health),
    stop: () => stop(ctx, lifecycle),
  };
  return Object.freeze(runtime);
}

function createCustomerDiagnosticRuntimeFromEnvironment(options = {}) {
  const env = options.env || process.env;
  const consent = environmentConsent(env.REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED);
  if (!consent) return createCustomerDiagnosticRuntime({ consent: false });
  const scope = connectedConfig.connectedScopeFromEnv(env, () => {});
  const db = options.db;
  if (!db || typeof db.customerDiagnosticStorage !== 'function') {
    throw runtimeError('diagnostic_storage_unavailable');
  }
  return createCustomerDiagnosticRuntime({
    consent: true,
    ...scope,
    storage: db.customerDiagnosticStorage(),
    integrityAuthority: createCustomerDiagnosticIntegrityAuthorityFromEnvironment(env),
    componentVersion: options.componentVersion,
    ...(typeof options.sender === 'function' ? { sender: options.sender } : {}),
    ...(options.clock ? { clock: options.clock } : {}),
    ...(options.setTimeout ? { setTimeout: options.setTimeout } : {}),
    ...(options.clearTimeout ? { clearTimeout: options.clearTimeout } : {}),
    ...(options.random ? { random: options.random } : {}),
    ...(options.randomUUID ? { randomUUID: options.randomUUID } : {}),
  });
}

function checkedContext(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw runtimeError('diagnostic_configuration_invalid');
  }
  const outbox = createCustomerDiagnosticOutbox({
    customerId: options.customerId,
    deploymentId: options.deploymentId,
    storage: options.storage,
    integrityAuthority: options.integrityAuthority,
    clock: receiverless(options.clock, Date.now, 'clock'),
    randomUUID: receiverless(options.randomUUID, crypto.randomUUID, 'randomUUID'),
  });
  return Object.freeze({
    outbox,
    customerId: options.customerId,
    deploymentId: options.deploymentId,
    componentVersion: checkedVersion(options.componentVersion),
    sender: options.sender === undefined ? null : receiverless(options.sender, null, 'sender'),
    clock: receiverless(options.clock, Date.now, 'clock'),
    randomUUID: receiverless(options.randomUUID, crypto.randomUUID, 'randomUUID'),
    random: receiverless(options.random, Math.random, 'random'),
    setTimeout: receiverless(options.setTimeout, setTimeout, 'setTimeout'),
    clearTimeout: receiverless(options.clearTimeout, clearTimeout, 'clearTimeout'),
    senderTimeoutMs: boundedInteger(
      options.senderTimeoutMs, DEFAULT_SENDER_TIMEOUT_MS, 1, MAX_SENDER_TIMEOUT_MS,
    ),
    batchSize: boundedInteger(options.batchSize, DEFAULT_BATCH_SIZE, 1, 100),
  });
}

function disabledRuntime() {
  const disposition = Object.freeze({ accepted: false, reason: 'diagnostic_consent_required' });
  const status = Object.freeze({
    enabled: false,
    state: 'disabled',
    queued: 0,
    degraded: false,
    failureCode: null,
    workerRunning: false,
  });
  return Object.freeze({
    status: () => status,
    readiness: () => Object.freeze({ ok: true, ...status }),
    connectorFailure: () => disposition,
    entitlementRejected: () => disposition,
    queueBacklog: () => disposition,
    recovery: () => disposition,
    drain: async () => Object.freeze({ ok: true, enabled: false, processed: 0 }),
    start: () => Object.freeze({ ok: true, enabled: false }),
    stop: async () => Object.freeze({ ok: true, enabled: false }),
  });
}

function produce(ctx, health, template) {
  const nowMs = checkedNow(ctx.clock);
  const event = Object.freeze({
    schemaVersion: 1,
    messageId: checkedUuid(ctx.randomUUID),
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    kind: 'diagnostic.event.v1',
    correlationId: checkedUuid(ctx.randomUUID),
    ...template,
    sizeBucket: 'none',
    componentVersion: ctx.componentVersion,
    occurredAt: new Date(nowMs).toISOString(),
  });
  try {
    const accepted = ctx.outbox.enqueue(event);
    health.failureCode = null;
    return accepted;
  } catch (error) {
    health.failureCode = normalizedFailure(error, 'diagnostic_enqueue_failed');
    throw error;
  }
}

function connectorEvent(value) {
  const kind = closedEnum(value, Object.keys(CONNECTOR_EVENTS));
  return Object.freeze({ ...CONNECTOR_EVENTS[kind], countBucket: '1' });
}

function entitlementEvent() {
  return Object.freeze({
    component: 'licensing', code: 'ENTITLEMENT_REJECTED', severity: 'error',
    outcome: 'blocked', countBucket: '1', durationBucket: '10-100ms',
    retryState: 'exhausted',
  });
}

function backlogEvent(value) {
  const countBucket = closedEnum(value, BACKLOG_BUCKETS);
  return Object.freeze({
    component: 'connector', code: 'QUEUE_BACKLOG', severity: 'warning',
    outcome: 'degraded', countBucket, durationBucket: '<10ms', retryState: 'scheduled',
  });
}

function recoveryEvent(value) {
  const kind = closedEnum(value, Object.keys(RECOVERY_EVENTS));
  return Object.freeze({
    ...RECOVERY_EVENTS[kind], severity: 'info', outcome: 'recovered',
    countBucket: '0', durationBucket: '<10ms', retryState: 'recovered',
  });
}

function start(ctx, lifecycle, health) {
  if (lifecycle.stopped || lifecycle.stopping) {
    return Object.freeze({ ok: false, enabled: true, reason: 'diagnostic_runtime_stopped' });
  }
  if (lifecycle.started) return Object.freeze({ ok: true, enabled: true });
  try {
    ctx.outbox.pendingCount();
    if (health.failureCode === 'diagnostic_storage_failed') health.failureCode = null;
  } catch (error) {
    health.failureCode = normalizedFailure(error, 'diagnostic_storage_failed');
    return Object.freeze({ ok: false, enabled: true, reason: health.failureCode });
  }
  lifecycle.started = true;
  schedule(ctx, lifecycle, health, 0);
  return Object.freeze({ ok: true, enabled: true });
}

async function stop(ctx, lifecycle) {
  if (lifecycle.stopped) return Object.freeze({ ok: true, enabled: true });
  lifecycle.stopping = true;
  if (lifecycle.timer !== null) ctx.clearTimeout(lifecycle.timer);
  lifecycle.timer = null;
  const active = lifecycle.active;
  if (active) await active;
  lifecycle.started = false;
  lifecycle.stopped = true;
  lifecycle.stopping = false;
  return Object.freeze({ ok: true, enabled: true });
}

function drain(ctx, lifecycle, health) {
  if (lifecycle.stopped || lifecycle.stopping) {
    return Promise.resolve(Object.freeze({
      ok: false, enabled: true, processed: 0, reason: 'diagnostic_runtime_stopped',
    }));
  }
  if (lifecycle.active) return lifecycle.active;
  const operation = executeDrain(ctx, health).finally(() => {
    if (lifecycle.active === operation) lifecycle.active = null;
  });
  lifecycle.active = operation;
  return operation;
}

async function executeDrain(ctx, health) {
  if (!ctx.sender) {
    health.failureCode = 'diagnostic_delivery_contract_unavailable';
    return Object.freeze({
      ok: false, enabled: true, processed: 0,
      reason: 'diagnostic_delivery_contract_unavailable',
    });
  }
  let leases;
  try { leases = ctx.outbox.leaseReady({ limit: ctx.batchSize }); }
  catch (error) { return drainFailure(health, error, 0); }
  let accepted = 0;
  for (const lease of leases) {
    const success = await deliverOne(ctx, health, lease);
    if (success) accepted += 1;
  }
  if (accepted === leases.length) health.failureCode = null;
  return Object.freeze({
    ok: accepted === leases.length,
    enabled: true,
    processed: leases.length,
    accepted,
    ...(accepted === leases.length ? {} : { reason: health.failureCode }),
  });
}

async function deliverOne(ctx, health, lease) {
  let accepted = false;
  try {
    // The injected adapter may return literal true only after it independently
    // proves an exact durable 204 acceptance. The connected client retains a
    // structured outcome, and the application adapter converts only its
    // verified exact-204 success to this literal boundary.
    accepted = await sendWithDeadline(ctx, lease.event) === true;
  } catch { accepted = false; }
  try {
    const recorded = ctx.outbox.recordDelivery({
      messageId: lease.messageId,
      payloadDigest: lease.payloadDigest,
      leaseId: lease.leaseId,
      accepted,
    });
    if (recorded && recorded.delivered === true) return true;
    health.failureCode = 'diagnostic_delivery_rejected';
    return false;
  } catch (error) {
    health.failureCode = normalizedFailure(error, 'diagnostic_delivery_failed');
    return false;
  }
}

async function sendWithDeadline(ctx, event) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = ctx.setTimeout(() => resolve(false), ctx.senderTimeoutMs);
    if (timer && typeof timer.unref === 'function') timer.unref();
  });
  try { return await Promise.race([Promise.resolve(ctx.sender(event)), timeout]); }
  finally { if (timer !== undefined) ctx.clearTimeout(timer); }
}

function drainFailure(health, error, processed) {
  health.failureCode = normalizedFailure(error, 'diagnostic_storage_failed');
  return Object.freeze({
    ok: false, enabled: true, processed, reason: health.failureCode,
  });
}

function schedule(ctx, lifecycle, health, delay) {
  if (lifecycle.stopping || lifecycle.stopped || !lifecycle.started) return;
  lifecycle.timer = ctx.setTimeout(async () => {
    lifecycle.timer = null;
    const result = await drain(ctx, lifecycle, health);
    lifecycle.failures = result.ok ? 0 : Math.min(10, lifecycle.failures + 1);
    schedule(ctx, lifecycle, health, retryDelay(ctx, lifecycle.failures));
  }, delay);
  if (lifecycle.timer && typeof lifecycle.timer.unref === 'function') lifecycle.timer.unref();
}

function retryDelay(ctx, failures) {
  const base = Math.min(POLL_MAX_MS, POLL_BASE_MS * (2 ** Math.max(0, failures - 1)));
  let random;
  try { random = ctx.random(); }
  catch { random = 0; }
  if (typeof random !== 'number' || !Number.isFinite(random) || random < 0 || random >= 1) random = 0;
  return Math.min(POLL_MAX_MS, base + Math.floor(random * (POLL_JITTER_MS + 1)));
}

function publicStatus(ctx, lifecycle, health) {
  let queued = null;
  try { queued = ctx.outbox.pendingCount(); }
  catch { health.failureCode = 'diagnostic_storage_failed'; }
  const degraded = health.failureCode !== null;
  return Object.freeze({
    enabled: true,
    state: degraded ? 'degraded' : 'healthy',
    queued,
    degraded,
    failureCode: health.failureCode,
    workerRunning: lifecycle.started && !lifecycle.stopping && !lifecycle.stopped,
  });
}

function environmentConsent(value) {
  if (value === undefined || value === null || value === '' || value === false || value === 'false') {
    return false;
  }
  if (value === true || value === 'true') return true;
  throw runtimeError('diagnostic_consent_invalid');
}

function checkedConsent(value) {
  if (value === true) return true;
  if (value === false) return false;
  throw runtimeError('diagnostic_consent_invalid');
}

function checkedVersion(value) {
  if (typeof value !== 'string'
      || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/.test(value)) {
    throw runtimeError('diagnostic_component_version_invalid');
  }
  return value;
}

function checkedNow(clock) {
  let value;
  try { value = clock(); }
  catch { throw runtimeError('diagnostic_time_invalid'); }
  if (!Number.isSafeInteger(value) || value < 0 || value > 8_640_000_000_000_000) {
    throw runtimeError('diagnostic_time_invalid');
  }
  return value;
}

function checkedUuid(randomUUID) {
  let value;
  try { value = randomUUID(); }
  catch { throw runtimeError('diagnostic_random_invalid'); }
  if (typeof value !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw runtimeError('diagnostic_random_invalid');
  }
  return value;
}

function closedEnum(value, allowed) {
  const set = allowed instanceof Set ? allowed : new Set(allowed);
  if (typeof value !== 'string' || !set.has(value)) throw producerError();
  return value;
}

function boundedInteger(value, fallback, min, max) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw runtimeError('diagnostic_configuration_invalid');
  }
  return value;
}

function receiverless(value, fallback, label) {
  const candidate = value === undefined ? fallback : value;
  if (typeof candidate !== 'function') throw runtimeError(`diagnostic_${label}_invalid`);
  return (...args) => Reflect.apply(candidate, undefined, args);
}

function normalizedFailure(error, fallback) {
  const code = String(error && error.code || '');
  return /^[a-z][a-z0-9_]{0,79}$/.test(code) ? code : fallback;
}

function producerError() {
  const error = new Error(PRODUCER_ERROR_MESSAGE);
  error.code = 'diagnostic_producer_input_invalid';
  return error;
}

function runtimeError(code) {
  const error = new Error('customer diagnostic runtime configuration rejected');
  error.code = code;
  return error;
}

module.exports = {
  createCustomerDiagnosticRuntime,
  createCustomerDiagnosticRuntimeFromEnvironment,
  POLL_BASE_MS,
  POLL_MAX_MS,
};
