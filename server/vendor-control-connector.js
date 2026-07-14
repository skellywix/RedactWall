'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isAuditCommitUncertainError } = require('./storage');

const SNAPSHOT_KEYS = Object.freeze([
  'lastAppliedCatalogVersion',
  'lastAppliedPolicyVersion',
  'plan',
  'seatLimit',
  'seatsUsed',
  'version',
]);
const MAX_ACK_BATCH = 20;
const MAX_RETRY_ATTEMPT = 8;
const RETRYABLE_ACK_FAILURES = Object.freeze(new Set([
  'transport_unavailable', 'transport_ambiguous', 'rate_limited',
]));

function createVendorControlConnector(options = {}) {
  const localHealth = Object.seal({
    failurePersistenceFailed: false,
    ackPersistenceFailed: false,
    ackTerminalFailure: null,
  });
  const lifecycle = Object.seal({ stopping: false });
  const ctx = checkedOptions(options, localHealth, lifecycle);
  let running = false;
  let stopped = true;
  let timer = null;
  let failures = 0;
  let activeSynchronization = null;

  async function synchronize() {
    if (lifecycle.stopping) return { ok: false, reason: 'connector_stopped' };
    if (running) return { ok: false, reason: 'synchronization_in_progress' };
    if (localHealth.failurePersistenceFailed) {
      return { ok: false, reason: 'state_corrupt' };
    }
    running = true;
    let settle;
    activeSynchronization = new Promise((resolve) => { settle = resolve; });
    try {
      const first = await heartbeatOnce(ctx);
      if (first.reason === 'connector_stopped') return first;
      if (!first.ok) {
        failures = Math.min(MAX_RETRY_ATTEMPT, failures + 1);
        // A protocol/version failure must not strand older authenticated ACKs.
        // True audit/state corruption remains frozen because neither the
        // outbox nor its anchors are safe to mutate in that condition.
        if (first.reason !== 'state_corrupt') {
          const failureDrain = await drainAcknowledgementPasses(ctx);
          if (!failureDrain.ok) return failureDrain.result;
        }
        return first;
      }
      failures = 0;
      let applied = first.applied;
      const firstDrain = await drainAcknowledgementPasses(ctx);
      if (!firstDrain.ok) {
        return firstDrain.result;
      }
      if (first.applied) {
        const confirmation = await heartbeatOnce(ctx);
        if (!confirmation.ok) return confirmation;
        applied = applied || confirmation.applied;
        const confirmationDrain = await drainAcknowledgementPasses(ctx);
        if (!confirmationDrain.ok) {
          return confirmationDrain.result;
        }
      }
      const highWaters = appliedHighWaters(ctx);
      return {
        ok: true,
        applied,
        ...highWaters,
      };
    } finally {
      running = false;
      settle();
      activeSynchronization = null;
    }
  }

  async function scheduledTick() {
    if (stopped) return;
    try { await synchronize(); }
    catch { failures = Math.min(MAX_RETRY_ATTEMPT, failures + 1); }
    finally {
      if (!stopped) timer = ctx.setTimeout(scheduledTick, retryDelayMs(ctx, failures));
    }
  }

  return Object.freeze({
    synchronize,
    start() {
      if (!stopped) return;
      stopped = false;
      timer = ctx.setTimeout(scheduledTick, 0);
    },
    async stop() {
      stopped = true;
      lifecycle.stopping = true;
      if (timer !== null) ctx.clearTimeout(timer);
      timer = null;
      const pending = activeSynchronization;
      let closeFailed = false;
      try { await ctx.client.close(); } catch { closeFailed = true; }
      if (pending) await pending;
      return closeFailed
        ? { ok: false, reason: 'connector_stop_failed' }
        : { ok: true };
    },
    readiness: () => readiness(ctx),
    sendDiagnostic: (value) => consentedOutbound(
      ctx, 'diagnosticsEnabled', 'sendDiagnostic', value, protocol.CHANNEL_KINDS.DIAGNOSTIC,
    ),
    sendShadowCandidate: (value) => consentedOutbound(
      ctx, 'shadowIntelligenceEnabled', 'sendShadowCandidate', value,
      protocol.CHANNEL_KINDS.SHADOW_CANDIDATE,
    ),
  });
}

function checkedOptions(options, localHealth, lifecycle) {
  if (!options.client || typeof options.client.heartbeat !== 'function'
      || typeof options.client.acknowledge !== 'function'
      || typeof options.client.close !== 'function') throw new TypeError('vendor client is required');
  const store = options.store;
  for (const name of [
    'applyHeartbeatResponse', 'recordFailure', 'getState', 'disposition',
    'listPendingAcknowledgements', 'acknowledgementHealth', 'recordAckResult',
  ]) {
    if (!store || typeof store[name] !== 'function') throw new TypeError(`connected store ${name} is required`);
  }
  if (typeof options.safeSnapshot !== 'function') throw new TypeError('safeSnapshot is required');
  if (options.diagnosticsEnabled !== true && options.diagnosticsEnabled !== false) {
    throw connectorError('diagnostic_consent_required');
  }
  if (options.shadowIntelligenceEnabled !== true && options.shadowIntelligenceEnabled !== false) {
    throw connectorError('shadow_ai_consent_required');
  }
  const identity = checkedIdentity(options.customerId, options.deploymentId);
  return Object.freeze({
    ...identity,
    client: options.client,
    store,
    safeSnapshot: receiverless(options.safeSnapshot, null, 'safeSnapshot'),
    diagnosticsEnabled: options.diagnosticsEnabled,
    shadowIntelligenceEnabled: options.shadowIntelligenceEnabled,
    heartbeatIntervalMs: protocol.heartbeatIntervalMs(options.heartbeatIntervalMs),
    now: receiverless(options.now, Date.now, 'now'),
    randomUUID: receiverless(options.randomUUID, crypto.randomUUID, 'randomUUID'),
    randomBytes: receiverless(options.randomBytes, crypto.randomBytes, 'randomBytes'),
    random: receiverless(options.random, Math.random, 'random'),
    offlineLicenseText: receiverless(options.offlineLicenseText, () => null, 'offlineLicenseText'),
    setTimeout: receiverless(options.setTimeout, setTimeout, 'setTimeout'),
    clearTimeout: receiverless(options.clearTimeout, clearTimeout, 'clearTimeout'),
    localHealth,
    lifecycle,
  });
}

function consentedOutbound(ctx, consentField, method, value, kind) {
  const code = consentField === 'diagnosticsEnabled'
    ? 'diagnostic_consent_required' : 'shadow_ai_consent_required';
  if (ctx[consentField] !== true) throw connectorError(code);
  return outbound(ctx, method, value, kind);
}

async function heartbeatOnce(ctx) {
  const nowMs = checkedNow(ctx.now());
  const previous = ctx.store.getState(ctx.customerId, ctx.deploymentId);
  const heartbeat = buildHeartbeat(ctx, previous, nowMs);
  const result = await ctx.client.heartbeat(heartbeat);
  if (!result || result.ok !== true) {
    if (result?.failureClass === 'shutdown_cancelled' && ctx.lifecycle.stopping) {
      return { ok: false, reason: 'connector_stopped' };
    }
    const failureClass = protocol.FAILURE_CLASSES.includes(result?.failureClass)
      ? result.failureClass : 'protocol_rejected';
    if (!persistFailure(ctx, {
      customerId: ctx.customerId,
      deploymentId: ctx.deploymentId,
      failureClass,
      nowMs,
    })) return { ok: false, reason: 'state_corrupt' };
    return { ok: false, reason: failureClass };
  }
  if (result.requestMessageId !== heartbeat.messageId
      || typeof result.signedOnlineRegistryVerdict !== 'string'
      || !Object.hasOwn(result, 'signedEntitlementArtifact')
      || (result.signedEntitlementArtifact !== null
        && !plainRecord(result.signedEntitlementArtifact))) {
    if (!persistFailure(ctx, {
      customerId: ctx.customerId,
      deploymentId: ctx.deploymentId,
      failureClass: 'invalid_schema',
      nowMs,
    })) return { ok: false, reason: 'state_corrupt' };
    return { ok: false, reason: 'invalid_schema' };
  }
  let applied;
  try {
    applied = ctx.store.applyHeartbeatResponse({
      customerId: ctx.customerId,
      deploymentId: ctx.deploymentId,
      signedOnlineRegistryVerdict: result.signedOnlineRegistryVerdict,
      signedEntitlementArtifact: result.signedEntitlementArtifact,
      nowMs,
      randomUUID: ctx.randomUUID,
    });
  } catch (error) {
    const capacityBlocked = error?.code === 'connected_ack_capacity';
    const failureClass = capacityBlocked ? 'protocol_rejected' : connectedFailureClass(error);
    if (failureClass !== 'state_corrupt') {
      if (!persistFailure(ctx, {
        customerId: ctx.customerId,
        deploymentId: ctx.deploymentId,
        failureClass,
        nowMs,
        preserveTrustedTime: error?.code === 'connected_response_replay_conflict',
      })) return { ok: false, reason: 'state_corrupt' };
    }
    return {
      ok: false,
      reason: capacityBlocked ? 'connected_ack_capacity' : failureClass,
    };
  }
  const highWaters = appliedHighWaters(ctx);
  return {
    ok: true,
    applied: applied.applied,
    ...highWaters,
  };
}

function appliedHighWaters(ctx) {
  const state = ctx.store.getState(ctx.customerId, ctx.deploymentId);
  return {
    entitlementVersion: state?.entitlement?.entitlementVersion || 0,
    registryGeneration: state?.registry?.registryGeneration || 0,
  };
}

function buildHeartbeat(ctx, state, nowMs) {
  const snapshot = checkedSnapshot(ctx.safeSnapshot(), ctx.customerId, ctx.deploymentId);
  return protocol.assertChannel({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: ctx.randomUUID(),
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    kind: protocol.CHANNEL_KINDS.HEARTBEAT,
    heartbeatNonce: ctx.randomBytes(24).toString('base64url'),
    plan: snapshot.plan,
    seatsUsed: snapshot.seatsUsed,
    seatLimit: snapshot.seatLimit,
    version: snapshot.version,
    sentAt: new Date(nowMs).toISOString(),
    lastAppliedEntitlementVersion: state?.entitlement?.entitlementVersion || 0,
    lastAppliedRegistryGeneration: state?.registry?.registryGeneration || 0,
    lastAppliedPolicyVersion: snapshot.lastAppliedPolicyVersion,
    lastAppliedCatalogVersion: snapshot.lastAppliedCatalogVersion,
  }, protocol.CHANNEL_KINDS.HEARTBEAT);
}

function checkedSnapshot(value, customerId, deploymentId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== SNAPSHOT_KEYS.join(',')) {
    throw connectorError('heartbeat_snapshot_invalid');
  }
  const probe = {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    customerId,
    deploymentId,
    kind: protocol.CHANNEL_KINDS.HEARTBEAT,
    heartbeatNonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    sentAt: new Date(0).toISOString(),
    lastAppliedEntitlementVersion: 0,
    lastAppliedRegistryGeneration: 0,
    ...value,
  };
  protocol.assertChannel(probe, protocol.CHANNEL_KINDS.HEARTBEAT);
  return { ...value };
}

async function drainAcknowledgements(ctx) {
  const health = ctx.store.acknowledgementHealth(ctx.customerId, ctx.deploymentId);
  if (!health || (health.ok !== true && health.reason !== 'connected_ack_backlog')) {
    throw terminalAckError(health?.failureClass || 'state_corrupt');
  }
  const pending = ctx.store.listPendingAcknowledgements({
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    nowMs: checkedNow(ctx.now()),
    limit: MAX_ACK_BATCH,
  });
  for (const item of pending) {
    let result;
    try {
      result = await ctx.client.acknowledge(item.acknowledgement);
    } catch (error) {
      result = ctx.lifecycle.stopping && error?.code === 'vendor_client_closed'
        ? { ok: false, failureClass: 'shutdown_cancelled' }
        : { ok: false, failureClass: connectedFailureClass(error) };
    }
    if (result?.failureClass === 'shutdown_cancelled' && ctx.lifecycle.stopping) {
      throw connectorError('connector_stopped');
    }
    const accepted = result?.ok === true && result?.accepted === true;
    const failureClass = accepted
      ? null
      : (protocol.FAILURE_CLASSES.includes(result?.failureClass)
        ? result.failureClass : 'protocol_rejected');
    const recorded = ctx.store.recordAckResult({
      id: item.id,
      customerId: ctx.customerId,
      deploymentId: ctx.deploymentId,
      payloadDigest: item.payloadDigest,
      accepted,
      ...(failureClass ? { failureClass } : {}),
      nowMs: checkedNow(ctx.now()),
    });
    if (!recorded) throw connectorError('ack_result_uncommitted');
    if (failureClass && !RETRYABLE_ACK_FAILURES.has(failureClass)) {
      throw terminalAckError(failureClass);
    }
  }
}

async function drainAcknowledgementsSafely(ctx) {
  try {
    await drainAcknowledgements(ctx);
    return { ok: true };
  } catch (error) {
    if (error?.code === 'connector_stopped' && ctx.lifecycle.stopping) {
      return { ok: false, result: { ok: false, reason: 'connector_stopped' } };
    }
    if (error?.code === 'connected_ack_terminal_failure') {
      ctx.localHealth.ackTerminalFailure = error.failureClass;
      return {
        ok: false,
        result: {
          ok: false,
          reason: 'connected_ack_terminal_failure',
          failureClass: error.failureClass,
        },
      };
    }
    ctx.localHealth.ackPersistenceFailed = true;
    return {
      ok: false,
      result: { ok: false, reason: 'connected_ack_persistence_failed' },
    };
  }
}

async function drainAcknowledgementPasses(ctx, passes = 2) {
  for (let pass = 0; pass < passes; pass += 1) {
    const result = await drainAcknowledgementsSafely(ctx);
    if (!result.ok) return result;
  }
  ctx.localHealth.ackPersistenceFailed = false;
  ctx.localHealth.ackTerminalFailure = null;
  return { ok: true };
}

function readiness(ctx) {
  if (ctx.localHealth.failurePersistenceFailed) {
    return {
      ok: false,
      reason: 'connected_failure_persistence_failed',
      connected: false,
    };
  }
  if (ctx.localHealth.ackPersistenceFailed) {
    return {
      ok: false,
      reason: 'connected_ack_persistence_failed',
      connected: false,
    };
  }
  if (ctx.localHealth.ackTerminalFailure) {
    return {
      ok: false,
      reason: 'connected_ack_terminal_failure',
      failureClass: ctx.localHealth.ackTerminalFailure,
      connected: false,
    };
  }
  try {
    const health = ctx.store.acknowledgementHealth(ctx.customerId, ctx.deploymentId);
    if (!health || health.ok !== true) {
      if (health?.reason === 'connected_ack_backlog') {
        return {
          ok: false,
          reason: 'connected_ack_backlog',
          pendingCount: health.pendingCount,
          connected: true,
        };
      }
      return {
        ok: false,
        reason: 'connected_ack_terminal_failure',
        failureClass: health?.failureClass || 'state_corrupt',
        connected: false,
      };
    }
  } catch {
    return { ok: false, reason: 'connected_state_invalid', connected: false };
  }
  try { return evaluatedReadiness(ctx); }
  catch { return { ok: false, reason: 'connected_state_invalid', connected: false }; }
}

function evaluatedReadiness(ctx) {
  const state = ctx.store.getState(ctx.customerId, ctx.deploymentId);
  if (!state || !state.registry || !state.registry.connectedEver
      || state.registry.registryGeneration < 1) {
    return { ok: false, reason: 'connected_enrollment_required', connected: false };
  }
  if (!state.entitlement || !state.entitlement.connectedEver
      || state.entitlement.entitlementVersion < 1) {
    return {
      ok: false,
      reason: 'connected_entitlement_required',
      connected: true,
      registryGeneration: state.registry.registryGeneration,
    };
  }
  const disposition = ctx.store.disposition(ctx.customerId, ctx.deploymentId, {
    nowMs: checkedNow(ctx.now()),
    offlineLicenseText: ctx.offlineLicenseText(),
  });
  return {
    ok: disposition.mode === 'connected' || disposition.mode === 'degraded_fallback',
    connected: true,
    reason: disposition.reason,
    mode: disposition.mode,
    entitlementVersion: state.entitlement.entitlementVersion,
    registryGeneration: state.registry.registryGeneration,
    lastContactAt: state.registry.lastContactAt,
  };
}

async function outbound(ctx, method, value, kind) {
  const parsed = protocol.assertChannel(value, kind);
  if (parsed.customerId !== ctx.customerId) throw connectorError('customer_mismatch');
  if (parsed.deploymentId !== ctx.deploymentId) throw connectorError('deployment_mismatch');
  return ctx.client[method](parsed);
}

function retryDelayMs(ctx, failures) {
  const attempt = Math.max(0, Math.min(MAX_RETRY_ATTEMPT, failures));
  const base = attempt === 0
    ? ctx.heartbeatIntervalMs
    : Math.min(ctx.heartbeatIntervalMs, 5000 * (2 ** Math.min(attempt - 1, 8)));
  const jitter = 0.9 + Math.max(0, Math.min(1, Number(ctx.random()) || 0)) * 0.2;
  return Math.max(1000, Math.round(base * jitter));
}

function connectedFailureClass(error) {
  if (isAuditCommitUncertainError(error)) return 'state_corrupt';
  const code = String(error?.code || '');
  if (protocol.FAILURE_CLASSES.includes(code)) return code;
  if (['version_gap', 'stale_version', 'connected_response_replay_conflict', 'registry_generation_stale',
    'registry_generation_conflict', 'registry_verdict_replay'].includes(code)) {
    return 'version_conflict';
  }
  if (['registry_signature_invalid', 'invalid_signature'].includes(code)) return 'invalid_signature';
  if (['registry_signing_key_unknown', 'unknown_signing_key'].includes(code)) {
    return 'unknown_signing_key';
  }
  if (['registry_customer_mismatch', 'customer_mismatch'].includes(code)) return 'customer_mismatch';
  if (['registry_deployment_mismatch', 'deployment_mismatch'].includes(code)) {
    return 'deployment_mismatch';
  }
  if (code === 'CONNECTED_HEARTBEAT_INTEGRITY'
      || code === 'CONNECTED_ENTITLEMENT_INTEGRITY'
      || code === 'CONNECTED_REGISTRY_INTEGRITY') return 'state_corrupt';
  return 'protocol_rejected';
}

function checkedIdentity(customerId, deploymentId) {
  if (!/^dep_[a-f0-9]{32}$/.test(String(deploymentId || ''))) {
    throw connectorError('deployment_mismatch');
  }
  const probe = checkedSnapshot({
    plan: 'standard', seatsUsed: 0, seatLimit: 0, version: '0.0.0',
    lastAppliedPolicyVersion: 0, lastAppliedCatalogVersion: 0,
  }, customerId, deploymentId);
  protocol.assertChannel({
    ...probe,
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    customerId,
    deploymentId,
    kind: protocol.CHANNEL_KINDS.HEARTBEAT,
    heartbeatNonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    sentAt: new Date(0).toISOString(),
    lastAppliedEntitlementVersion: 0,
    lastAppliedRegistryGeneration: 0,
  }, protocol.CHANNEL_KINDS.HEARTBEAT);
  return { customerId, deploymentId };
}

function checkedNow(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw connectorError('connector_time_invalid');
  return parsed;
}

function connectorError(code) {
  const error = new Error('vendor connector rejected input');
  error.code = code;
  return error;
}

function terminalAckError(failureClass) {
  const error = connectorError('connected_ack_terminal_failure');
  error.failureClass = protocol.FAILURE_CLASSES.includes(failureClass)
    ? failureClass : 'state_corrupt';
  return error;
}

function persistFailure(ctx, input) {
  try {
    ctx.store.recordFailure(input);
    return true;
  } catch {
    ctx.localHealth.failurePersistenceFailed = true;
    return false;
  }
}

function receiverless(value, fallback, name) {
  const callback = value === undefined || value === null ? fallback : value;
  if (typeof callback !== 'function') {
    throw new TypeError(`vendor connector ${name} callback is required`);
  }
  return (...args) => Reflect.apply(callback, undefined, args);
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

module.exports = {
  createVendorControlConnector,
  retryDelayMs,
  MAX_ACK_BATCH,
};
