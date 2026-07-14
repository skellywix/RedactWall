'use strict';

const { isAuditImmediateTransactionRunner } = require('./storage');

const APPLY_KEYS = Object.freeze(new Set([
  'clock',
  'customerId',
  'deploymentId',
  'nowMs',
  'randomUUID',
  'signedEntitlementArtifact',
  'signedOnlineRegistryVerdict',
]));
const TRANSACTION_COORDINATORS = new WeakSet();

function createConnectedHeartbeatApplyStore(options = {}) {
  const ctx = context(options);
  const health = { failurePersistenceFailed: false };
  const applyTransaction = ctx.driver.transaction((input) => ctx.coordinator.runVerified(
    ctx.verifyAuditState,
    () => applyInTransaction(ctx, input),
  ));
  const acknowledgementTransaction = ctx.driver.transaction((input) => ctx.coordinator.runVerified(
    ctx.verifyAuditState,
    () => acknowledgementInTransaction(ctx, input),
  ));
  const combinedReadTransaction = coordinatedReadTransaction(ctx);
  const requireOperational = () => {
    if (health.failurePersistenceFailed) throw integrityError();
  };
  return Object.freeze({
    applyHeartbeatResponse(input) {
      requireOperational();
      return applyTransaction(input);
    },
    recordFailure(input) {
      requireOperational();
      try { return ctx.entitlementStore.recordFailure(input); }
      catch (error) {
        health.failurePersistenceFailed = true;
        throw error;
      }
    },
    getState(customerId, deploymentId) {
      requireOperational();
      return combinedReadTransaction(() => stateSnapshot(ctx, customerId, deploymentId));
    },
    entitlementVersion: (customerId, deploymentId) => {
      requireOperational();
      const state = ctx.entitlementStore.getState(customerId, deploymentId);
      return state && state.connectedEver ? state.entitlementVersion : 0;
    },
    registryGeneration: (customerId, deploymentId) => {
      requireOperational();
      return ctx.registryStore.registryGeneration(customerId, deploymentId);
    },
    disposition: (customerId, deploymentId, input) => {
      requireOperational();
      return combinedReadTransaction(() => acknowledgedDisposition(
        ctx, customerId, deploymentId, input,
      ));
    },
    listPendingAcknowledgements: (input) => {
      requireOperational();
      return ctx.entitlementStore.listPendingAcknowledgements(input);
    },
    acknowledgementHealth: (customerId, deploymentId) => {
      requireOperational();
      return ctx.entitlementStore.acknowledgementHealth(customerId, deploymentId);
    },
    recordAckResult: (input) => {
      requireOperational();
      return acknowledgementTransaction(input);
    },
  });
}

function coordinatedReadTransaction(ctx) {
  const transaction = ctx.driver.transaction((callback) => {
    if (typeof callback !== 'function') throw integrityError();
    if (typeof ctx.driver.lockAuditAppend === 'function') ctx.driver.lockAuditAppend();
    return ctx.coordinator.runVerified(ctx.verifyAuditState, callback);
  });
  if (typeof transaction !== 'function') {
    throw new TypeError('connected heartbeat read transaction is required');
  }
  if (typeof ctx.driver.lockAuditAppend === 'function'
      || isAuditImmediateTransactionRunner(transaction)) {
    return receiverless(transaction);
  }
  if (typeof transaction.immediate === 'function') {
    return receiverless(transaction.immediate);
  }
  throw new TypeError('connected heartbeat writer-coordinated read transaction is required');
}

function context(options) {
  const driver = options.driver;
  if (!driver || typeof driver.transaction !== 'function') {
    throw new TypeError('connected heartbeat transaction driver is required');
  }
  const entitlementStore = checkedStore(options.entitlementStore, [
    'applyEntitlement', 'assertExactReplay', 'recordFailure', 'getState', 'disposition',
    'listPendingAcknowledgements', 'acknowledgementHealth', 'recordAckResult',
    'assertAcknowledgementLineages',
  ], 'entitlement');
  const registryStore = checkedStore(options.registryStore, [
    'applyVerdict', 'getState', 'registryGeneration', 'disposition',
  ], 'registry');
  const acknowledgedAuthorityStore = checkedStore(options.acknowledgedAuthorityStore, [
    'stagePair', 'recordAcknowledgementResult', 'getState', 'constrainDisposition',
  ], 'acknowledged authority');
  if (typeof options.verifyAuditState !== 'function') {
    throw new TypeError('connected heartbeat audit verifier is required');
  }
  const coordinator = options.coordinator;
  if (!isConnectedHeartbeatTransactionCoordinator(coordinator)) {
    throw new TypeError('connected heartbeat transaction coordinator is required');
  }
  return Object.freeze({
    driver,
    entitlementStore,
    registryStore,
    acknowledgedAuthorityStore,
    verifyAuditState: receiverless(options.verifyAuditState),
    coordinator,
  });
}

function createConnectedHeartbeatTransactionCoordinator() {
  let auditVerified = false;
  const coordinator = Object.freeze({
    isAuditVerified: () => auditVerified,
    runVerified(verifyAuditState, callback) {
      if (auditVerified || typeof verifyAuditState !== 'function'
          || typeof callback !== 'function') throw integrityError();
      let verification;
      try { verification = verifyAuditState(); }
      catch { throw integrityError(); }
      if (!verification || verification.ok !== true) throw integrityError();
      auditVerified = true;
      try { return callback(); }
      finally { auditVerified = false; }
    },
  });
  TRANSACTION_COORDINATORS.add(coordinator);
  return coordinator;
}

function isConnectedHeartbeatTransactionCoordinator(value) {
  return Boolean(value && TRANSACTION_COORDINATORS.has(value));
}

function applyInTransaction(ctx, input) {
  const parsed = checkedApplyInput(input);
  const registry = ctx.registryStore.applyVerdict({
    customerId: parsed.customerId,
    deploymentId: parsed.deploymentId,
    signedVerdict: parsed.signedOnlineRegistryVerdict,
    nowMs: parsed.nowMs,
  });
  let entitlement = null;
  if (registry.contactAdvanced !== true) {
    if (parsed.signedEntitlementArtifact !== null) {
      entitlement = applyOrReplayEntitlement(ctx, parsed);
    } else {
      ctx.entitlementStore.recordFailure({
        customerId: parsed.customerId,
        deploymentId: parsed.deploymentId,
        failureClass: 'protocol_rejected',
        nowMs: parsed.nowMs,
        preserveTrustedTime: true,
      });
    }
  } else if (parsed.signedEntitlementArtifact === null) {
    ctx.entitlementStore.recordFailure({
      customerId: parsed.customerId,
      deploymentId: parsed.deploymentId,
      failureClass: 'protocol_rejected',
      nowMs: parsed.nowMs,
      preserveTrustedTime: true,
    });
  } else {
    entitlement = ctx.entitlementStore.applyEntitlement({
      customerId: parsed.customerId,
      deploymentId: parsed.deploymentId,
      signedArtifact: parsed.signedEntitlementArtifact,
      nowMs: parsed.nowMs,
      ...(parsed.randomUUID ? { randomUUID: parsed.randomUUID } : {}),
      ...(parsed.clock ? { clock: parsed.clock } : {}),
    });
  }
  let acknowledgedAuthority = null;
  if (entitlement?.outboxes && entitlement?.artifactDigest) {
    acknowledgedAuthority = ctx.acknowledgedAuthorityStore.stagePair({
      customerId: parsed.customerId,
      deploymentId: parsed.deploymentId,
      registryState: registry.state,
      entitlementState: entitlement.state,
      artifactDigest: entitlement.artifactDigest,
      outboxes: entitlement.outboxes,
      nowMs: parsed.nowMs,
    });
  }
  return Object.freeze({
    registry,
    entitlement,
    acknowledgedAuthority,
    entitlementMissing: parsed.signedEntitlementArtifact === null,
    contactAdvanced: registry.contactAdvanced === true,
    applied: registry.contactAdvanced === true
      || parsed.signedEntitlementArtifact === null
      || !!(entitlement && !entitlement.idempotent && !entitlement.capacityRestricted),
  });
}

function applyOrReplayEntitlement(ctx, parsed) {
  try {
    return ctx.entitlementStore.assertExactReplay({
      customerId: parsed.customerId,
      deploymentId: parsed.deploymentId,
      signedArtifact: parsed.signedEntitlementArtifact,
    });
  } catch (error) {
    if (error?.code !== 'connected_response_replay_conflict') throw error;
    return ctx.entitlementStore.applyEntitlement({
      customerId: parsed.customerId,
      deploymentId: parsed.deploymentId,
      signedArtifact: parsed.signedEntitlementArtifact,
      nowMs: parsed.nowMs,
      ...(parsed.randomUUID ? { randomUUID: parsed.randomUUID } : {}),
      ...(parsed.clock ? { clock: parsed.clock } : {}),
    });
  }
}

function stateSnapshot(ctx, customerId, deploymentId) {
  return Object.freeze({
    entitlement: ctx.entitlementStore.getState(customerId, deploymentId),
    registry: ctx.registryStore.getState(customerId, deploymentId),
    acknowledgedAuthority: ctx.acknowledgedAuthorityStore.getState(customerId, deploymentId),
  });
}

function acknowledgementInTransaction(ctx, input) {
  const result = ctx.entitlementStore.recordAckResult(input);
  if (result) ctx.acknowledgedAuthorityStore.recordAcknowledgementResult(input, result);
  return result;
}

function acknowledgedDisposition(ctx, customerId, deploymentId, input = {}) {
  const entitlementState = ctx.entitlementStore.getState(customerId, deploymentId);
  const registryState = ctx.registryStore.getState(customerId, deploymentId);
  const entitlement = ctx.entitlementStore.disposition(customerId, deploymentId, input);
  const currentDisposition = ctx.registryStore.disposition(
    customerId, deploymentId, entitlement,
  );
  return ctx.acknowledgedAuthorityStore.constrainDisposition({
    customerId,
    deploymentId,
    registryState,
    entitlementState,
    currentDisposition,
    nowMs: input.nowMs === undefined ? Date.now() : input.nowMs,
  });
}

function checkedApplyInput(value) {
  if (!plainRecord(value) || Object.keys(value).some((key) => !APPLY_KEYS.has(key))
      || !Object.hasOwn(value, 'customerId')
      || !Object.hasOwn(value, 'deploymentId')
      || !Object.hasOwn(value, 'nowMs')
      || !Object.hasOwn(value, 'signedOnlineRegistryVerdict')
      || !Object.hasOwn(value, 'signedEntitlementArtifact')
      || (value.signedEntitlementArtifact !== null
        && !plainRecord(value.signedEntitlementArtifact))) {
    throw storeError('connected_heartbeat_apply_invalid');
  }
  const nowMs = Number(value.nowMs);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0
      || (value.randomUUID !== undefined && typeof value.randomUUID !== 'function')
      || (value.clock !== undefined && !plainRecord(value.clock))) {
    throw storeError('connected_heartbeat_apply_invalid');
  }
  return { ...value, nowMs };
}

function checkedStore(value, methods, name) {
  if (!value || methods.some((method) => typeof value[method] !== 'function')) {
    throw new TypeError(`connected ${name} store is required`);
  }
  return Object.freeze(Object.fromEntries(
    methods.map((method) => [method, receiverless(value[method])]),
  ));
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function receiverless(callback) {
  return (...args) => Reflect.apply(callback, undefined, args);
}

function storeError(code) {
  const error = new Error('connected heartbeat response rejected');
  error.code = code;
  return error;
}

function integrityError() {
  const error = new Error('connected heartbeat audit state is not healthy');
  error.code = 'CONNECTED_HEARTBEAT_INTEGRITY';
  return error;
}

module.exports = Object.freeze({
  createConnectedHeartbeatApplyStore,
  createConnectedHeartbeatTransactionCoordinator,
  isConnectedHeartbeatTransactionCoordinator,
});
