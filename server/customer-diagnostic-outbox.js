'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const {
  DEFAULT_QUEUE_LIMIT,
  MAX_QUEUE_LIMIT,
  assertSafeDiagnostic,
} = require('./customer-diagnostic-channel');

const RETRY_BASE_MS = 5_000;
const RETRY_MAX_MS = 60 * 60 * 1000;
const DEFAULT_LEASE_MS = 30_000;
const MIN_LEASE_MS = 5_000;
const MAX_LEASE_MS = 5 * 60 * 1000;
const MAX_DIAGNOSTIC_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_MAX_ATTEMPTS = 8;
const MAX_DELIVERY_ATTEMPTS = 100;
const DEFAULT_TOMBSTONE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const MIN_TOMBSTONE_RETENTION_MS = 5_000;
const MAX_TOMBSTONE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_RECORD_LIMIT = 10_000;
const TOMBSTONE_PURGE_BATCH = 100;
const MAX_ISO_TIME_MS = 8_640_000_000_000_000
  - MAX_TOMBSTONE_RETENTION_MS - MAX_LEASE_MS;

const ROW_STATE_DOMAIN = 'redactwall.customer-diagnostic-row-state.v1';
const TIME_STATE_DOMAIN = 'redactwall.customer-diagnostic-time-high-water.v1';
const AUDIT_ANCHOR_DOMAIN = 'redactwall.customer-diagnostic-audit-anchor.v1';
const OUTBOX_ERROR = Symbol('customer-diagnostic-outbox-error');
const OUTBOX_ERROR_MESSAGE = 'customer diagnostic outbox operation rejected';

const ACTIVE_STATUSES = new Set(['pending', 'leased']);
const TERMINAL_STATUSES = new Set(['delivered', 'expired', 'dead_letter']);
const ROW_KEYS = Object.freeze([
  'customerId', 'deploymentId', 'messageId', 'payloadJson', 'payloadDigest',
  'status', 'stateVersion', 'attempts', 'nextAttemptAt', 'leaseId', 'leaseUntil',
  'settledLeaseId', 'createdAt', 'updatedAt', 'retainUntil',
  'lastAuditAction', 'lastAuditAt', 'stateKeyId', 'stateMac',
  'auditKeyId', 'auditAnchor',
]);
const TIME_KEYS = Object.freeze([
  'customerId', 'deploymentId', 'observedAt', 'stateKeyId', 'stateMac',
]);
const PROOF_KEYS = Object.freeze(['keyId', 'mac']);
const RECEIPT_KEYS = Object.freeze(['messageId', 'payloadDigest', 'leaseId', 'accepted']);
const PURGE_AUDIT_KEYS = Object.freeze([
  'action', 'occurredAt', 'customerId', 'deploymentId', 'messageId',
  'payloadDigest', 'terminalStatus', 'priorStateVersion', 'priorStateKeyId',
  'priorStateMac', 'priorAuditAnchor', 'auditKeyId', 'auditAnchor',
]);
const STORAGE_METHODS = Object.freeze([
  'advanceDiagnosticTimeHighWater', 'appendDiagnosticAudit',
  'compareAndSwapDiagnostic', 'countDiagnosticRecords',
  'countPendingDiagnostics', 'deleteDiagnosticTombstone',
  'insertDiagnostic', 'listExpiredDiagnosticTombstones',
  'listReadyDiagnostics', 'readDiagnostic', 'readDiagnosticTimeHighWater',
  'readLatestDiagnosticAudit',
]);

/*
 * Production storage adapter contract:
 * - transaction(callback) is synchronous, invokes callback exactly once, and
 *   returns the exact callback result object without cloning or substitution.
 * - the transaction is serializable for one customer/deployment scope.
 * - every mutation below is staged atomically, rolls back when callback throws,
 *   and uses the supplied state MAC/audit anchor as its compare-and-swap fence.
 * - appendDiagnosticAudit stages the event in the same transaction and returns
 *   an exact value copy of that event. It must never silently drop an append.
 * - readLatestDiagnosticAudit reads the actual latest append-only event for the
 *   exact message and scope, not a mutable row cache or eventually consistent
 *   projection.
 * - count/list/read methods operate only on the exact supplied scope and never
 *   omit segments or treat storage errors as empty results.
 * The injected integrity authority is customer-local, synchronous, and backed
 * by a secret that is not stored with these rows or reused by another silo.
 */
function createCustomerDiagnosticOutbox(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw outboxError('diagnostic_configuration_invalid');
  }
  const ctx = context(options);
  return Object.freeze({
    enqueue: (candidate, input) => enqueue(ctx, candidate, input),
    leaseReady: (input) => leaseReady(ctx, input),
    recordDelivery: (input) => recordDelivery(ctx, input),
    pendingCount: () => pendingCount(ctx),
  });
}

function context(options) {
  const binding = checkedBinding(options.customerId, options.deploymentId);
  const maxItems = queueLimit(options.maxItems);
  const ctx = Object.freeze({
    ...binding,
    storage: checkedStorage(options.storage),
    authority: checkedAuthority(options.integrityAuthority),
    clock: checkedClock(options.clock),
    randomUUID: checkedRandom(options.randomUUID),
    maxItems,
    maxRecords: recordLimit(options.maxRecords, maxItems),
    maxAttempts: attemptLimit(options.maxAttempts),
    leaseMs: leaseDuration(options.leaseMs),
    eventMaxAgeMs: eventAgeLimit(options.eventMaxAgeMs),
    tombstoneRetentionMs: retentionDuration(options.tombstoneRetentionMs),
  });
  proveStorageContract(ctx.storage);
  return ctx;
}

function enqueue(ctx, candidate, input) {
  assertEmptyInput(input);
  let event;
  try { event = assertSafeDiagnostic(candidate, ctx); }
  catch (error) {
    recordRejectionPreserving(ctx, error);
    throw error;
  }
  const payloadJson = protocol.canonicalJson(event);
  const digest = sha256(payloadJson);
  let rejection = null;
  let outcome;
  try {
    outcome = transact(ctx, (tx) => {
      const nowMs = trustedNow(ctx, tx);
      purgeExpiredTombstones(ctx, tx, nowMs);
      try { assertEventFresh(ctx, event, nowMs); }
      catch (error) {
        rejection = error;
        appendRejectionAudit(ctx, tx, reasonCode(error), nowMs);
        return Object.freeze({ error: error.code });
      }
      return enqueueTransaction(ctx, tx, {
        event, payloadJson, digest, nowMs,
        reject: (error) => { rejection = error; },
      });
    });
  } catch (error) {
    if (rejection) {
      markAuditDisposition(rejection, false);
      throw rejection;
    }
    throw error;
  }
  if (outcome.error) {
    const error = rejection || outboxError(outcome.error);
    markAuditDisposition(error, true);
    throw error;
  }
  return outcome.value;
}

function enqueueTransaction(ctx, tx, input) {
  const existing = tx.readDiagnostic(scopeMessage(ctx, input.event.messageId));
  if (existing) {
    const current = inspectRow(ctx, existing);
    assertCurrentAuditHead(ctx, tx, current.row);
    if (current.row.payloadDigest === input.digest) {
      return Object.freeze({ value: publicEnqueue(current.row, true) });
    }
    return rejectedOutcome(ctx, tx, input, 'diagnostic_idempotency_conflict');
  }
  const pending = checkedCount(tx.countPendingDiagnostics(scope(ctx)));
  const total = checkedCount(tx.countDiagnosticRecords(scope(ctx)));
  if (pending > total) throw outboxError('diagnostic_integrity_failed');
  if (pending >= ctx.maxItems) return rejectedOutcome(ctx, tx, input, 'diagnostic_queue_full');
  if (total >= ctx.maxRecords) return rejectedOutcome(ctx, tx, input, 'diagnostic_history_full');
  assertInsertAuditDisposition(ctx, tx, input.event.messageId);
  const row = pendingRow(ctx, input);
  exactRow(ctx, tx.insertDiagnostic(row), row);
  appendRowAudit(ctx, tx, row);
  return Object.freeze({ value: publicEnqueue(row, false) });
}

function rejectedOutcome(ctx, tx, input, code) {
  const error = outboxError(code);
  input.reject(error);
  appendRejectionAudit(ctx, tx, reasonCode(error), input.nowMs);
  return Object.freeze({ error: code });
}

function leaseReady(ctx, input) {
  const request = checkedLeaseRequest(input);
  return transact(ctx, (tx) => {
    const nowMs = trustedNow(ctx, tx);
    purgeExpiredTombstones(ctx, tx, nowMs);
    return leaseReadyTransaction(ctx, tx, request.limit, nowMs);
  });
}

function leaseReadyTransaction(ctx, tx, limit, nowMs) {
  const values = tx.listReadyDiagnostics({ ...scope(ctx), now: iso(nowMs), limit });
  if (!Array.isArray(values) || values.length > limit) {
    throw outboxError('diagnostic_storage_invalid');
  }
  const leased = [];
  for (const value of values) {
    const current = inspectRow(ctx, value);
    assertCurrentAuditHead(ctx, tx, current.row);
    if (!ready(current.row, nowMs) || !current.event) {
      throw outboxError('diagnostic_integrity_failed');
    }
    if (eventExpired(ctx, current.event, nowMs)) {
      transitionTerminal(ctx, tx, current.row, 'expired', nowMs);
      continue;
    }
    if (current.row.attempts >= ctx.maxAttempts) {
      transitionTerminal(ctx, tx, current.row, 'dead_letter', nowMs);
      continue;
    }
    const next = leasedRow(ctx, current.row, nowMs);
    const changed = compareAndSwap(ctx, tx, current.row, next);
    leased.push(publicLease(changed));
  }
  return Object.freeze(leased);
}

function recordDelivery(ctx, input) {
  let receipt;
  try { receipt = checkedReceipt(input); }
  catch (error) {
    recordRejectionPreserving(ctx, error);
    throw error;
  }
  return transact(ctx, (tx) => {
    const nowMs = trustedNow(ctx, tx);
    purgeExpiredTombstones(ctx, tx, nowMs);
    return deliveryTransaction(ctx, tx, receipt, nowMs);
  });
}

function deliveryTransaction(ctx, tx, receipt, nowMs) {
  const value = tx.readDiagnostic(scopeMessage(ctx, receipt.messageId));
  if (!value) {
    assertAbsentRowAuditDisposition(ctx, tx, receipt.messageId);
    return null;
  }
  const current = inspectRow(ctx, value);
  assertCurrentAuditHead(ctx, tx, current.row);
  if (isExactDeliveredReplay(current.row, receipt)) {
    return Object.freeze({ delivered: true, duplicate: true, attempts: current.row.attempts });
  }
  assertCurrentDelivery(current.row, receipt, nowMs);
  const next = receipt.accepted
    ? terminalRow(ctx, current.row, 'delivered', nowMs)
    : retryOrDeadLetterRow(ctx, current.row, nowMs);
  const changed = compareAndSwap(ctx, tx, current.row, next);
  if (!changed) throw outboxError('diagnostic_delivery_not_current');
  return publicDelivery(changed);
}

function pendingCount(ctx) {
  return transact(ctx, (tx) => {
    const nowMs = trustedNow(ctx, tx);
    purgeExpiredTombstones(ctx, tx, nowMs);
    const pending = checkedCount(tx.countPendingDiagnostics(scope(ctx)));
    const total = checkedCount(tx.countDiagnosticRecords(scope(ctx)));
    if (pending > total) throw outboxError('diagnostic_integrity_failed');
    return pending;
  });
}

function compareAndSwap(ctx, tx, current, next) {
  const changed = tx.compareAndSwapDiagnostic({
    ...scope(ctx),
    messageId: current.messageId,
    expectedStateMac: current.stateMac,
    expectedAuditAnchor: current.auditAnchor,
    expectedStateVersion: current.stateVersion,
    nextRow: next,
  });
  if (!changed) throw outboxError('diagnostic_state_conflict');
  exactRow(ctx, changed, next);
  appendRowAudit(ctx, tx, next);
  return next;
}

function transitionTerminal(ctx, tx, current, status, nowMs) {
  const next = terminalRow(ctx, current, status, nowMs);
  return compareAndSwap(ctx, tx, current, next);
}

function pendingRow(ctx, input) {
  const now = iso(input.nowMs);
  return sealRow(ctx, {
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    messageId: input.event.messageId,
    payloadJson: input.payloadJson,
    payloadDigest: input.digest,
    status: 'pending',
    stateVersion: 1,
    attempts: 0,
    nextAttemptAt: now,
    leaseId: null,
    leaseUntil: null,
    settledLeaseId: null,
    createdAt: now,
    updatedAt: now,
    retainUntil: null,
  }, 'DIAGNOSTIC_QUEUED', input.nowMs);
}

function leasedRow(ctx, current, nowMs) {
  const leaseId = generatedUuid(ctx);
  return resealRow(ctx, current, {
    status: 'leased',
    attempts: current.attempts + 1,
    leaseId,
    leaseUntil: iso(nowMs + ctx.leaseMs),
    settledLeaseId: null,
    updatedAt: iso(nowMs),
    retainUntil: null,
  }, 'DIAGNOSTIC_LEASED', nowMs);
}

function retryOrDeadLetterRow(ctx, current, nowMs) {
  if (current.attempts >= ctx.maxAttempts) {
    return terminalRow(ctx, current, 'dead_letter', nowMs);
  }
  return resealRow(ctx, current, {
    status: 'pending',
    nextAttemptAt: iso(retryAt(nowMs, current.attempts)),
    leaseId: null,
    leaseUntil: null,
    settledLeaseId: null,
    updatedAt: iso(nowMs),
    retainUntil: null,
  }, 'DIAGNOSTIC_RETRY_SCHEDULED', nowMs);
}

function terminalRow(ctx, current, status, nowMs) {
  const action = {
    delivered: 'DIAGNOSTIC_DELIVERED',
    expired: 'DIAGNOSTIC_EXPIRED',
    dead_letter: 'DIAGNOSTIC_DEAD_LETTERED',
  }[status];
  if (!action) throw outboxError('diagnostic_integrity_failed');
  return resealRow(ctx, current, {
    // Only an exact vendor acceptance may compact the delivery payload here.
    // Local expiry and retry exhaustion retain the already-sanitized bytes
    // until the separately audited retention purge removes the exact row.
    payloadJson: status === 'delivered' ? null : current.payloadJson,
    status,
    nextAttemptAt: null,
    leaseId: null,
    leaseUntil: null,
    settledLeaseId: status === 'delivered' || status === 'dead_letter'
      ? current.leaseId : null,
    updatedAt: iso(nowMs),
    retainUntil: iso(nowMs + ctx.tombstoneRetentionMs),
  }, action, nowMs);
}

function resealRow(ctx, current, changes, action, nowMs) {
  const base = unsignedRow(current);
  delete base.lastAuditAction;
  delete base.lastAuditAt;
  return sealRow(ctx, {
    ...base,
    ...changes,
    stateVersion: current.stateVersion + 1,
  }, action, nowMs);
}

function sealRow(ctx, base, action, nowMs) {
  const unsigned = Object.freeze({
    ...base,
    lastAuditAction: action,
    lastAuditAt: iso(nowMs),
  });
  const stateProof = signProof(ctx, ROW_STATE_DOMAIN, unsigned);
  const state = Object.freeze({
    ...unsigned,
    stateKeyId: stateProof.keyId,
    stateMac: stateProof.mac,
  });
  const auditProof = signProof(ctx, AUDIT_ANCHOR_DOMAIN, rowAuditBase(state));
  return Object.freeze({
    ...state,
    auditKeyId: auditProof.keyId,
    auditAnchor: auditProof.mac,
  });
}

function inspectRow(ctx, value) {
  const row = snapshotRecord(value, ROW_KEYS, 'diagnostic_integrity_failed');
  validateRowScopeAndIdentity(ctx, row);
  validateRowShape(row);
  verifyProof(ctx, ROW_STATE_DOMAIN, unsignedRow(row), {
    keyId: row.stateKeyId, mac: row.stateMac,
  });
  verifyProof(ctx, AUDIT_ANCHOR_DOMAIN, rowAuditBase(row), {
    keyId: row.auditKeyId, mac: row.auditAnchor,
  });
  const event = row.payloadJson === null ? null : checkedPayload(ctx, row);
  return Object.freeze({ row: Object.freeze(row), event: event && Object.freeze(event) });
}

function validateRowScopeAndIdentity(ctx, row) {
  if (row.customerId !== ctx.customerId || row.deploymentId !== ctx.deploymentId
      || !uuid(row.messageId) || !sha256Digest(row.payloadDigest)) {
    throw outboxError('diagnostic_integrity_failed');
  }
}

function validateRowShape(row) {
  if (!ACTIVE_STATUSES.has(row.status) && !TERMINAL_STATUSES.has(row.status)) {
    throw outboxError('diagnostic_integrity_failed');
  }
  if (!Number.isSafeInteger(row.attempts) || row.attempts < 0
      || row.attempts > MAX_DELIVERY_ATTEMPTS
      || !Number.isSafeInteger(row.stateVersion) || row.stateVersion < 1
      || !validIso(row.createdAt) || !validIso(row.updatedAt)
      || row.lastAuditAt !== row.updatedAt) {
    throw outboxError('diagnostic_integrity_failed');
  }
  if (!proofFields(row.stateKeyId, row.stateMac)
      || !proofFields(row.auditKeyId, row.auditAnchor)
      || Date.parse(row.createdAt) > Date.parse(row.updatedAt)) {
    throw outboxError('diagnostic_integrity_failed');
  }
  if (ACTIVE_STATUSES.has(row.status)) validateActiveRow(row);
  else validateTerminalRow(row);
}

function validateActiveRow(row) {
  if (typeof row.payloadJson !== 'string'
      || Buffer.byteLength(row.payloadJson, 'utf8') > protocol.MAX_CHANNEL_BYTES[protocol.CHANNEL_KINDS.DIAGNOSTIC]
      || !validIso(row.nextAttemptAt) || row.settledLeaseId !== null
      || row.retainUntil !== null) {
    throw outboxError('diagnostic_integrity_failed');
  }
  if (row.status === 'pending') validatePendingRow(row);
  else validateLeasedRow(row);
}

function validatePendingRow(row) {
  const actionOk = row.attempts === 0
    ? row.lastAuditAction === 'DIAGNOSTIC_QUEUED'
    : row.lastAuditAction === 'DIAGNOSTIC_RETRY_SCHEDULED';
  if (!actionOk || row.leaseId !== null || row.leaseUntil !== null
      || Date.parse(row.nextAttemptAt) < Date.parse(row.updatedAt)) {
    throw outboxError('diagnostic_integrity_failed');
  }
}

function validateLeasedRow(row) {
  if (row.lastAuditAction !== 'DIAGNOSTIC_LEASED' || row.attempts < 1
      || !uuid(row.leaseId) || !validIso(row.leaseUntil)
      || Date.parse(row.nextAttemptAt) > Date.parse(row.updatedAt)
      || Date.parse(row.leaseUntil) <= Date.parse(row.updatedAt)) {
    throw outboxError('diagnostic_integrity_failed');
  }
}

function validateTerminalRow(row) {
  const actions = {
    delivered: 'DIAGNOSTIC_DELIVERED',
    expired: 'DIAGNOSTIC_EXPIRED',
    dead_letter: 'DIAGNOSTIC_DEAD_LETTERED',
  };
  const receiptOk = terminalReceiptValid(row);
  const payloadOk = row.status === 'delivered'
    ? row.payloadJson === null
    : typeof row.payloadJson === 'string'
      && Buffer.byteLength(row.payloadJson, 'utf8')
        <= protocol.MAX_CHANNEL_BYTES[protocol.CHANNEL_KINDS.DIAGNOSTIC];
  if (!payloadOk || row.nextAttemptAt !== null
      || row.leaseId !== null || row.leaseUntil !== null
      || !receiptOk || row.lastAuditAction !== actions[row.status]
      || !validIso(row.retainUntil)
      || Date.parse(row.retainUntil) <= Date.parse(row.updatedAt)) {
    throw outboxError('diagnostic_integrity_failed');
  }
}

function terminalReceiptValid(row) {
  if (row.status === 'expired') return row.settledLeaseId === null;
  if (row.status === 'delivered') return row.attempts >= 1 && uuid(row.settledLeaseId);
  return row.attempts >= 1 && (row.settledLeaseId === null || uuid(row.settledLeaseId));
}

function checkedPayload(ctx, row) {
  let event;
  try { event = assertSafeDiagnostic(JSON.parse(row.payloadJson), ctx); }
  catch { throw outboxError('diagnostic_integrity_failed'); }
  if (event.messageId !== row.messageId || sha256(row.payloadJson) !== row.payloadDigest
      || protocol.canonicalJson(event) !== row.payloadJson) {
    throw outboxError('diagnostic_integrity_failed');
  }
  return event;
}

function exactRow(ctx, value, expected) {
  const inspected = inspectRow(ctx, value);
  if (!canonicalEqual(inspected.row, expected)) {
    throw outboxError('diagnostic_integrity_failed');
  }
  return inspected;
}

function unsignedRow(row) {
  const result = {};
  for (const key of ROW_KEYS) {
    if (!['stateKeyId', 'stateMac', 'auditKeyId', 'auditAnchor'].includes(key)) {
      result[key] = row[key];
    }
  }
  return result;
}

function rowAuditBase(row) {
  return {
    action: row.lastAuditAction,
    occurredAt: row.lastAuditAt,
    customerId: row.customerId,
    deploymentId: row.deploymentId,
    messageId: row.messageId,
    payloadDigest: row.payloadDigest,
    status: row.status,
    stateVersion: row.stateVersion,
    attempts: row.attempts,
    retainUntil: row.retainUntil,
    stateKeyId: row.stateKeyId,
    stateMac: row.stateMac,
  };
}

function rowAuditEvent(row) {
  return Object.freeze({
    ...rowAuditBase(row),
    auditKeyId: row.auditKeyId,
    auditAnchor: row.auditAnchor,
  });
}

function appendRowAudit(ctx, tx, row) {
  verifyProof(ctx, AUDIT_ANCHOR_DOMAIN, rowAuditBase(row), {
    keyId: row.auditKeyId, mac: row.auditAnchor,
  });
  appendAudit(tx, rowAuditEvent(row));
}

function appendRejectionAudit(ctx, tx, code, nowMs) {
  const base = Object.freeze({
    action: 'DIAGNOSTIC_REJECTED',
    occurredAt: iso(nowMs),
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    reasonCode: code,
  });
  appendSignedAudit(ctx, tx, base);
}

function appendPurgeAudit(ctx, tx, row, nowMs) {
  const base = Object.freeze(purgeAuditBase(ctx, row, nowMs));
  appendSignedAudit(ctx, tx, base);
}

function purgeAuditBase(ctx, row, nowMs) {
  return {
    action: 'DIAGNOSTIC_TOMBSTONE_PURGED',
    occurredAt: iso(nowMs),
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    messageId: row.messageId,
    payloadDigest: row.payloadDigest,
    terminalStatus: row.status,
    priorStateVersion: row.stateVersion,
    priorStateKeyId: row.stateKeyId,
    priorStateMac: row.stateMac,
    priorAuditAnchor: row.auditAnchor,
  };
}

function appendSignedAudit(ctx, tx, base) {
  const proof = signProof(ctx, AUDIT_ANCHOR_DOMAIN, base);
  const event = Object.freeze({ ...base, auditKeyId: proof.keyId, auditAnchor: proof.mac });
  appendAudit(tx, event);
}

function appendAudit(tx, event) {
  const accepted = tx.appendDiagnosticAudit(event);
  if (!canonicalEqual(accepted, event)) throw outboxError('diagnostic_integrity_failed');
}

function assertCurrentAuditHead(ctx, tx, row) {
  const value = tx.readLatestDiagnosticAudit(scopeMessage(ctx, row.messageId));
  const expected = rowAuditEvent(row);
  if (!value || !canonicalEqual(value, expected)) {
    throw outboxError('diagnostic_audit_anchor_mismatch');
  }
}

function assertInsertAuditDisposition(ctx, tx, messageId) {
  assertAbsentRowAuditDisposition(ctx, tx, messageId);
}

function assertAbsentRowAuditDisposition(ctx, tx, messageId) {
  const value = tx.readLatestDiagnosticAudit(scopeMessage(ctx, messageId));
  if (value === null || value === undefined) return;
  checkedPurgeAudit(ctx, value, messageId);
}

function checkedPurgeAudit(ctx, value, messageId) {
  const event = snapshotRecord(value, PURGE_AUDIT_KEYS, 'diagnostic_audit_anchor_mismatch');
  const base = {};
  for (const key of PURGE_AUDIT_KEYS) {
    if (key !== 'auditKeyId' && key !== 'auditAnchor') base[key] = event[key];
  }
  if (event.action !== 'DIAGNOSTIC_TOMBSTONE_PURGED'
      || event.customerId !== ctx.customerId || event.deploymentId !== ctx.deploymentId
      || event.messageId !== messageId || !uuid(event.messageId)
      || !sha256Digest(event.payloadDigest) || !TERMINAL_STATUSES.has(event.terminalStatus)
      || !Number.isSafeInteger(event.priorStateVersion) || event.priorStateVersion < 1
      || !proofFields(event.priorStateKeyId, event.priorStateMac)
      || !sha256Digest(event.priorAuditAnchor) || !validIso(event.occurredAt)) {
    throw outboxError('diagnostic_audit_anchor_mismatch');
  }
  verifyProof(ctx, AUDIT_ANCHOR_DOMAIN, base, {
    keyId: event.auditKeyId, mac: event.auditAnchor,
  });
  return Object.freeze(event);
}

function trustedNow(ctx, tx) {
  const wallMs = checkedClockValue(ctx.clock);
  const value = tx.readDiagnosticTimeHighWater(scope(ctx));
  const current = value === null || value === undefined ? null : checkedTimeState(ctx, value);
  const currentMs = current ? Date.parse(current.observedAt) : -1;
  const nowMs = Math.max(wallMs, currentMs);
  if (current && nowMs === currentMs) return nowMs;
  const next = sealTimeState(ctx, nowMs);
  const changed = tx.advanceDiagnosticTimeHighWater({
    ...scope(ctx),
    expectedStateMac: current ? current.stateMac : null,
    expectedObservedAt: current ? current.observedAt : null,
    nextRecord: next,
  });
  if (!changed) throw outboxError('diagnostic_time_conflict');
  exactTimeState(ctx, changed, next);
  return nowMs;
}

function sealTimeState(ctx, nowMs) {
  const unsigned = Object.freeze({
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    observedAt: iso(nowMs),
  });
  const proof = signProof(ctx, TIME_STATE_DOMAIN, unsigned);
  return Object.freeze({ ...unsigned, stateKeyId: proof.keyId, stateMac: proof.mac });
}

function checkedTimeState(ctx, value) {
  const record = snapshotRecord(value, TIME_KEYS, 'diagnostic_time_integrity_failed');
  if (record.customerId !== ctx.customerId || record.deploymentId !== ctx.deploymentId
      || !validIso(record.observedAt) || Date.parse(record.observedAt) > MAX_ISO_TIME_MS
      || !proofFields(record.stateKeyId, record.stateMac)) {
    throw outboxError('diagnostic_time_integrity_failed');
  }
  const unsigned = {
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    observedAt: record.observedAt,
  };
  verifyProof(ctx, TIME_STATE_DOMAIN, unsigned, {
    keyId: record.stateKeyId, mac: record.stateMac,
  });
  return Object.freeze(record);
}

function exactTimeState(ctx, value, expected) {
  const record = checkedTimeState(ctx, value);
  if (!canonicalEqual(record, expected)) throw outboxError('diagnostic_time_integrity_failed');
  return record;
}

function purgeExpiredTombstones(ctx, tx, nowMs) {
  const values = tx.listExpiredDiagnosticTombstones({
    ...scope(ctx), before: iso(nowMs), limit: TOMBSTONE_PURGE_BATCH,
  });
  if (!Array.isArray(values) || values.length > TOMBSTONE_PURGE_BATCH) {
    throw outboxError('diagnostic_storage_invalid');
  }
  for (const value of values) purgeOneTombstone(ctx, tx, value, nowMs);
}

function purgeOneTombstone(ctx, tx, value, nowMs) {
  const current = inspectRow(ctx, value).row;
  assertCurrentAuditHead(ctx, tx, current);
  if (!TERMINAL_STATUSES.has(current.status)
      || Date.parse(current.retainUntil) > nowMs) {
    throw outboxError('diagnostic_integrity_failed');
  }
  const removed = tx.deleteDiagnosticTombstone({
    ...scope(ctx),
    messageId: current.messageId,
    expectedStateMac: current.stateMac,
    expectedAuditAnchor: current.auditAnchor,
    expectedStateVersion: current.stateVersion,
    expectedRetainUntil: current.retainUntil,
  });
  if (!removed) throw outboxError('diagnostic_state_conflict');
  exactRow(ctx, removed, current);
  appendPurgeAudit(ctx, tx, current, nowMs);
}

function recordRejectionPreserving(ctx, error) {
  try {
    transact(ctx, (tx) => {
      const nowMs = trustedNow(ctx, tx);
      appendRejectionAudit(ctx, tx, reasonCode(error), nowMs);
      return true;
    });
    markAuditDisposition(error, true);
  } catch {
    markAuditDisposition(error, false);
  }
}

function markAuditDisposition(error, recorded) {
  try {
    Object.defineProperty(error, 'auditRecorded', {
      value: recorded, configurable: true, enumerable: true, writable: false,
    });
    if (!recorded) Object.defineProperty(error, 'auditFailureCode', {
      value: 'diagnostic_rejection_audit_failed',
      configurable: true, enumerable: true, writable: false,
    });
  } catch { /* Preserve the sanitized original even if it is frozen. */ }
}

function assertCurrentDelivery(row, receipt, nowMs) {
  if (row.status !== 'leased' || row.payloadDigest !== receipt.payloadDigest
      || row.leaseId !== receipt.leaseId
      || nowMs < Date.parse(row.updatedAt) || nowMs >= Date.parse(row.leaseUntil)) {
    throw outboxError('diagnostic_delivery_not_current');
  }
}

function isExactDeliveredReplay(row, receipt) {
  return row.status === 'delivered'
    && row.payloadDigest === receipt.payloadDigest
    && row.settledLeaseId === receipt.leaseId;
}

function publicEnqueue(row, duplicate) {
  return Object.freeze({ accepted: !duplicate, duplicate, digest: row.payloadDigest });
}

function publicLease(row) {
  const inspected = Object.freeze({
    messageId: row.messageId,
    payloadDigest: row.payloadDigest,
    leaseId: row.leaseId,
    leaseUntil: row.leaseUntil,
    attempts: row.attempts,
    event: Object.freeze(JSON.parse(row.payloadJson)),
  });
  return inspected;
}

function publicDelivery(row) {
  return Object.freeze({
    delivered: row.status === 'delivered',
    duplicate: false,
    terminal: TERMINAL_STATUSES.has(row.status),
    terminalStatus: TERMINAL_STATUSES.has(row.status) ? row.status : null,
    attempts: row.attempts,
    nextAttemptAt: row.nextAttemptAt,
  });
}

function ready(row, nowMs) {
  if (row.status === 'pending') return Date.parse(row.nextAttemptAt) <= nowMs;
  return row.status === 'leased' && Date.parse(row.leaseUntil) <= nowMs;
}

function eventExpired(ctx, event, nowMs) {
  return nowMs - Date.parse(event.occurredAt) > ctx.eventMaxAgeMs;
}

function assertEventFresh(ctx, event, nowMs) {
  const occurred = Date.parse(event.occurredAt);
  if (occurred > nowMs + MAX_CLOCK_SKEW_MS || nowMs - occurred > ctx.eventMaxAgeMs) {
    throw outboxError('diagnostic_time_invalid');
  }
}

function transact(ctx, callback) {
  let calls = 0;
  let captured;
  let completed = false;
  let result;
  try {
    result = ctx.storage.transaction((tx) => {
      calls += 1;
      if (calls !== 1) throw outboxError('diagnostic_storage_invalid');
      requireTransaction(tx);
      captured = callback(tx);
      if (thenable(captured)) throw outboxError('diagnostic_storage_invalid');
      completed = true;
      return captured;
    });
  } catch (error) {
    throw normalizedStorageError(error);
  }
  if (calls !== 1 || !completed || thenable(result) || !Object.is(result, captured)) {
    throw outboxError('diagnostic_storage_invalid');
  }
  return result;
}

function proveStorageContract(storage) {
  const token = Object.freeze({ diagnosticStorageContractProbe: true });
  let calls = 0;
  let result;
  try {
    result = storage.transaction((tx) => {
      calls += 1;
      if (calls !== 1) throw outboxError('diagnostic_storage_invalid');
      requireTransaction(tx);
      return token;
    });
  } catch { throw outboxError('diagnostic_storage_invalid'); }
  if (calls !== 1 || thenable(result) || result !== token) {
    throw outboxError('diagnostic_storage_invalid');
  }
}

function requireTransaction(tx) {
  if (!tx || STORAGE_METHODS.some((name) => typeof tx[name] !== 'function')) {
    throw outboxError('diagnostic_storage_invalid');
  }
}

function checkedAuthority(authority) {
  if (!authority || typeof authority.sign !== 'function'
      || typeof authority.verify !== 'function') {
    throw outboxError('diagnostic_configuration_invalid');
  }
  const facade = Object.freeze({
    sign: authority.sign.bind(authority),
    verify: authority.verify.bind(authority),
  });
  const message = `${ROW_STATE_DOMAIN}\0contract-probe`;
  let proof;
  try { proof = checkedProof(facade.sign(message)); }
  catch { throw outboxError('diagnostic_configuration_invalid'); }
  try {
    if (facade.verify(message, proof) !== true
        || facade.verify(`${message}.altered`, proof) !== false) {
      throw outboxError('diagnostic_configuration_invalid');
    }
  } catch { throw outboxError('diagnostic_configuration_invalid'); }
  return facade;
}

function signProof(ctx, domain, value) {
  let proof;
  try { proof = checkedProof(ctx.authority.sign(integrityMessage(domain, value))); }
  catch { throw outboxError('diagnostic_integrity_failed'); }
  verifyProof(ctx, domain, value, proof);
  return proof;
}

function verifyProof(ctx, domain, value, proof) {
  const checked = checkedProof(proof);
  let valid = false;
  try { valid = ctx.authority.verify(integrityMessage(domain, value), checked) === true; }
  catch { valid = false; }
  if (!valid) throw outboxError('diagnostic_integrity_failed');
}

function checkedProof(value) {
  const proof = snapshotRecord(value, PROOF_KEYS, 'diagnostic_integrity_failed');
  if (!keyId(proof.keyId) || !sha256Digest(proof.mac)) {
    throw outboxError('diagnostic_integrity_failed');
  }
  return Object.freeze(proof);
}

function integrityMessage(domain, value) {
  return `${domain}\0${protocol.canonicalJson(value)}`;
}

function checkedReceipt(value) {
  const receipt = snapshotRecord(value, RECEIPT_KEYS, 'diagnostic_delivery_invalid');
  if (!uuid(receipt.messageId) || !sha256Digest(receipt.payloadDigest)
      || !uuid(receipt.leaseId) || typeof receipt.accepted !== 'boolean') {
    throw outboxError('diagnostic_delivery_invalid');
  }
  return Object.freeze(receipt);
}

function checkedLeaseRequest(value) {
  if (value === undefined) return Object.freeze({ limit: 20 });
  const request = snapshotFlexibleRecord(value, ['limit'], 'diagnostic_limit_invalid');
  const parsed = request.limit === undefined ? 20 : request.limit;
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 100) {
    throw outboxError('diagnostic_limit_invalid');
  }
  return Object.freeze({ limit: parsed });
}

function assertEmptyInput(value) {
  if (value === undefined) return;
  snapshotRecord(value, [], 'diagnostic_input_invalid');
}

function snapshotRecord(value, expectedKeys, errorCode) {
  const record = snapshotFlexibleRecord(value, expectedKeys, errorCode);
  if (Object.keys(record).length !== expectedKeys.length) throw outboxError(errorCode);
  return record;
}

function snapshotFlexibleRecord(value, allowedKeys, errorCode) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new Error();
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string' || !allowedKeys.includes(key))) throw new Error();
    const record = {};
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || descriptor.get || descriptor.set) throw new Error();
      record[key] = descriptor.value;
    }
    return record;
  } catch { throw outboxError(errorCode); }
}

function checkedStorage(storage) {
  if (!storage || typeof storage.transaction !== 'function') {
    throw outboxError('diagnostic_storage_invalid');
  }
  return storage;
}

function checkedClock(value) {
  if (value === undefined) return Date.now;
  if (typeof value !== 'function') throw outboxError('diagnostic_configuration_invalid');
  return value;
}

function checkedRandom(value) {
  if (value === undefined) return crypto.randomUUID;
  if (typeof value !== 'function') throw outboxError('diagnostic_configuration_invalid');
  return value;
}

function generatedUuid(ctx) {
  let value;
  try { value = ctx.randomUUID(); }
  catch { throw outboxError('diagnostic_integrity_failed'); }
  if (!uuid(value)) throw outboxError('diagnostic_integrity_failed');
  return value;
}

function checkedClockValue(clock) {
  let value;
  try { value = clock(); }
  catch { throw outboxError('diagnostic_time_invalid'); }
  if (typeof value !== 'number' || !Number.isSafeInteger(value)
      || value < 0 || value > MAX_ISO_TIME_MS) {
    throw outboxError('diagnostic_time_invalid');
  }
  return value;
}

function checkedBinding(customerId, deploymentId) {
  try {
    const probe = {
      schemaVersion: 1, messageId: crypto.randomUUID(), customerId, deploymentId,
      kind: protocol.CHANNEL_KINDS.DIAGNOSTIC, correlationId: crypto.randomUUID(),
      component: 'connector', code: 'CONNECTOR_TIMEOUT', severity: 'warning',
      outcome: 'retrying', countBucket: '1', sizeBucket: 'none', durationBucket: '<10ms',
      retryState: 'scheduled', componentVersion: '0.0.0', occurredAt: new Date(0).toISOString(),
    };
    assertSafeDiagnostic(probe, { customerId, deploymentId });
  } catch { throw outboxError('diagnostic_configuration_invalid'); }
  return { customerId, deploymentId };
}

function queueLimit(value) {
  if (value === undefined) return DEFAULT_QUEUE_LIMIT;
  if (!Number.isInteger(value) || value < 1 || value > MAX_QUEUE_LIMIT) {
    throw outboxError('diagnostic_configuration_invalid');
  }
  return value;
}

function recordLimit(value, maxItems) {
  if (value === undefined) return Math.min(MAX_RECORD_LIMIT, Math.max(256, maxItems * 4));
  if (!Number.isInteger(value) || value < maxItems || value > MAX_RECORD_LIMIT) {
    throw outboxError('diagnostic_configuration_invalid');
  }
  return value;
}

function attemptLimit(value) {
  if (value === undefined) return DEFAULT_MAX_ATTEMPTS;
  if (!Number.isInteger(value) || value < 1 || value > MAX_DELIVERY_ATTEMPTS) {
    throw outboxError('diagnostic_configuration_invalid');
  }
  return value;
}

function leaseDuration(value) {
  if (value === undefined) return DEFAULT_LEASE_MS;
  if (!Number.isInteger(value) || value < MIN_LEASE_MS || value > MAX_LEASE_MS) {
    throw outboxError('diagnostic_configuration_invalid');
  }
  return value;
}

function retentionDuration(value) {
  if (value === undefined) return DEFAULT_TOMBSTONE_RETENTION_MS;
  if (!Number.isInteger(value) || value < MIN_TOMBSTONE_RETENTION_MS
      || value > MAX_TOMBSTONE_RETENTION_MS) {
    throw outboxError('diagnostic_configuration_invalid');
  }
  return value;
}

function eventAgeLimit(value) {
  if (value === undefined) return MAX_DIAGNOSTIC_AGE_MS;
  if (!Number.isInteger(value) || value < 1_000 || value > MAX_DIAGNOSTIC_AGE_MS) {
    throw outboxError('diagnostic_configuration_invalid');
  }
  return value;
}

function checkedCount(value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)
      || value < 0 || value > MAX_RECORD_LIMIT) {
    throw outboxError('diagnostic_integrity_failed');
  }
  return value;
}

function retryAt(nowMs, attempts) {
  const exponent = Math.max(0, Math.min(10, attempts - 1));
  return nowMs + Math.min(RETRY_MAX_MS, RETRY_BASE_MS * (2 ** exponent));
}

function reasonCode(error) {
  const allowed = new Set([
    'diagnostic_customer_mismatch', 'diagnostic_deployment_mismatch',
    'diagnostic_schema_rejected', 'diagnostic_sensitive_metadata',
    'diagnostic_time_invalid', 'diagnostic_delivery_invalid',
    'diagnostic_idempotency_conflict', 'diagnostic_queue_full',
    'diagnostic_history_full', 'diagnostic_input_invalid',
  ]);
  const code = allowed.has(error && error.code) ? error.code : 'diagnostic_rejected';
  return code.replace(/^diagnostic_/, '');
}

function canonicalEqual(left, right) {
  try { return protocol.canonicalJson(left) === protocol.canonicalJson(right); }
  catch { return false; }
}

function proofFields(proofKeyId, mac) { return keyId(proofKeyId) && sha256Digest(mac); }
function keyId(value) { return typeof value === 'string' && /^[a-z0-9][a-z0-9_.-]{0,63}$/.test(value); }
function sha256Digest(value) { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function sha256(value) { return crypto.createHash('sha256').update(value, 'utf8').digest('hex'); }
function thenable(value) { return Boolean(value && (typeof value === 'object' || typeof value === 'function') && typeof value.then === 'function'); }
function iso(value) { return new Date(value).toISOString(); }
function validIso(value) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= MAX_ISO_TIME_MS && iso(parsed) === value;
}
function uuid(value) {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
function scope(ctx) { return { customerId: ctx.customerId, deploymentId: ctx.deploymentId }; }
function scopeMessage(ctx, messageId) { return { ...scope(ctx), messageId }; }

function normalizedStorageError(error) {
  return error && error[OUTBOX_ERROR] ? error : outboxError('diagnostic_storage_failed');
}

function outboxError(code) {
  const error = new Error(OUTBOX_ERROR_MESSAGE);
  error.code = code;
  Object.defineProperty(error, OUTBOX_ERROR, { value: true });
  return error;
}

module.exports = {
  createCustomerDiagnosticOutbox,
  RETRY_BASE_MS,
  RETRY_MAX_MS,
  DEFAULT_LEASE_MS,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_TOMBSTONE_RETENTION_MS,
};
