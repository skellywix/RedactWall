'use strict';

const crypto = require('node:crypto');
const Database = require('better-sqlite3');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const {
  isAuditAcknowledgementRegistry,
} = require('./audit-support-acknowledgement');
const {
  CANCELLATION_KIND,
  CANCELLATION_SIGNATURE_DOMAIN,
  assertAuditSupportCancellation,
  assertAuditSupportRequest,
  payloadDigest: auditSupportPayloadDigest,
  REQUEST_SIGNATURE_DOMAIN,
} = require('./audit-support-control-artifacts');

const SCHEMA_VERSION = 4;
const ZERO_DIGEST = '0'.repeat(64);
const OUTBOX_LEASE_MS = 60 * 1000;
const MAX_OUTBOX_ATTEMPTS = 16;
const MAX_FUTURE_SKEW_MS = 60 * 1000;
const STORE_BRAND = Symbol('vendor-audit-support-reference-store');
const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const IDEMPOTENCY_RE = /^[A-Za-z0-9_-]{16,128}$/;
const SAFE_CODE_RE = /^[a-z0-9][a-z0-9_.:-]{0,79}$/;
const OPAQUE_REF_RE = /^[a-z0-9][A-Za-z0-9_-]{19,127}$/;
const REQUEST_KEY_ID_RE = /^rw-audit-request-[a-z0-9][a-z0-9_.-]{0,77}$/;
const EVENT_TYPES = new Set([
  'issued', 'delivered', 'customer_decision', 'response_received', 'expired', 'revoked',
  'superseded', 'cancellation_delivered',
]);
const EVENT_OUTCOMES = new Set([
  'issued', 'delivered', 'approved', 'denied', 'expired', 'revoked', 'completed',
  'superseded',
]);
const ALLOWED_TRANSITIONS = Object.freeze({
  issued: new Set(['delivered', 'expired']),
  delivered: new Set(['expired']),
  responded: new Set(),
  expired: new Set(),
  revoked: new Set(),
  superseded: new Set(),
});

const MIGRATION = `
CREATE TABLE IF NOT EXISTS vendor_audit_support_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL,
  trusted_time_ms INTEGER NOT NULL
);
INSERT OR IGNORE INTO vendor_audit_support_meta(singleton, schema_version, trusted_time_ms)
VALUES (1, 4, 0);
CREATE TABLE IF NOT EXISTS vendor_audit_support_records (
  request_id TEXT NOT NULL,
  request_version INTEGER NOT NULL,
  request_digest TEXT NOT NULL,
  revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  record_json TEXT NOT NULL,
  PRIMARY KEY(request_id, request_version)
);
CREATE INDEX IF NOT EXISTS vendor_audit_support_latest
  ON vendor_audit_support_records(request_id, request_version DESC);
CREATE TABLE IF NOT EXISTS vendor_audit_support_commands (
  idempotency_key TEXT PRIMARY KEY,
  operation_digest TEXT NOT NULL,
  result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vendor_audit_support_response_claims (
  message_id TEXT PRIMARY KEY,
  response_digest TEXT NOT NULL UNIQUE,
  request_id TEXT NOT NULL,
  request_version INTEGER NOT NULL,
  result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vendor_audit_support_outbox (
  message_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  request_version INTEGER NOT NULL,
  request_digest TEXT NOT NULL,
  artifact_digest TEXT NOT NULL,
  document_kind TEXT NOT NULL,
  document_json TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  next_attempt_at TEXT NOT NULL,
  last_error_code TEXT,
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  acknowledgement_applied_at TEXT,
  acknowledgement_digest TEXT,
  acknowledgement_key_id TEXT,
  claim_token TEXT
);
CREATE INDEX IF NOT EXISTS vendor_audit_support_outbox_ready
  ON vendor_audit_support_outbox(status, next_attempt_at, created_at);
CREATE TABLE IF NOT EXISTS vendor_audit_support_audit (
  sequence INTEGER PRIMARY KEY,
  previous_digest TEXT NOT NULL,
  event_digest TEXT NOT NULL UNIQUE,
  event_json TEXT NOT NULL
);
`;

function openReferenceVendorAuditSupportSqlite(options = {}) {
  assertReferenceRuntime();
  const driver = String(options.driver || 'sqlite').toLowerCase();
  if (driver === 'postgres' || driver === 'postgresql') {
    throw storeError('audit_support_postgres_adapter_unavailable');
  }
  if (driver !== 'sqlite') throw storeError('audit_support_storage_driver_invalid');
  const acknowledgementRegistry = checkedAcknowledgementRegistry(
    options.acknowledgementRegistry,
  );
  const database = options.database || new Database(options.path || ':memory:');
  database.pragma('foreign_keys = ON');
  database.pragma('journal_mode = WAL');
  database.pragma('synchronous = FULL');
  database.pragma('busy_timeout = 30000');
  database.exec(MIGRATION);
  const schema = database.prepare(`
    SELECT schema_version FROM vendor_audit_support_meta WHERE singleton = 1
  `).get();
  if (!schema || schema.schema_version !== SCHEMA_VERSION) {
    throw storeError('audit_support_schema_unsupported');
  }
  withTransaction(database, () => null);
  return createStore(database, acknowledgementRegistry);
}

function openProductionVendorAuditSupportStore() {
  throw storeError('audit_support_postgres_adapter_unavailable');
}

function observeTrustedTime(database, nowMs) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw storeError('audit_support_clock_invalid');
  const row = database.prepare(`
    SELECT trusted_time_ms FROM vendor_audit_support_meta WHERE singleton = 1
  `).get();
  if (!row || !Number.isSafeInteger(row.trusted_time_ms) || row.trusted_time_ms < 0) {
    throw storeError('audit_support_clock_invalid');
  }
  const trusted = Math.max(row.trusted_time_ms, nowMs);
  if (trusted !== row.trusted_time_ms) {
    const changed = database.prepare(`
      UPDATE vendor_audit_support_meta SET trusted_time_ms = ?
      WHERE singleton = 1 AND trusted_time_ms = ?
    `).run(trusted, row.trusted_time_ms).changes;
    if (changed !== 1) throw storeError('audit_support_clock_conflict');
  }
  return trusted;
}

function assertLifecycleTime(database, occurredAt) {
  const supplied = Date.parse(canonicalIso(occurredAt, 'audit_support_clock_invalid'));
  const trusted = observeTrustedTime(database, supplied);
  if (trusted !== supplied) throw storeError('audit_support_clock_stale');
  return trusted;
}

function createStore(database, acknowledgementRegistry) {
  let closed = false;
  const store = {
    kind: 'sqlite',
    runtimeProfile: 'reference-only',
    schemaVersion: SCHEMA_VERSION,
    issue: (operation) => withTransaction(database, () => issue(database, operation)),
    transition: (operation) => withTransaction(
      database, () => transition(database, acknowledgementRegistry, operation),
    ),
    revoke: (operation) => withTransaction(database, () => revoke(database, operation)),
    acceptResponse: (operation) => withTransaction(
      database, () => acceptResponse(database, operation),
    ),
    commandReplay(claim) {
      assertOpen(closed);
      return withTransaction(database, () => commandReplay(database, claim));
    },
    responseReplay(claim) {
      assertOpen(closed);
      return withTransaction(database, () => responseReplay(database, claim));
    },
    observeTrustedTime(nowMs) {
      assertOpen(closed);
      return withTransaction(database, () => observeTrustedTime(database, nowMs));
    },
    get(requestId, requestVersion) {
      assertOpen(closed);
      return readRecord(database, requestId, requestVersion);
    },
    getLatest(requestId) {
      assertOpen(closed);
      return readLatestRecord(database, requestId);
    },
    claimOutbox(limit = 16, now = new Date().toISOString()) {
      assertOpen(closed);
      return withTransaction(database, () => claimOutbox(database, limit, now));
    },
    markOutboxRetry(messageId, artifactDigest, nextAt, errorCode, claimToken) {
      assertOpen(closed);
      return withTransaction(
        database,
        () => markOutboxRetry(
          database, messageId, artifactDigest, nextAt, errorCode, claimToken,
        ),
      );
    },
    markCancellationDelivered(operation) {
      assertOpen(closed);
      return withTransaction(
        database,
        () => markCancellationDelivered(database, acknowledgementRegistry, operation),
      );
    },
    auditEvents(cursor = 0) {
      assertOpen(closed);
      const events = verifyAudit(database);
      if (!Number.isSafeInteger(cursor) || cursor < 0 || cursor > events.length) {
        throw storeError('audit_support_cursor_invalid');
      }
      return deepFreeze({ cursor: events.length, items: events.slice(cursor) });
    },
    readiness(now = new Date().toISOString()) {
      assertOpen(closed);
      canonicalIso(now, 'audit_support_clock_invalid');
      let auditReady = true;
      try { verifyAudit(database); } catch { auditReady = false; }
      const quick = database.pragma('quick_check', { simple: true });
      let outboxReady = true;
      try { verifyOutboxEvidence(database); } catch { outboxReady = false; }
      const blocked = database.prepare(`
        SELECT COUNT(*) AS count FROM vendor_audit_support_outbox WHERE status = 'blocked'
      `).get().count;
      const expiredFinalLeases = database.prepare(`
        SELECT COUNT(*) AS count FROM vendor_audit_support_outbox
        WHERE status = 'sending' AND attempts >= ? AND next_attempt_at <= ?
      `).get(MAX_OUTBOX_ATTEMPTS, now).count;
      return Object.freeze({
        ready: quick === 'ok' && auditReady && outboxReady
          && blocked === 0 && expiredFinalLeases === 0,
        storage: quick === 'ok' ? 'ok' : 'failed',
        audit: auditReady ? 'ok' : 'failed',
        outboxIntegrity: outboxReady ? 'ok' : 'failed',
        outboxBlocked: blocked,
        outboxExpiredFinalLeases: expiredFinalLeases,
        postgresSupported: false,
        runtimeProfile: 'reference-only',
      });
    },
    close() { if (!closed) database.close(); closed = true; },
    database,
  };
  Object.defineProperty(store, STORE_BRAND, { value: true });
  return Object.freeze(store);
}

function issue(database, rawOperation) {
  const operation = checkedIssue(rawOperation);
  const replay = idempotentResult(database, operation.idempotencyKey, operation.operationDigest);
  if (replay) return replay;
  assertLifecycleTime(database, operation.record.issuedAt);
  const existing = readRecord(database, operation.record.requestId, operation.record.requestVersion);
  if (existing) throw storeError('audit_support_request_conflict');
  const previous = assertVersionProgression(database, operation.record);
  if (previous && ['issued', 'delivered'].includes(previous.status)) {
    supersedeRecord(database, previous, operation.record.issuedAt);
  }
  if (previous) cancelOutbox(database, previous);
  insertRecord(database, operation.record);
  insertOutbox(database, operation.outbox);
  appendAudit(database, operation.auditEvent);
  const result = publicResult(operation.record, false);
  rememberCommand(database, operation.idempotencyKey, operation.operationDigest, result);
  return result;
}

function transition(database, acknowledgementRegistry, rawOperation) {
  const operation = checkedTransition(rawOperation, acknowledgementRegistry);
  const replay = idempotentResult(database, operation.idempotencyKey, operation.operationDigest);
  if (replay) return replay;
  assertLifecycleTime(database, operation.occurredAt);
  const record = requireRecord(database, operation);
  assertAuditEventScope(record, operation.auditEvent);
  if (operation.targetStatus === 'delivered') assertStoredReceipt(record, operation, false);
  if (!ALLOWED_TRANSITIONS[record.status]?.has(operation.targetStatus)) {
    throw storeError('audit_support_transition_invalid');
  }
  const field = operation.targetStatus === 'delivered' ? 'deliveredAt' : 'terminatedAt';
  const evidence = operation.targetStatus === 'delivered'
    ? acknowledgementEvidence(operation.receipt) : null;
  const updated = {
    ...record,
    ...(evidence ? {
      deliveryAcknowledgementDigest: evidence.digest,
      deliveryAcknowledgementKeyId: evidence.keyId,
      deliveryAppliedAt: evidence.appliedAt,
    } : {}),
    [field]: operation.occurredAt,
    revision: record.revision + 1,
    status: operation.targetStatus,
  };
  replaceRecord(database, updated, record.revision);
  if (operation.targetStatus === 'delivered') markOutboxDelivered(database, updated, operation);
  else cancelOutbox(database, updated);
  appendAudit(database, operation.auditEvent);
  const result = publicResult(updated, false);
  rememberCommand(database, operation.idempotencyKey, operation.operationDigest, result);
  return result;
}

function revoke(database, rawOperation) {
  const operation = checkedRevoke(rawOperation);
  const replay = idempotentResult(database, operation.idempotencyKey, operation.operationDigest);
  if (replay) return replay;
  assertLifecycleTime(database, operation.occurredAt);
  const record = requireRecord(database, operation);
  assertAuditEventScope(record, operation.auditEvent);
  if (!['issued', 'delivered'].includes(record.status)) {
    throw storeError('audit_support_transition_invalid');
  }
  assertCancellationBinding(operation, record);
  const updated = {
    ...record,
    cancellationArtifact: operation.cancellation.signedArtifact,
    cancellationDigest: operation.cancellation.cancellationDigest,
    cancellationIssuedAt: operation.cancellation.issuedAt,
    revision: record.revision + 1,
    status: 'revoked',
    terminatedAt: operation.occurredAt,
  };
  replaceRecord(database, updated, record.revision);
  cancelOutbox(database, record);
  insertOutbox(database, operation.cancellationOutbox);
  appendAudit(database, operation.auditEvent);
  const result = publicResult(updated, false);
  rememberCommand(database, operation.idempotencyKey, operation.operationDigest, result);
  return result;
}

function markCancellationDelivered(database, acknowledgementRegistry, rawOperation) {
  const operation = checkedCancellationDelivery(rawOperation, acknowledgementRegistry);
  const replay = idempotentResult(database, operation.idempotencyKey, operation.operationDigest);
  if (replay) return replay;
  assertLifecycleTime(database, operation.occurredAt);
  const record = requireRecord(database, operation);
  if (record.status !== 'revoked'
      || record.cancellationDigest !== operation.cancellationDigest) {
    throw storeError('audit_support_cancellation_not_current');
  }
  assertStoredReceipt(record, operation, true);
  assertAuditEventScope(record, operation.auditEvent);
  const evidence = acknowledgementEvidence(operation.receipt);
  const changed = database.prepare(`
    UPDATE vendor_audit_support_outbox
    SET status = 'delivered', delivered_at = ?, acknowledgement_applied_at = ?,
      acknowledgement_digest = ?, acknowledgement_key_id = ?,
      last_error_code = NULL, claim_token = NULL
    WHERE message_id = ? AND artifact_digest = ? AND document_kind = ?
      AND status = 'sending' AND claim_token = ?
  `).run(operation.occurredAt, evidence.appliedAt, evidence.digest, evidence.keyId,
    operation.messageId, operation.artifactDigest, CANCELLATION_KIND,
    operation.claimToken).changes;
  if (changed !== 1) throw storeError('audit_support_outbox_conflict');
  const updated = {
    ...record,
    cancellationAcknowledgementDigest: evidence.digest,
    cancellationAcknowledgementKeyId: evidence.keyId,
    cancellationAppliedAt: evidence.appliedAt,
    cancellationDeliveredAt: operation.occurredAt,
    revision: record.revision + 1,
  };
  replaceRecord(database, updated, record.revision);
  appendAudit(database, operation.auditEvent);
  const result = publicResult(updated, false);
  rememberCommand(database, operation.idempotencyKey, operation.operationDigest, result);
  return result;
}

function acceptResponse(database, rawOperation) {
  const operation = checkedResponseOperation(rawOperation);
  const trustedReceiveTimeMs = observeTrustedTime(database, operation.receivedTimeMs);
  const existingClaim = database.prepare(`
    SELECT response_digest, result_json FROM vendor_audit_support_response_claims
    WHERE message_id = ?
  `).get(operation.messageId);
  if (existingClaim) {
    if (existingClaim.response_digest !== operation.responseDigest) {
      throw storeError('audit_support_response_conflict');
    }
    return duplicate(parseCanonical(existingClaim.result_json, 'audit_support_response_invalid'));
  }
  const duplicateDigest = database.prepare(`
    SELECT 1 FROM vendor_audit_support_response_claims WHERE response_digest = ?
  `).get(operation.responseDigest);
  if (duplicateDigest) throw storeError('audit_support_response_conflict');
  const record = requireRecord(database, operation);
  if (!['issued', 'delivered'].includes(record.status)) {
    throw storeError('audit_support_response_not_current');
  }
  assertResponseAuditEvents(record, operation);
  const respondedMs = Date.parse(operation.respondedAt);
  const notBeforeMs = Date.parse(record.signedArtifact.payload.notBefore);
  const expiresMs = Date.parse(record.signedArtifact.payload.expiresAt);
  if (trustedReceiveTimeMs > expiresMs
      || respondedMs < notBeforeMs || respondedMs > expiresMs
      || respondedMs > trustedReceiveTimeMs + MAX_FUTURE_SKEW_MS) {
    throw storeError('audit_support_response_expired');
  }
  const updated = {
    ...record,
    customerDecision: operation.decision,
    responseDigest: operation.responseDigest,
    responseKeyId: operation.responseKeyId,
    responseMessageId: operation.messageId,
    responseSignatureDomain: operation.responseSignatureDomain,
    respondedAt: operation.respondedAt,
    revision: record.revision + 1,
    status: 'responded',
  };
  replaceRecord(database, updated, record.revision);
  cancelOutbox(database, updated);
  for (const event of operation.auditEvents) appendAudit(database, event);
  const result = publicResult(updated, false);
  database.prepare(`
    INSERT INTO vendor_audit_support_response_claims
      (message_id, response_digest, request_id, request_version, result_json)
    VALUES (?, ?, ?, ?, ?)
  `).run(operation.messageId, operation.responseDigest, operation.requestId,
    operation.requestVersion, canonical(result));
  return result;
}

function responseReplay(database, rawClaim) {
  const claim = checkedResponseClaim(rawClaim);
  const existing = database.prepare(`
    SELECT response_digest, result_json FROM vendor_audit_support_response_claims
    WHERE message_id = ?
  `).get(claim.messageId);
  if (!existing) return null;
  if (existing.response_digest !== claim.responseDigest) {
    throw storeError('audit_support_response_conflict');
  }
  return duplicate(parseCanonical(existing.result_json, 'audit_support_response_invalid'));
}

function commandReplay(database, rawClaim) {
  const claim = checkedCommandClaim(rawClaim);
  return idempotentResult(database, claim.idempotencyKey, claim.operationDigest);
}

function checkedCommandClaim(raw) {
  const claim = clonePlain(raw, 'audit_support_command_invalid');
  if (!exactKeys(claim, ['idempotencyKey', 'operationDigest'])) {
    throw storeError('audit_support_command_invalid');
  }
  checkedIdempotency(claim.idempotencyKey);
  checkedDigest(claim.operationDigest, 'audit_support_command_invalid');
  return claim;
}

function checkedResponseClaim(raw) {
  const claim = clonePlain(raw, 'audit_support_response_invalid');
  if (!exactKeys(claim, ['messageId', 'responseDigest'])) {
    throw storeError('audit_support_response_invalid');
  }
  checkedUuid(claim.messageId, 'audit_support_response_invalid');
  checkedDigest(claim.responseDigest, 'audit_support_response_invalid');
  return claim;
}

function checkedIssue(raw) {
  const operation = clonePlain(raw, 'audit_support_issue_invalid');
  if (!exactKeys(operation, [
    'auditEvent', 'idempotencyKey', 'operationDigest', 'outbox', 'record',
  ])) throw storeError('audit_support_issue_invalid');
  checkedIdempotency(operation.idempotencyKey);
  checkedDigest(operation.operationDigest, 'audit_support_issue_invalid');
  operation.record = checkedRecord(operation.record);
  if (operation.record.status !== 'issued' || operation.record.revision !== 1) {
    throw storeError('audit_support_issue_invalid');
  }
  operation.outbox = checkedOutbox(
    operation.outbox, operation.record, protocol.CHANNEL_KINDS.AUDIT_REQUEST,
    operation.record.signedArtifact,
  );
  operation.auditEvent = checkedAuditEvent(operation.auditEvent);
  assertAuditEventBinding(operation.auditEvent, operation.record, {
    authorizationRef: operation.record.authorization.auditRef,
    count: 0,
    eventType: 'issued',
    occurredAt: operation.record.issuedAt,
    outcome: 'issued',
  });
  return operation;
}

function checkedTransition(raw, acknowledgementRegistry) {
  const operation = clonePlain(raw, 'audit_support_transition_invalid');
  const baseKeys = [
    'auditEvent', 'idempotencyKey', 'occurredAt', 'operationDigest', 'requestDigest',
    'requestId', 'requestVersion', 'targetStatus',
  ];
  const expectedKeys = operation.targetStatus === 'delivered'
    ? [...baseKeys, 'artifactDigest', 'claimToken', 'messageId', 'receipt'] : baseKeys;
  if (!exactKeys(operation, expectedKeys)) throw storeError('audit_support_transition_invalid');
  checkedIdempotency(operation.idempotencyKey);
  checkedDigest(operation.operationDigest, 'audit_support_transition_invalid');
  checkedRequestBinding(operation, 'audit_support_transition_invalid');
  canonicalIso(operation.occurredAt, 'audit_support_transition_invalid');
  if (!['delivered', 'expired'].includes(operation.targetStatus)) {
    throw storeError('audit_support_transition_invalid');
  }
  if (operation.targetStatus === 'delivered') {
    checkedUuid(operation.messageId, 'audit_support_transition_invalid');
    checkedUuid(operation.claimToken, 'audit_support_transition_invalid');
    checkedDigest(operation.artifactDigest, 'audit_support_transition_invalid');
    operation.receipt = checkedDeliveryReceipt(
      operation.receipt, operation, false, 'audit_support_transition_invalid',
      acknowledgementRegistry,
    );
  }
  operation.auditEvent = checkedAuditEvent(operation.auditEvent);
  const evidence = operation.targetStatus === 'delivered'
    ? acknowledgementEvidence(operation.receipt) : null;
  assertAuditEventBinding(operation.auditEvent, operation, {
    acknowledgementAppliedAt: evidence?.appliedAt || null,
    acknowledgementDigest: evidence?.digest || null,
    acknowledgementKeyId: evidence?.keyId || null,
    authorizationRef: null,
    count: 0,
    eventType: operation.targetStatus,
    occurredAt: operation.occurredAt,
    outcome: operation.targetStatus,
  });
  return operation;
}

function checkedRevoke(raw) {
  const operation = clonePlain(raw, 'audit_support_revoke_invalid');
  if (!exactKeys(operation, [
    'auditEvent', 'cancellation', 'cancellationOutbox', 'idempotencyKey', 'occurredAt',
    'operationDigest', 'requestDigest', 'requestId', 'requestVersion', 'targetStatus',
  ]) || operation.targetStatus !== 'revoked') throw storeError('audit_support_revoke_invalid');
  checkedIdempotency(operation.idempotencyKey);
  checkedDigest(operation.operationDigest, 'audit_support_revoke_invalid');
  checkedRequestBinding(operation, 'audit_support_revoke_invalid');
  canonicalIso(operation.occurredAt, 'audit_support_revoke_invalid');
  operation.cancellation = checkedCancellation(operation.cancellation);
  operation.cancellationOutbox = checkedOutbox(
    operation.cancellationOutbox, operation, CANCELLATION_KIND,
    operation.cancellation.signedArtifact,
  );
  operation.auditEvent = checkedAuditEvent(operation.auditEvent);
  assertAuditEventBinding(operation.auditEvent, operation, {
    authorizationRefRequired: true,
    count: 0,
    eventType: 'revoked',
    occurredAt: operation.occurredAt,
    outcome: 'revoked',
  });
  return operation;
}

function checkedCancellationDelivery(raw, acknowledgementRegistry) {
  const operation = clonePlain(raw, 'audit_support_cancellation_delivery_invalid');
  if (!exactKeys(operation, [
    'artifactDigest', 'auditEvent', 'cancellationDigest', 'idempotencyKey', 'messageId',
    'claimToken', 'occurredAt', 'operationDigest', 'receipt', 'requestDigest', 'requestId',
    'requestVersion',
  ])) throw storeError('audit_support_cancellation_delivery_invalid');
  checkedIdempotency(operation.idempotencyKey);
  checkedRequestBinding(operation, 'audit_support_cancellation_delivery_invalid');
  checkedUuid(operation.messageId, 'audit_support_cancellation_delivery_invalid');
  checkedUuid(operation.claimToken, 'audit_support_cancellation_delivery_invalid');
  checkedDigest(operation.artifactDigest, 'audit_support_cancellation_delivery_invalid');
  checkedDigest(operation.cancellationDigest, 'audit_support_cancellation_delivery_invalid');
  checkedDigest(operation.operationDigest, 'audit_support_cancellation_delivery_invalid');
  canonicalIso(operation.occurredAt, 'audit_support_cancellation_delivery_invalid');
  operation.receipt = checkedDeliveryReceipt(
    operation.receipt, operation, true, 'audit_support_cancellation_delivery_invalid',
    acknowledgementRegistry,
  );
  operation.auditEvent = checkedAuditEvent(operation.auditEvent);
  const evidence = acknowledgementEvidence(operation.receipt);
  assertAuditEventBinding(operation.auditEvent, operation, {
    acknowledgementAppliedAt: evidence.appliedAt,
    acknowledgementDigest: evidence.digest,
    acknowledgementKeyId: evidence.keyId,
    authorizationRef: null,
    count: 0,
    eventType: 'cancellation_delivered',
    occurredAt: operation.occurredAt,
    outcome: 'delivered',
  });
  return operation;
}

function checkedDeliveryReceipt(raw, binding, cancellation, code, acknowledgementRegistry) {
  const receipt = clonePlain(raw, code);
  const keys = [
    'accepted', 'acknowledgementKeyId', 'acknowledgementMac', 'artifactDigest',
    'customerId', 'deploymentId', 'messageId', 'receivedAt', 'requestDigest',
    'requestId', 'requestVersion',
  ];
  if (cancellation) keys.push('cancellationDigest');
  if (!exactKeys(receipt, keys) || receipt.accepted !== true
      || receipt.messageId !== binding.messageId
      || receipt.artifactDigest !== binding.artifactDigest
      || receipt.requestDigest !== binding.requestDigest
      || receipt.requestId !== binding.requestId
      || receipt.requestVersion !== binding.requestVersion
      || (cancellation && receipt.cancellationDigest !== binding.cancellationDigest)
      || !CUSTOMER_ID_RE.test(String(receipt.customerId || ''))
      || !isDeploymentId(receipt.deploymentId)) throw storeError(code);
  canonicalIso(receipt.receivedAt, code);
  let verified;
  try { verified = acknowledgementRegistry.verify(receipt); }
  catch { throw storeError('audit_support_acknowledgement_invalid'); }
  const core = { ...receipt };
  delete core.acknowledgementKeyId;
  delete core.acknowledgementMac;
  if (canonical(verified) !== canonical(core)) {
    throw storeError('audit_support_acknowledgement_invalid');
  }
  return receipt;
}

function assertStoredReceipt(record, operation, cancellation) {
  const receipt = operation.receipt;
  const earliest = cancellation ? record.cancellationIssuedAt : record.issuedAt;
  const latest = cancellation ? null : record.signedArtifact.payload.expiresAt;
  if (receipt.customerId !== record.customerId
      || receipt.deploymentId !== record.deploymentId
      || Date.parse(receipt.receivedAt) < Date.parse(earliest)
      || (latest !== null && Date.parse(receipt.receivedAt) >= Date.parse(latest))
      || Date.parse(receipt.receivedAt)
        > Date.parse(operation.occurredAt) + MAX_FUTURE_SKEW_MS
      || (cancellation && receipt.cancellationDigest !== record.cancellationDigest)) {
    throw storeError(cancellation
      ? 'audit_support_cancellation_delivery_invalid' : 'audit_support_transition_invalid');
  }
}

function checkedCancellation(raw) {
  const value = clonePlain(raw, 'audit_support_cancellation_invalid');
  if (!exactKeys(value, ['cancellationDigest', 'issuedAt', 'signedArtifact'])) {
    throw storeError('audit_support_cancellation_invalid');
  }
  const payload = assertAuditSupportCancellation(value.signedArtifact?.payload);
  canonicalIso(value.issuedAt, 'audit_support_cancellation_invalid');
  if (payload.issuedAt !== value.issuedAt
      || auditSupportPayloadDigest(payload, CANCELLATION_SIGNATURE_DOMAIN)
        !== value.cancellationDigest) {
    throw storeError('audit_support_cancellation_invalid');
  }
  return value;
}

function checkedResponseOperation(raw) {
  const operation = clonePlain(raw, 'audit_support_response_invalid');
  if (!exactKeys(operation, [
    'auditEvents', 'decision', 'localApprovalRef', 'messageId', 'requestDigest', 'requestId',
    'receivedTimeMs', 'requestVersion', 'respondedAt', 'responseDigest', 'responseKeyId',
    'responseSignatureDomain', 'responseStatus', 'summaryCount',
  ])) throw storeError('audit_support_response_invalid');
  checkedRequestBinding(operation, 'audit_support_response_invalid');
  checkedUuid(operation.messageId, 'audit_support_response_invalid');
  checkedDigest(operation.responseDigest, 'audit_support_response_invalid');
  canonicalIso(operation.respondedAt, 'audit_support_response_invalid');
  if (!Number.isSafeInteger(operation.receivedTimeMs) || operation.receivedTimeMs < 0) {
    throw storeError('audit_support_response_invalid');
  }
  if (!['approved', 'denied', 'expired', 'revoked'].includes(operation.decision)
      || !SAFE_CODE_RE.test(String(operation.responseKeyId || ''))
      || operation.responseSignatureDomain !== 'redactwall.customer-audit-response.v1'
      || !OPAQUE_REF_RE.test(String(operation.localApprovalRef || ''))
      || !['completed', 'denied', 'expired', 'revoked'].includes(operation.responseStatus)
      || !Number.isSafeInteger(operation.summaryCount) || operation.summaryCount < 0
      || !Array.isArray(operation.auditEvents) || operation.auditEvents.length !== 2) {
    throw storeError('audit_support_response_invalid');
  }
  operation.auditEvents = operation.auditEvents.map(checkedAuditEvent);
  return operation;
}

function assertAuditEventBinding(event, binding, expected) {
  if (event.requestDigest !== binding.requestDigest
      || event.requestVersion !== binding.requestVersion
      || event.eventType !== expected.eventType
      || event.outcome !== expected.outcome
      || event.occurredAt !== expected.occurredAt
      || event.count !== expected.count
      || event.acknowledgementAppliedAt
        !== (expected.acknowledgementAppliedAt || null)
      || event.acknowledgementDigest !== (expected.acknowledgementDigest || null)
      || event.acknowledgementKeyId !== (expected.acknowledgementKeyId || null)
      || (expected.authorizationRefRequired === true && event.authorizationRef === null)
      || (Object.hasOwn(expected, 'authorizationRef')
        && event.authorizationRef !== expected.authorizationRef)) {
    throw storeError('audit_support_audit_event_binding_invalid');
  }
  if (binding.customerId !== undefined) assertAuditEventScope(binding, event);
}

function assertAuditEventScope(record, event) {
  if (event.scopeDigest !== sha256(`${record.customerId}\0${record.deploymentId}`)) {
    throw storeError('audit_support_audit_event_binding_invalid');
  }
}

function assertResponseAuditEvents(record, operation) {
  const scopeDigest = sha256(`${record.customerId}\0${record.deploymentId}`);
  const expectedStatus = {
    approved: 'completed', denied: 'denied', expired: 'expired', revoked: 'revoked',
  }[operation.decision];
  const [decisionEvent, responseEvent] = operation.auditEvents;
  if (operation.responseStatus !== expectedStatus
      || decisionEvent.scopeDigest !== scopeDigest || responseEvent.scopeDigest !== scopeDigest) {
    throw storeError('audit_support_audit_event_binding_invalid');
  }
  assertAuditEventBinding(decisionEvent, operation, {
    authorizationRef: operation.localApprovalRef,
    count: 0,
    eventType: 'customer_decision',
    occurredAt: operation.respondedAt,
    outcome: operation.decision,
  });
  assertAuditEventBinding(responseEvent, operation, {
    authorizationRef: operation.localApprovalRef,
    count: operation.summaryCount,
    eventType: 'response_received',
    occurredAt: operation.respondedAt,
    outcome: operation.responseStatus,
  });
}

function checkedRecord(raw) {
  const record = clonePlain(raw, 'audit_support_record_invalid');
  const keys = [
    'authorization', 'cancellationAcknowledgementDigest', 'cancellationAcknowledgementKeyId',
    'cancellationAppliedAt', 'cancellationArtifact', 'cancellationDeliveredAt',
    'cancellationDigest', 'cancellationIssuedAt', 'customerDecision', 'customerId',
    'deliveredAt', 'deliveryAcknowledgementDigest', 'deliveryAcknowledgementKeyId',
    'deliveryAppliedAt', 'deploymentId',
    'issuedAt', 'purposeCode', 'requestDigest', 'requestId', 'requestVersion', 'respondedAt',
    'responseDigest', 'responseKeyId', 'responseMessageId', 'responseSignatureDomain',
    'revision', 'scopeRef', 'signedArtifact', 'status', 'terminatedAt', 'schemaVersion',
  ];
  if (!exactKeys(record, keys) || record.schemaVersion !== 1
      || !UUID_RE.test(String(record.requestId || ''))
      || !CUSTOMER_ID_RE.test(String(record.customerId || ''))
      || !isDeploymentId(record.deploymentId)
      || !Number.isSafeInteger(record.requestVersion) || record.requestVersion < 1
      || !Number.isSafeInteger(record.revision) || record.revision < 1
      || !SHA256_RE.test(String(record.requestDigest || ''))
      || !['issued', 'delivered', 'responded', 'expired', 'revoked', 'superseded']
        .includes(record.status)
      || !OPAQUE_REF_RE.test(String(record.scopeRef || ''))
      || !['customer_support', 'security_incident', 'compliance_assistance']
        .includes(record.purposeCode)) throw storeError('audit_support_record_invalid');
  canonicalIso(record.issuedAt, 'audit_support_record_invalid');
  checkedNullableIso(record.deliveredAt, 'audit_support_record_invalid');
  checkedNullableIso(record.deliveryAppliedAt, 'audit_support_record_invalid');
  checkedNullableIso(record.respondedAt, 'audit_support_record_invalid');
  checkedNullableIso(record.terminatedAt, 'audit_support_record_invalid');
  if (record.responseDigest !== null) checkedDigest(
    record.responseDigest, 'audit_support_record_invalid',
  );
  if (record.responseMessageId !== null) checkedUuid(
    record.responseMessageId, 'audit_support_record_invalid',
  );
  if ((record.responseKeyId !== null && !SAFE_CODE_RE.test(String(record.responseKeyId || '')))
      || (record.responseSignatureDomain !== null
        && record.responseSignatureDomain !== 'redactwall.customer-audit-response.v1')
      || (record.customerDecision !== null
        && !['approved', 'denied', 'expired', 'revoked'].includes(record.customerDecision))) {
    throw storeError('audit_support_record_invalid');
  }
  checkedAcknowledgementEvidence(record, 'delivery');
  checkedAcknowledgementEvidence(record, 'cancellation');
  const requestArtifact = checkedSignedArtifact(
    record.signedArtifact, assertAuditSupportRequest, REQUEST_SIGNATURE_DOMAIN,
    'audit_support_record_invalid',
  );
  const request = requestArtifact.payload;
  if (requestArtifact.payloadDigest !== record.requestDigest
      || requestArtifact.keyId !== record.signedArtifact.keyId
      || request.customerId !== record.customerId
      || request.deploymentId !== record.deploymentId
      || request.requestId !== record.requestId
      || request.requestVersion !== record.requestVersion
      || request.purposeCode !== record.purposeCode
      || request.issuedAt !== record.issuedAt
      || !record.authorization || !exactKeys(record.authorization, ['authEventId', 'auditRef'])
      || !UUID_RE.test(String(record.authorization.authEventId || ''))
      || !OPAQUE_REF_RE.test(String(record.authorization.auditRef || ''))) {
    throw storeError('audit_support_record_invalid');
  }
  if (record.cancellationDigest !== null) {
    checkedDigest(record.cancellationDigest, 'audit_support_record_invalid');
    canonicalIso(record.cancellationIssuedAt, 'audit_support_record_invalid');
    const cancellationArtifact = checkedSignedArtifact(
      record.cancellationArtifact, assertAuditSupportCancellation,
      CANCELLATION_SIGNATURE_DOMAIN, 'audit_support_record_invalid',
    );
    const cancellation = cancellationArtifact.payload;
    if (cancellationArtifact.payloadDigest !== record.cancellationDigest
        || cancellation.customerId !== record.customerId
        || cancellation.deploymentId !== record.deploymentId
        || cancellation.requestId !== record.requestId
        || cancellation.requestVersion !== record.requestVersion
        || cancellation.requestDigest !== record.requestDigest
        || cancellation.issuedAt !== record.cancellationIssuedAt) {
      throw storeError('audit_support_record_invalid');
    }
  } else if (record.cancellationArtifact !== null || record.cancellationIssuedAt !== null
      || record.cancellationDeliveredAt !== null) {
    throw storeError('audit_support_record_invalid');
  }
  if (record.cancellationDeliveredAt !== null) {
    canonicalIso(record.cancellationDeliveredAt, 'audit_support_record_invalid');
  }
  assertRecordStateCoherence(record);
  return record;
}

function assertRecordStateCoherence(record) {
  const responseFields = [
    record.customerDecision, record.respondedAt, record.responseDigest, record.responseKeyId,
    record.responseMessageId, record.responseSignatureDomain,
  ];
  const hasResponse = responseFields.every((value) => value !== null);
  const noResponse = responseFields.every((value) => value === null);
  const hasCancellation = record.cancellationArtifact !== null
    && record.cancellationDigest !== null && record.cancellationIssuedAt !== null;
  const noCancellation = record.cancellationArtifact === null
    && record.cancellationDigest === null && record.cancellationIssuedAt === null
    && record.cancellationDeliveredAt === null;
  const deliveryEvidence = [
    record.deliveryAppliedAt, record.deliveryAcknowledgementDigest,
    record.deliveryAcknowledgementKeyId,
  ];
  const hasDeliveryEvidence = deliveryEvidence.every((value) => value !== null);
  const noDeliveryEvidence = deliveryEvidence.every((value) => value === null);
  const cancellationEvidence = [
    record.cancellationAppliedAt, record.cancellationAcknowledgementDigest,
    record.cancellationAcknowledgementKeyId,
  ];
  const hasCancellationEvidence = cancellationEvidence.every((value) => value !== null);
  const noCancellationEvidence = cancellationEvidence.every((value) => value === null);
  if ((!hasDeliveryEvidence && !noDeliveryEvidence)
      || (record.deliveredAt === null) !== noDeliveryEvidence
      || (!hasCancellationEvidence && !noCancellationEvidence)
      || (record.cancellationDeliveredAt === null) !== noCancellationEvidence) {
    throw storeError('audit_support_record_invalid');
  }
  const valid = {
    issued: record.deliveredAt === null && record.terminatedAt === null
      && noResponse && noCancellation,
    delivered: record.deliveredAt !== null && record.terminatedAt === null
      && noResponse && noCancellation,
    responded: record.terminatedAt === null && hasResponse && noCancellation,
    expired: record.terminatedAt !== null && noResponse && noCancellation,
    superseded: record.terminatedAt !== null && noResponse && noCancellation,
    revoked: record.terminatedAt !== null && noResponse && hasCancellation,
  }[record.status];
  if (!valid) throw storeError('audit_support_record_invalid');
}

function checkedAcknowledgementEvidence(record, prefix) {
  const appliedAt = record[`${prefix}AppliedAt`];
  const digest = record[`${prefix}AcknowledgementDigest`];
  const keyId = record[`${prefix}AcknowledgementKeyId`];
  if (appliedAt !== null) canonicalIso(appliedAt, 'audit_support_record_invalid');
  if (digest !== null) checkedDigest(digest, 'audit_support_record_invalid');
  if (keyId !== null && !/^rw-audit-ack-[a-z0-9][a-z0-9_.-]{0,70}$/.test(
    String(keyId || ''),
  )) throw storeError('audit_support_record_invalid');
}

function checkedOutbox(raw, record, expectedKind, expectedDocument) {
  const outbox = clonePlain(raw, 'audit_support_outbox_invalid');
  if (!exactKeys(outbox, [
    'artifactDigest', 'createdAt', 'document', 'documentKind', 'messageId', 'requestDigest',
    'requestId', 'requestVersion',
  ]) || outbox.requestId !== record.requestId
      || outbox.requestVersion !== record.requestVersion
      || outbox.requestDigest !== record.requestDigest
      || outbox.documentKind !== expectedKind
      || outbox.messageId !== expectedDocument.payload.messageId
      || !SHA256_RE.test(String(outbox.artifactDigest || ''))
      || canonical(outbox.document) !== canonical(expectedDocument)
      || sha256(canonical(outbox.document)) !== outbox.artifactDigest) {
    throw storeError('audit_support_outbox_invalid');
  }
  canonicalIso(outbox.createdAt, 'audit_support_outbox_invalid');
  return outbox;
}

function checkedSignedArtifact(raw, payloadValidator, domain, code) {
  const artifact = clonePlain(raw, code);
  if (!exactKeys(artifact, ['keyId', 'payload', 'signature'])
      || !REQUEST_KEY_ID_RE.test(String(artifact.keyId || ''))) throw storeError(code);
  let payload;
  try { payload = payloadValidator(artifact.payload); }
  catch { throw storeError(code); }
  canonicalSignature(artifact.signature, code);
  return {
    keyId: artifact.keyId,
    payload,
    payloadDigest: auditSupportPayloadDigest(payload, domain),
  };
}

function assertCancellationBinding(operation, record) {
  const payload = operation.cancellation.signedArtifact.payload;
  if (payload.requestId !== record.requestId
      || payload.requestVersion !== record.requestVersion
      || payload.requestDigest !== record.requestDigest
      || payload.customerId !== record.customerId
      || payload.deploymentId !== record.deploymentId
      || operation.cancellationOutbox.requestDigest !== record.requestDigest) {
    throw storeError('audit_support_cancellation_invalid');
  }
}

function checkedAuditEvent(raw) {
  const event = clonePlain(raw, 'audit_support_audit_event_invalid');
  if (!exactKeys(event, [
    'acknowledgementAppliedAt', 'acknowledgementDigest', 'acknowledgementKeyId',
    'authorizationRef', 'count', 'eventType', 'occurredAt', 'outcome', 'requestDigest',
    'requestVersion', 'scopeDigest',
  ]) || !EVENT_TYPES.has(event.eventType) || !EVENT_OUTCOMES.has(event.outcome)
      || !Number.isSafeInteger(event.requestVersion) || event.requestVersion < 1
      || !SHA256_RE.test(String(event.requestDigest || ''))
      || !SHA256_RE.test(String(event.scopeDigest || ''))
      || !Number.isSafeInteger(event.count) || event.count < 0
      || (event.acknowledgementDigest !== null
        && !SHA256_RE.test(String(event.acknowledgementDigest || '')))
      || (event.acknowledgementKeyId !== null
        && !/^rw-audit-ack-[a-z0-9][a-z0-9_.-]{0,70}$/.test(
          String(event.acknowledgementKeyId || ''),
        ))
      || (event.authorizationRef !== null
        && !OPAQUE_REF_RE.test(String(event.authorizationRef || '')))) {
    throw storeError('audit_support_audit_event_invalid');
  }
  canonicalIso(event.occurredAt, 'audit_support_audit_event_invalid');
  if (event.acknowledgementAppliedAt !== null) {
    canonicalIso(event.acknowledgementAppliedAt, 'audit_support_audit_event_invalid');
  }
  const evidenceFields = [
    event.acknowledgementAppliedAt, event.acknowledgementDigest,
    event.acknowledgementKeyId,
  ];
  if (!evidenceFields.every((value) => value === null)
      && !evidenceFields.every((value) => value !== null)) {
    throw storeError('audit_support_audit_event_invalid');
  }
  return event;
}

function assertVersionProgression(database, record) {
  const previous = readLatestRecord(database, record.requestId);
  const expected = previous ? previous.requestVersion + 1 : 1;
  if (record.requestVersion !== expected) throw storeError('audit_support_version_invalid');
  if (previous) {
    const priorRequest = previous.signedArtifact.payload;
    const nextRequest = record.signedArtifact.payload;
    if (previous.customerId !== record.customerId
        || previous.deploymentId !== record.deploymentId
        || previous.purposeCode !== record.purposeCode
        || priorRequest.requestType !== nextRequest.requestType) {
      throw storeError('audit_support_request_lineage_invalid');
    }
  }
  return previous;
}

function supersedeRecord(database, previous, occurredAt) {
  const updated = {
    ...previous,
    revision: previous.revision + 1,
    status: 'superseded',
    terminatedAt: occurredAt,
  };
  replaceRecord(database, updated, previous.revision);
  cancelOutbox(database, updated);
  appendAudit(database, {
    acknowledgementAppliedAt: null,
    acknowledgementDigest: null,
    acknowledgementKeyId: null,
    authorizationRef: null,
    count: 0,
    eventType: 'superseded',
    occurredAt,
    outcome: 'superseded',
    requestDigest: previous.requestDigest,
    requestVersion: previous.requestVersion,
    scopeDigest: sha256(`${previous.customerId}\0${previous.deploymentId}`),
  });
}

function insertRecord(database, record) {
  database.prepare(`
    INSERT INTO vendor_audit_support_records
      (request_id, request_version, request_digest, revision, status, record_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(record.requestId, record.requestVersion, record.requestDigest, record.revision,
    record.status, canonical(record));
}

function replaceRecord(database, record, expectedRevision) {
  const checked = checkedRecord(record);
  if (checked.revision !== expectedRevision + 1) throw storeError('audit_support_revision_invalid');
  const result = database.prepare(`
    UPDATE vendor_audit_support_records
    SET revision = ?, status = ?, record_json = ?
    WHERE request_id = ? AND request_version = ? AND request_digest = ? AND revision = ?
  `).run(checked.revision, checked.status, canonical(checked), checked.requestId,
    checked.requestVersion, checked.requestDigest, expectedRevision);
  if (result.changes !== 1) throw storeError('audit_support_revision_conflict');
}

function readRecord(database, requestId, requestVersion) {
  checkedUuid(requestId, 'audit_support_request_invalid');
  if (!Number.isSafeInteger(requestVersion) || requestVersion < 1) {
    throw storeError('audit_support_request_invalid');
  }
  const row = database.prepare(`
    SELECT request_digest, revision, status, record_json
    FROM vendor_audit_support_records WHERE request_id = ? AND request_version = ?
  `).get(requestId, requestVersion);
  if (!row) return null;
  const record = checkedRecord(parseCanonical(row.record_json, 'audit_support_record_invalid'));
  if (record.requestDigest !== row.request_digest || record.revision !== row.revision
      || record.status !== row.status) throw storeError('audit_support_record_invalid');
  return deepFreeze(record);
}

function readLatestRecord(database, requestId) {
  checkedUuid(requestId, 'audit_support_request_invalid');
  const row = database.prepare(`
    SELECT request_version FROM vendor_audit_support_records
    WHERE request_id = ? ORDER BY request_version DESC LIMIT 1
  `).get(requestId);
  return row ? readRecord(database, requestId, row.request_version) : null;
}

function requireRecord(database, binding) {
  const record = readRecord(database, binding.requestId, binding.requestVersion);
  const latest = readLatestRecord(database, binding.requestId);
  if (!record || record.requestDigest !== binding.requestDigest
      || latest.requestVersion !== record.requestVersion
      || latest.requestDigest !== record.requestDigest) {
    throw storeError('audit_support_request_not_current');
  }
  return record;
}

function insertOutbox(database, outbox) {
  database.prepare(`
    INSERT INTO vendor_audit_support_outbox
      (message_id, request_id, request_version, request_digest, artifact_digest,
       document_kind, document_json, status, attempts, next_attempt_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)
  `).run(outbox.messageId, outbox.requestId, outbox.requestVersion, outbox.requestDigest,
    outbox.artifactDigest, outbox.documentKind, canonical(outbox.document),
    outbox.createdAt, outbox.createdAt);
}

function claimOutbox(database, limit, now) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw storeError('audit_support_outbox_limit_invalid');
  }
  const suppliedMs = Date.parse(canonicalIso(now, 'audit_support_clock_invalid'));
  const nowMs = observeTrustedTime(database, suppliedMs);
  const trustedNow = new Date(nowMs).toISOString();
  database.prepare(`
    UPDATE vendor_audit_support_outbox
    SET status = 'blocked', claim_token = NULL, last_error_code = 'delivery_lease_expired'
    WHERE status = 'sending' AND next_attempt_at <= ? AND attempts >= ?
  `).run(trustedNow, MAX_OUTBOX_ATTEMPTS);
  database.prepare(`
    UPDATE vendor_audit_support_outbox SET status = 'pending', claim_token = NULL
    WHERE status = 'sending' AND next_attempt_at <= ? AND attempts < ?
  `).run(trustedNow, MAX_OUTBOX_ATTEMPTS);
  const rows = database.prepare(`
    SELECT message_id, request_digest, artifact_digest, document_kind, document_json, attempts
    FROM vendor_audit_support_outbox
    WHERE status = 'pending' AND next_attempt_at <= ? AND attempts < ?
    ORDER BY created_at, message_id LIMIT ?
  `).all(trustedNow, MAX_OUTBOX_ATTEMPTS, limit);
  return rows.map((row) => {
    if (sha256(row.document_json) !== row.artifact_digest) {
      throw storeError('audit_support_outbox_integrity_failed');
    }
    const claimToken = crypto.randomUUID();
    const leaseUntil = new Date(nowMs + OUTBOX_LEASE_MS).toISOString();
    const changed = database.prepare(`
      UPDATE vendor_audit_support_outbox
      SET status = 'sending', attempts = attempts + 1, next_attempt_at = ?, claim_token = ?
      WHERE message_id = ? AND status = 'pending'
    `).run(leaseUntil, claimToken, row.message_id).changes;
    if (changed !== 1) throw storeError('audit_support_outbox_conflict');
    return deepFreeze({
      messageId: row.message_id,
      requestDigest: row.request_digest,
      artifactDigest: row.artifact_digest,
      document: parseCanonical(row.document_json, 'audit_support_outbox_integrity_failed'),
      documentKind: row.document_kind,
      attempts: row.attempts + 1,
      claimToken,
    });
  });
}

function markOutboxDelivered(database, record, operation) {
  const evidence = acknowledgementEvidence(operation.receipt);
  const result = database.prepare(`
    UPDATE vendor_audit_support_outbox
    SET status = 'delivered', delivered_at = ?, acknowledgement_applied_at = ?,
      acknowledgement_digest = ?, acknowledgement_key_id = ?,
      last_error_code = NULL, claim_token = NULL
    WHERE message_id = ? AND artifact_digest = ?
      AND request_id = ? AND request_version = ? AND request_digest = ?
      AND status = 'sending' AND claim_token = ?
  `).run(operation.occurredAt, evidence.appliedAt, evidence.digest, evidence.keyId,
    operation.messageId, operation.artifactDigest, record.requestId, record.requestVersion,
    record.requestDigest, operation.claimToken);
  if (result.changes !== 1) throw storeError('audit_support_outbox_conflict');
}

function cancelOutbox(database, record) {
  database.prepare(`
    UPDATE vendor_audit_support_outbox
    SET status = 'cancelled', claim_token = NULL
    WHERE request_id = ? AND request_version = ? AND request_digest = ?
      AND status IN ('pending', 'sending', 'blocked')
  `).run(record.requestId, record.requestVersion, record.requestDigest);
}

function markOutboxRetry(database, messageId, artifactDigest, nextAt, errorCode, claimToken) {
  checkedUuid(messageId, 'audit_support_outbox_claim_invalid');
  checkedUuid(claimToken, 'audit_support_outbox_claim_invalid');
  checkedDigest(artifactDigest, 'audit_support_outbox_claim_invalid');
  canonicalIso(nextAt, 'audit_support_outbox_claim_invalid');
  if (!SAFE_CODE_RE.test(String(errorCode || ''))) {
    throw storeError('audit_support_outbox_error_invalid');
  }
  const row = database.prepare(`
    SELECT attempts FROM vendor_audit_support_outbox
    WHERE message_id = ? AND artifact_digest = ? AND status = 'sending' AND claim_token = ?
  `).get(messageId, artifactDigest, claimToken);
  if (!row) return false;
  const status = row.attempts >= MAX_OUTBOX_ATTEMPTS ? 'blocked' : 'pending';
  return database.prepare(`
    UPDATE vendor_audit_support_outbox
    SET status = ?, next_attempt_at = ?, last_error_code = ?, claim_token = NULL
    WHERE message_id = ? AND artifact_digest = ? AND status = 'sending' AND claim_token = ?
  `).run(status, nextAt, errorCode, messageId, artifactDigest, claimToken).changes === 1;
}

function verifyOutboxEvidence(database) {
  const rows = database.prepare(`
    SELECT message_id, request_id, request_version, request_digest, artifact_digest,
      document_kind, document_json, status, delivered_at, acknowledgement_applied_at,
      acknowledgement_digest, acknowledgement_key_id
    FROM vendor_audit_support_outbox
  `).all();
  for (const row of rows) {
    if (sha256(row.document_json) !== row.artifact_digest
        || !['pending', 'sending', 'delivered', 'cancelled', 'blocked'].includes(row.status)) {
      throw storeError('audit_support_outbox_integrity_failed');
    }
    const record = readRecord(database, row.request_id, row.request_version);
    if (!record || record.requestDigest !== row.request_digest) {
      throw storeError('audit_support_outbox_integrity_failed');
    }
    const cancellation = row.document_kind === CANCELLATION_KIND;
    const expectedDocument = cancellation ? record.cancellationArtifact : record.signedArtifact;
    if ((!cancellation && row.document_kind !== protocol.CHANNEL_KINDS.AUDIT_REQUEST)
        || expectedDocument === null || canonical(expectedDocument) !== row.document_json) {
      throw storeError('audit_support_outbox_integrity_failed');
    }
    const evidence = [
      row.delivered_at, row.acknowledgement_applied_at,
      row.acknowledgement_digest, row.acknowledgement_key_id,
    ];
    if (row.status !== 'delivered') {
      if (evidence.some((value) => value !== null)) {
        throw storeError('audit_support_outbox_integrity_failed');
      }
      continue;
    }
    if (evidence.some((value) => value === null)) {
      throw storeError('audit_support_outbox_integrity_failed');
    }
    const expected = cancellation ? {
      appliedAt: record.cancellationAppliedAt,
      deliveredAt: record.cancellationDeliveredAt,
      digest: record.cancellationAcknowledgementDigest,
      keyId: record.cancellationAcknowledgementKeyId,
    } : {
      appliedAt: record.deliveryAppliedAt,
      deliveredAt: record.deliveredAt,
      digest: record.deliveryAcknowledgementDigest,
      keyId: record.deliveryAcknowledgementKeyId,
    };
    if (row.delivered_at !== expected.deliveredAt
        || row.acknowledgement_applied_at !== expected.appliedAt
        || row.acknowledgement_digest !== expected.digest
        || row.acknowledgement_key_id !== expected.keyId) {
      throw storeError('audit_support_outbox_integrity_failed');
    }
  }
}

function appendAudit(database, rawEvent) {
  const body = checkedAuditEvent(rawEvent);
  const prior = database.prepare(`
    SELECT sequence, event_digest FROM vendor_audit_support_audit
    ORDER BY sequence DESC LIMIT 1
  `).get();
  const sequence = (prior?.sequence || 0) + 1;
  const previousDigest = prior?.event_digest || ZERO_DIGEST;
  const core = { schemaVersion: 1, sequence, previousDigest, ...body };
  const eventDigest = sha256(canonical(core));
  const event = { ...core, eventDigest };
  database.prepare(`
    INSERT INTO vendor_audit_support_audit
      (sequence, previous_digest, event_digest, event_json) VALUES (?, ?, ?, ?)
  `).run(sequence, previousDigest, eventDigest, canonical(event));
}

function verifyAudit(database) {
  const rows = database.prepare(`
    SELECT sequence, previous_digest, event_digest, event_json
    FROM vendor_audit_support_audit ORDER BY sequence
  `).all();
  const events = [];
  let previous = ZERO_DIGEST;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const event = parseCanonical(row.event_json, 'audit_support_audit_integrity_failed');
    const core = { ...event };
    delete core.eventDigest;
    if (row.sequence !== index + 1 || row.previous_digest !== previous
        || event.sequence !== row.sequence || event.previousDigest !== previous
        || event.eventDigest !== row.event_digest || sha256(canonical(core)) !== row.event_digest) {
      throw storeError('audit_support_audit_integrity_failed');
    }
    checkedAuditEvent({
      acknowledgementAppliedAt: event.acknowledgementAppliedAt,
      acknowledgementDigest: event.acknowledgementDigest,
      acknowledgementKeyId: event.acknowledgementKeyId,
      authorizationRef: event.authorizationRef,
      count: event.count,
      eventType: event.eventType,
      occurredAt: event.occurredAt,
      outcome: event.outcome,
      requestDigest: event.requestDigest,
      requestVersion: event.requestVersion,
      scopeDigest: event.scopeDigest,
    });
    events.push(deepFreeze(event));
    previous = row.event_digest;
  }
  return events;
}

function idempotentResult(database, key, digest) {
  const row = database.prepare(`
    SELECT operation_digest, result_json FROM vendor_audit_support_commands
    WHERE idempotency_key = ?
  `).get(key);
  if (!row) return null;
  if (row.operation_digest !== digest) throw storeError('audit_support_idempotency_conflict');
  return duplicate(parseCanonical(row.result_json, 'audit_support_command_invalid'));
}

function rememberCommand(database, key, digest, result) {
  database.prepare(`
    INSERT INTO vendor_audit_support_commands(idempotency_key, operation_digest, result_json)
    VALUES (?, ?, ?)
  `).run(key, digest, canonical(result));
}

function publicResult(record, duplicateValue) {
  return deepFreeze({
    duplicate: duplicateValue,
    requestDigest: record.requestDigest,
    requestId: record.requestId,
    requestVersion: record.requestVersion,
    status: record.status,
  });
}

function duplicate(result) { return deepFreeze({ ...result, duplicate: true }); }
function checkedRequestBinding(value, code) {
  checkedUuid(value.requestId, code);
  if (!Number.isSafeInteger(value.requestVersion) || value.requestVersion < 1) throw storeError(code);
  checkedDigest(value.requestDigest, code);
}
function checkedIdempotency(value) {
  if (!IDEMPOTENCY_RE.test(String(value || ''))) throw storeError('audit_support_idempotency_invalid');
}
function checkedDigest(value, code) {
  if (!SHA256_RE.test(String(value || ''))) throw storeError(code);
  return value;
}
function checkedUuid(value, code) {
  if (!UUID_RE.test(String(value || ''))) throw storeError(code);
  return value;
}
function canonicalIso(value, code) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw storeError(code);
  return value;
}
function checkedNullableIso(value, code) {
  if (value !== null) canonicalIso(value, code);
  return value;
}
function canonicalSignature(value, code) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw storeError(code);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== value) throw storeError(code);
  return value;
}
function clonePlain(value, code) {
  let serialized;
  try { serialized = JSON.stringify(value); }
  catch { throw storeError(code); }
  if (typeof serialized !== 'string' || Buffer.byteLength(serialized, 'utf8') > 2 * 1024 * 1024) {
    throw storeError(code);
  }
  return JSON.parse(serialized);
}
function parseCanonical(value, code) {
  let parsed;
  try { parsed = JSON.parse(value); } catch { throw storeError(code); }
  if (canonical(parsed) !== value) throw storeError(code);
  return parsed;
}
function canonical(value) { return protocol.canonicalJson(value); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function acknowledgementEvidence(receipt) {
  return Object.freeze({
    appliedAt: receipt.receivedAt,
    digest: sha256(canonical(receipt)),
    keyId: receipt.acknowledgementKeyId,
  });
}
function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}
function withTransaction(database, callback) {
  database.exec('BEGIN IMMEDIATE');
  try {
    verifyAudit(database);
    verifyOutboxEvidence(database);
    const result = callback();
    verifyAudit(database);
    verifyOutboxEvidence(database);
    database.exec('COMMIT');
    return result;
  } catch (error) {
    try { database.exec('ROLLBACK'); } catch {}
    throw error;
  }
}
function assertOpen(closed) { if (closed) throw storeError('audit_support_store_closed'); }
function isReferenceVendorAuditSupportStore(value) {
  return Boolean(value && value[STORE_BRAND] === true);
}

function checkedAcknowledgementRegistry(value) {
  if (!isAuditAcknowledgementRegistry(value)) {
    throw storeError('audit_support_acknowledgement_registry_required');
  }
  return value;
}

function storeError(code) {
  const error = new Error('vendor audit support storage rejected');
  error.code = code;
  return error;
}

function assertReferenceRuntime() {
  if (process.env.NODE_ENV === 'production') {
    throw storeError('audit_support_reference_runtime_forbidden');
  }
}

module.exports = {
  isReferenceVendorAuditSupportStore,
  openProductionVendorAuditSupportStore,
  openReferenceVendorAuditSupportSqlite,
};
