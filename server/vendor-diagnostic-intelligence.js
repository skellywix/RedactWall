'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const {
  KEY_PURPOSES,
  validPurposeKeyId,
} = require('./vendor-signed-artifact');

const SCHEMA_VERSION = 1;
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_EVENT_AGE_MS = DAY_MS;
const TOMBSTONE_RETENTION_MS = MAX_EVENT_AGE_MS + MAX_CLOCK_SKEW_MS;
const MIN_RETENTION_DAYS = 1;
const MAX_RETENTION_DAYS = 90;
const IDEMPOTENCY_HORIZON_MS = MAX_RETENTION_DAYS * DAY_MS + TOMBSTONE_RETENTION_MS;
const KEY_RETENTION_MARGIN_MS = 7 * DAY_MS;
const MAX_CAPABILITY_LIFETIME_MS = 15 * 60 * 1000;
const MAX_STEP_UP_AGE_MS = 5 * 60 * 1000;
const MAX_DESTRUCTIVE_FORWARD_JUMP_MS = 7 * DAY_MS;
const DELETION_LEASE_MS = 15 * 60 * 1000;
const MAX_QUERY_LIMIT = 200;
const DEFAULT_DAILY_EVENT_LIMIT = 100_000;
const MIN_DAILY_EVENT_LIMIT = 100;
const MAX_DAILY_EVENT_LIMIT = 1_000_000;
const MAX_QUERY_RANGE_MS = MAX_RETENTION_DAYS * DAY_MS;
const MAX_CUSTOMER_SCOPE = 1_000;
const MAX_DOCUMENT_DEPTH = 16;
const MAX_DOCUMENT_NODES = 5_000;
const MAX_DOCUMENT_BYTES = 512 * 1024;
const MAX_STRING_BYTES = 16 * 1024;
const MAX_ISO_TIME_MS = 8_640_000_000_000_000 - IDEMPOTENCY_HORIZON_MS;
const STORAGE_CONTRACT_VERSION = 'vendor-diagnostic-serializable-v2';

const RECORD_DOMAIN = 'redactwall.vendor-diagnostic-record.v2';
const TIME_DOMAIN = 'redactwall.vendor-diagnostic-time.v1';
const QUOTA_DOMAIN = 'redactwall.vendor-diagnostic-quota.v1';
const CONSENT_DOMAIN = 'redactwall.vendor-diagnostic-consent.v1';
const AUTHORIZATION_DOMAIN = 'redactwall.vendor-diagnostic-authorization.v1';
const CAPABILITY_DOMAIN = 'redactwall.vendor-diagnostic-capability.v1';
const OWNER_AUTH_ASSERTION_DOMAIN = 'redactwall.owner-auth-assertion.v1';
const CAPABILITY_CLAIM_DOMAIN = 'redactwall.vendor-diagnostic-capability-claim.v1';
const CUSTOMER_GRANT_DOMAIN = 'redactwall.customer-diagnostic-grant.v1';
const AUDIT_DOMAIN = 'redactwall.vendor-diagnostic-audit.v1';
const CURSOR_DOMAIN = 'redactwall.vendor-diagnostic-cursor.v1';
const DELETION_INTENT_DOMAIN = 'redactwall.customer-diagnostic-deletion-intent.v1';
const DELETION_JOB_DOMAIN = 'redactwall.vendor-diagnostic-deletion-job.v1';
const DELETION_COMPLETION_DOMAIN = 'redactwall.vendor-diagnostic-deletion-completion.v1';
const DELETION_RESERVATION_DOMAIN = 'redactwall.vendor-diagnostic-deletion-reservation.v1';
const ACCESS_MANIFEST_DOMAIN = 'redactwall.vendor-diagnostic-access-manifest.v1';
const CUSTOMER_ACCESS_MANIFEST_DOMAIN = 'redactwall.vendor-diagnostic-customer-access-manifest.v1';
const ACCESS_EVIDENCE_DOMAIN = 'redactwall.vendor-diagnostic-access-evidence.v1';
const STAFF_REFERENCE_DOMAIN = 'redactwall.vendor-diagnostic-staff-reference.v1';
const AUTHORITY_PROBE_DOMAIN = 'redactwall.vendor-diagnostic-authority-probe.v1';
const SERVICE_ERROR = Symbol('vendor-diagnostic-service-error');
const SERVICE_ERROR_MESSAGE = 'vendor diagnostic intelligence operation rejected';
const DUPLICATE_RECEIPT = Object.freeze({ accepted: true, duplicate: true });
const CLOCK_RECOVERY_REASONS = new Set([
  'database_clock_corrected', 'disaster_recovery', 'operator_time_attestation',
]);
const DELETION_REASONS = new Set([
  'customer_request', 'contract_termination', 'privacy_request', 'retention_exception',
]);
const TERMINAL_DELETION_STATUSES = new Set([
  'completed', 'rejected', 'canceled', 'expired', 'failed',
]);
const VENDOR_TERMINAL_DELETION_STATUSES = new Set(['rejected', 'canceled', 'failed']);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const KEY_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,95}$/;
const CURSOR_RE = /^[A-Za-z0-9_-]{1,65536}$/;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const COMPONENTS = new Set([
  'browser', 'endpoint', 'mcp', 'gateway', 'connector', 'control_plane',
  'storage', 'database', 'policy', 'catalog', 'licensing', 'updater',
]);
const CODES = new Set([
  'CONNECTOR_AUTH_FAILED', 'CONNECTOR_TIMEOUT', 'CONNECTOR_PROTOCOL_REJECTED',
  'ENTITLEMENT_REJECTED', 'POLICY_REJECTED', 'CATALOG_REJECTED',
  'AUDIT_INTEGRITY_FAILED', 'STORAGE_DEGRADED', 'SENSOR_STALE',
  'VERSION_GAP', 'QUEUE_BACKLOG', 'RATE_LIMITED',
]);
const SEVERITIES = new Set(['info', 'warning', 'error', 'critical']);
const OUTCOMES = new Set(['healthy', 'degraded', 'retrying', 'blocked', 'recovered']);
const CAPABILITY_PURPOSES = new Set([
  'diagnostic:ingest', 'diagnostics:view', 'diagnostics:export',
  'diagnostics:compact', 'diagnostics:compact:global',
  'diagnostics:delete:preview', 'diagnostics:delete:execute',
  'diagnostics:delete:approve',
  'diagnostics:clock:recover',
]);
const PRINCIPAL_TYPES = new Set(['connector', 'vendor', 'scheduler']);
const CREDENTIAL_PURPOSES = new Set([
  'connector_credential', 'owner_session', 'scheduler_job',
]);
const AUDIT_ACTIONS = new Set([
  'diagnostic_authorization_state', 'diagnostic_capability_used',
  'diagnostic_access_replayed',
  'diagnostic_clock_advanced', 'diagnostic_compacted', 'diagnostic_consent_state',
  'diagnostic_clock_recovered',
  'diagnostic_customer_grant_state',
  'diagnostic_ingested', 'diagnostic_quota_claimed', 'diagnostic_replay_index_deleted',
  'diagnostic_replay_indexed', 'diagnostic_tombstone_deleted',
  'diagnostics_exported', 'diagnostics_viewed',
  'diagnostics_export_completed',
  'diagnostic_deletion_state', 'diagnostic_deletion_batch',
  'diagnostic_deletion_completed',
  'diagnostic_deletion_reservation_released',
  'diagnostic_store_scope_restored',
]);
const AUTHORITY_FINGERPRINT_KEYS = Object.freeze([
  'diagnosticAccess', 'diagnosticAudit', 'diagnosticCursor',
  'diagnosticCustomerGrant', 'diagnosticIntegrity', 'diagnosticOwnerAuth',
  'diagnosticWitness',
  'acknowledgement_credential', 'audit_request', 'catalog_distribution',
  'catalog_global', 'command_idempotency', 'diagnostic_credential',
  'diagnostic_integrity', 'entitlement', 'heartbeat_credential',
  'license_registry_integrity', 'lifecycle', 'offline_license',
  'online_verdict', 'owner_attestation', 'pagination_cursor', 'platform_audit',
  'policy', 'recovery', 'shadow_candidate_credential', 'witness_integrity',
]);

const COMMON_METHODS = Object.freeze([
  'appendAudit', 'claimDiagnosticCapability', 'compareAndSwapTimeHighWater',
  'readAuditDescriptor', 'readDiagnosticAuthorizationState',
  'readDiagnosticCapabilityClaim', 'readLatestCapabilityAudit',
  'readLatestStateAudit', 'readStateRevisionHighWater',
  'readTimeHighWater', 'readTrustedDatabaseTime',
]);
const INGEST_METHODS = Object.freeze(COMMON_METHODS.concat([
  'compareAndSwapDiagnosticQuota', 'findDiagnosticClaim', 'insertDiagnostic',
  'readCustomerDiagnosticGrant', 'readDiagnosticConsent', 'readDiagnosticQuota',
  'readLatestClaimAudit',
]));
const SEARCH_METHODS = Object.freeze(COMMON_METHODS.concat([
  'beginDiagnosticSearchSnapshot', 'insertDiagnosticAccessEvidence',
  'readDiagnosticAccessEvidence', 'readDiagnosticAccessRecord', 'searchDiagnostics',
]));
const COMPACT_METHODS = Object.freeze(COMMON_METHODS.concat([
  'compareAndSwapDiagnosticDeletionJob', 'compareAndSwapDiagnosticDeletionReservation',
  'deleteDiagnosticReplayIndex', 'listExpiredDiagnosticReplayIndexes',
  'listExpiredDiagnosticDeletionReservations', 'listExpiredDiagnostics',
  'listExpiredDiagnosticTombstones', 'readDiagnosticDeletionJob',
  'readDiagnosticDeletionReservation',
  'replaceDiagnosticTombstoneWithReplay', 'replaceDiagnosticWithTombstone',
]));
const RECOVERY_METHODS = COMMON_METHODS;
const DELETION_INTENT_METHODS = Object.freeze(COMMON_METHODS.concat([
  'compareAndSwapDiagnosticDeletionJob', 'readCustomerDiagnosticGrant',
  'compareAndSwapDiagnosticDeletionReservation', 'readDiagnosticDeletionJob',
  'readDiagnosticDeletionReservation',
]));
const DELETION_PREVIEW_METHODS = Object.freeze(COMMON_METHODS.concat([
  'compareAndSwapDiagnosticDeletionJob', 'previewDiagnosticDeletion',
  'readDiagnosticDeletionJob', 'readDiagnosticDeletionReservation',
]));
const DELETION_APPROVAL_METHODS = Object.freeze(COMMON_METHODS.concat([
  'compareAndSwapDiagnosticDeletionJob', 'readDiagnosticDeletionJob',
  'readDiagnosticDeletionReservation',
]));
const DELETION_EXECUTION_METHODS = Object.freeze(COMMON_METHODS.concat([
  'compareAndSwapDiagnosticDeletionJob', 'deleteDiagnosticBatch',
  'compareAndSwapDiagnosticDeletionReservation', 'listDiagnosticDeletionBatch',
  'readDiagnosticDeletionJob', 'readDiagnosticDeletionReservation',
]));
const DELETION_TERMINATION_METHODS = Object.freeze(COMMON_METHODS.concat([
  'compareAndSwapDiagnosticDeletionJob', 'compareAndSwapDiagnosticDeletionReservation',
  'readDiagnosticDeletionJob', 'readDiagnosticDeletionReservation',
]));

/*
 * Production adapters must implement the named contract with one awaited
 * callback, serializable isolation, atomic rollback on every callback/result
 * failure, exact result echoes, durable append-only audits, and no omitted
 * cursor or audit segments. The reference and durable SQLite adapters are the
 * executable contract. Postgres remains disabled until an adapter proves the
 * same transaction, checkpoint, pending-witness, and exact-CAS guarantees.
 */
function createVendorDiagnosticIntelligence(options = {}) {
  assertReferenceRuntime();
  let context;
  try { context = checkedOptions(options); }
  catch (error) { throw normalizeError(error); }
  return Object.freeze({
    ingest: (command) => guarded(() => ingest(context, command)),
    search: (command) => guarded(() => search(context, command)),
    compact: (command) => guarded(() => compact(context, command)),
    recoverClock: (command) => guarded(() => recoverClock(context, command)),
    submitDeletionIntent: (command) => guarded(() => submitDeletionIntent(context, command)),
    previewDeletion: (command) => guarded(() => previewDeletion(context, command)),
    approveDeletion: (command) => guarded(() => approveDeletion(context, command)),
    executeDeletion: (command) => guarded(() => executeDeletion(context, command)),
    terminateDeletion: (command) => guarded(() => terminateDeletion(context, command)),
  });
}

async function ingest(context, commandValue) {
  const command = ingestCommand(commandValue);
  const payload = parseDiagnostic(command.payload);
  return transact(context.storage, INGEST_METHODS, async (tx) => {
    const nowMs = await trustedNow(context, tx);
    const capability = await authorizeCapability(
      context, tx, command.capability, ['diagnostic:ingest'], nowMs,
    );
    assertIngestScope(payload, capability);
    const consent = await currentConsent(context, tx, payload, nowMs);
    const existing = await tx.findDiagnosticClaim(scopeMessage(payload));
    if (existing) return duplicateDisposition(context, tx, existing, payload);
    assertEventTime(payload, nowMs);
    await assertInsertAuditDisposition(context, tx, payload);
    await claimIngestQuota(context, tx, payload, nowMs);
    const record = createEventRecord(context, payload, capability, consent, nowMs);
    await appendExactAudit(context, tx, recordAudit(record));
    assertExactValue(await tx.insertDiagnostic(record), record, 'diagnostic_insert_invalid');
    return publicIngest(record);
  });
}

async function search(context, commandValue) {
  const command = searchCommand(commandValue);
  return transact(context.storage, SEARCH_METHODS, async (tx) => {
    const nowMs = await trustedNow(context, tx);
    const expected = command.mode === 'export' ? ['diagnostics:export'] : ['diagnostics:view'];
    const capability = await validateCapabilityAuthorization(
      context, tx, command.capability, expected, nowMs,
    );
    const requestDigest = accessRequestDigest(command, capability);
    const existingEvidence = await tx.readDiagnosticAccessEvidence(requestDigest);
    if (existingEvidence !== null) {
      if (await verifiedCapabilityClaim(context, tx, capability) === null) {
        throw serviceError('diagnostic_access_evidence_invalid');
      }
      const response = await verifiedAccessEvidence(
        context, tx, existingEvidence, requestDigest, capability, nowMs,
      );
      await appendExactAudit(context, tx, accessReplayAudit(
        context, capability, existingEvidence, response.accessManifest, nowMs,
      ));
      return response;
    }
    await claimCapabilityUse(context, tx, capability, nowMs);
    const baseQuery = boundedQuery(command, capability, nowMs);
    const cursor = command.cursor === null
      ? null : verifiedCursor(context, command.cursor, command, capability, baseQuery, nowMs);
    const snapshotHighWater = cursor
      ? cursor.snapshotHighWater
      : checkedSnapshotHighWater(await tx.beginDiagnosticSearchSnapshot(baseQuery));
    const query = deepFreeze({
      ...baseQuery,
      after: cursor ? {
        receivedAt: cursor.lastReceivedAt,
        messageId: cursor.lastMessageId,
      } : null,
      limit: command.limit + 1,
      snapshotHighWater,
    });
    const result = searchResult(await tx.searchDiagnostics(query), command.limit + 1);
    const verified = await verifiedSearchRecords(context, tx, result.items, query, nowMs);
    assertStrictSearchOrder(verified, query);
    const records = verified.slice(0, command.limit);
    const hasMore = verified.length > command.limit;
    const pageAuditEventId = randomId(context);
    const accessManifest = createAccessManifest(
      context, command, capability, cursor, snapshotHighWater, records, !hasMore,
      pageAuditEventId, nowMs,
    );
    const nextCursor = hasMore ? createCursor(
      context, command, capability, baseQuery, snapshotHighWater,
      records.at(-1), accessManifest, nowMs,
    ) : null;
    const pageAudit = await appendExactAudit(context, tx, searchAudit(
      command, capability, query, records, nextCursor, accessManifest, pageAuditEventId, nowMs,
    ));
    let completionAudit = null;
    if (command.mode === 'export' && nextCursor === null) {
      completionAudit = await appendExactAudit(context, tx, exportCompletionAudit(
        context, command, capability, query, records, accessManifest, nowMs,
      ));
    }
    const response = deepFreeze({
      items: records.map(publicEvent),
      nextCursor,
      accessManifest,
    });
    const evidence = createAccessEvidence(
      context, requestDigest, capability, response, pageAudit, completionAudit, nowMs,
    );
    assertExactValue(
      await tx.insertDiagnosticAccessEvidence(requestDigest, evidence), evidence,
      'diagnostic_access_evidence_invalid',
    );
    return response;
  });
}

async function compact(context, commandValue) {
  const command = compactCommand(commandValue);
  return transact(context.storage, COMPACT_METHODS, async (tx) => {
    const nowMs = await trustedNow(context, tx, 'destructive');
    const capability = await authorizeCapability(context, tx, command.capability, [
      'diagnostics:compact', 'diagnostics:compact:global',
    ], nowMs);
    const allowedCustomerIds = compactionScope(capability);
    await releaseExpiredDeletionLeases(context, tx, nowMs, command.limit, allowedCustomerIds);
    const compacted = await compactEvents(context, tx, nowMs, command.limit, allowedCustomerIds);
    const tombstonesDeleted = await indexTombstones(
      context, tx, nowMs, command.limit, allowedCustomerIds,
    );
    const replayIndexesDeleted = await deleteReplayIndexes(
      context, tx, nowMs, command.limit, allowedCustomerIds,
    );
    return Object.freeze({ compacted, tombstonesDeleted, replayIndexesDeleted });
  });
}

async function submitDeletionIntent(context, commandValue) {
  const command = deletionIntentCommand(commandValue);
  return transact(context.storage, DELETION_INTENT_METHODS, async (tx) => {
    const nowMs = await trustedNow(context, tx, 'destructive');
    const intent = verifiedDeletionIntent(context, command.intent, nowMs);
    const grant = await currentDeletionGrant(context, tx, intent, nowMs);
    assertDeletionGrantBinding(intent, grant);
    const raw = await tx.readDiagnosticDeletionJob(intent.intentId);
    const reservationValue = await tx.readDiagnosticDeletionReservation(scope(intent));
    const reservation = reservationValue === null
      ? null : verifiedDeletionReservation(context, reservationValue);
    if (raw !== null) {
      const existing = await verifiedDeletionJob(context, tx, raw);
      if (existing.intentDigest !== intent.recordDigest || reservation === null
          || reservation.active !== !TERMINAL_DELETION_STATUSES.has(existing.status)
          || reservation.jobId !== existing.jobId
          || reservation.intentDigest !== existing.intentDigest) {
        throw serviceError('diagnostic_deletion_conflict');
      }
      return deletionIntentReceipt(existing);
    }
    if (reservation && reservation.active) throw serviceError('diagnostic_deletion_scope_reserved');
    await assertNoLatestStateAudit(
      tx, deletionStateAuditQuery(intent), 'diagnostic_deletion_integrity_failed',
    );
    const job = initialDeletionJob(context, intent, grant, nowMs);
    const nextReservation = createDeletionReservation(
      context, reservation, job, true, nowMs, null,
    );
    await appendExactAudit(context, tx, deletionStateAudit(job));
    assertExactValue(await tx.compareAndSwapDiagnosticDeletionReservation({
      customerId: job.customerId,
      deploymentId: job.deploymentId,
      expectedRecordDigest: reservation ? reservation.recordDigest : null,
      nextRecord: nextReservation,
    }), nextReservation, 'diagnostic_deletion_scope_reserved');
    assertExactValue(await tx.compareAndSwapDiagnosticDeletionJob({
      jobId: job.jobId, expectedRecordDigest: null, nextRecord: job,
    }), job, 'diagnostic_deletion_conflict');
    return deletionIntentReceipt(job);
  });
}

async function previewDeletion(context, commandValue) {
  const command = deletionVendorCommand(commandValue, false);
  return transact(context.storage, DELETION_PREVIEW_METHODS, async (tx) => {
    const nowMs = await trustedNow(context, tx, 'destructive');
    let current = await requiredDeletionJob(context, tx, command.jobId);
    assertDeletionStatus(current, ['requested']);
    const capability = await authorizeCapability(
      context, tx, command.capability, ['diagnostics:delete:preview'], nowMs,
    );
    assertDeletionCapability(current, capability);
    const lease = await renewOrExpireDeletionLease(context, tx, current, nowMs);
    if (lease.expired) return deletionProgress(lease.job);
    current = lease.job;
    const preview = deletionPreview(await tx.previewDiagnosticDeletion({
      customerId: current.customerId,
      deploymentId: current.deploymentId,
    }));
    const next = advanceDeletionJob(context, current, {
      status: 'previewed',
      previewCount: preview.count,
      snapshotHighWater: preview.snapshotHighWater,
      previewDigest: digest(preview),
      supportCaseId: capability.supportCaseId,
    }, nowMs);
    await storeDeletionState(context, tx, current, next);
    return deepFreeze({
      jobId: next.jobId, count: next.previewCount, previewDigest: next.previewDigest,
    });
  });
}

async function approveDeletion(context, commandValue) {
  const command = deletionVendorCommand(commandValue, false);
  return transact(context.storage, DELETION_APPROVAL_METHODS, async (tx) => {
    const nowMs = await trustedNow(context, tx, 'destructive');
    let current = await requiredDeletionJob(context, tx, command.jobId);
    assertDeletionStatus(current, ['previewed']);
    const capability = await authorizeCapability(
      context, tx, command.capability, ['diagnostics:delete:approve'], nowMs,
    );
    assertDeletionCapability(current, capability);
    const lease = await renewOrExpireDeletionLease(context, tx, current, nowMs);
    if (lease.expired) return deletionProgress(lease.job);
    current = lease.job;
    if (current.supportCaseId !== null && capability.supportCaseId !== current.supportCaseId) {
      throw serviceError('diagnostic_deletion_approval_invalid');
    }
    const next = advanceDeletionJob(context, current, {
      status: 'approved',
      approvalId: capability.approvalId,
      supportCaseId: capability.supportCaseId,
    }, nowMs);
    await storeDeletionState(context, tx, current, next);
    return deepFreeze({ approved: true, jobId: next.jobId, revision: next.revision });
  });
}

async function executeDeletion(context, commandValue) {
  const command = deletionVendorCommand(commandValue, true);
  return transact(context.storage, DELETION_EXECUTION_METHODS, async (tx) => {
    const nowMs = await trustedNow(context, tx, 'destructive');
    let current = await requiredDeletionJob(context, tx, command.jobId);
    assertDeletionStatus(current, ['approved', 'running']);
    const capability = await authorizeCapability(
      context, tx, command.capability, ['diagnostics:delete:execute'], nowMs,
    );
    assertDeletionCapability(current, capability);
    const lease = await renewOrExpireDeletionLease(context, tx, current, nowMs);
    if (lease.expired) return deletionProgress(lease.job);
    current = lease.job;
    if (capability.approvalId !== current.approvalId
        || capability.supportCaseId !== current.supportCaseId) {
      throw serviceError('diagnostic_deletion_approval_invalid');
    }
    const batchQuery = {
      jobId: current.jobId,
      customerId: current.customerId,
      deploymentId: current.deploymentId,
      snapshotHighWater: current.snapshotHighWater,
      after: current.nextAfter,
      limit: command.limit + 1,
      expectedJobDigest: current.recordDigest,
    };
    const candidates = boundedList(
      await tx.listDiagnosticDeletionBatch(batchQuery),
      command.limit + 1, 'diagnostic_deletion_batch_invalid',
    );
    const verified = [];
    for (const value of candidates) verified.push(await verifiedRecord(context, tx, value));
    assertDeletionCandidates(current, verified);
    const selected = verified.slice(0, command.limit);
    const batch = deepFreeze({
      deleted: selected.map(recordPoint),
      done: verified.length <= command.limit,
    });
    assertExactValue(await tx.deleteDiagnosticBatch({
      ...batchQuery,
      limit: command.limit,
      records: selected,
      done: batch.done,
    }), batch, 'diagnostic_deletion_batch_invalid');
    const next = completedDeletionJob(
      context, current, batch, capability, nowMs,
    );
    await appendExactAudit(context, tx, deletionBatchAudit(
      context, current, next, batch, nowMs,
    ));
    if (next.status === 'completed') {
      await appendExactAudit(context, tx, deletionCompletionAudit(context, next));
      const currentReservation = verifiedDeletionReservation(
        context, await tx.readDiagnosticDeletionReservation(scope(current)),
      );
      await releaseDeletionReservation(
        context, tx, currentReservation, next, 'completed', nowMs,
      );
    }
    await storeDeletionState(context, tx, current, next);
    return deletionProgress(next);
  });
}

async function terminateDeletion(context, commandValue) {
  const command = deletionTerminationCommand(commandValue);
  return transact(context.storage, DELETION_TERMINATION_METHODS, async (tx) => {
    const nowMs = await trustedNow(context, tx, 'destructive');
    const current = await requiredDeletionJob(context, tx, command.jobId);
    assertDeletionStatus(current, ['requested', 'previewed', 'approved', 'running']);
    const capability = await authorizeCapability(
      context, tx, command.capability, ['diagnostics:delete:approve'], nowMs,
    );
    assertDeletionCapability(current, capability);
    const next = advanceDeletionJob(context, current, {
      status: command.status,
      terminalReasonCode: `vendor_${command.status}`,
    }, nowMs);
    await storeDeletionState(context, tx, current, next);
    const reservation = verifiedDeletionReservation(
      context, await tx.readDiagnosticDeletionReservation(scope(current)),
    );
    await releaseDeletionReservation(context, tx, reservation, next, command.status, nowMs);
    return deletionProgress(next);
  });
}

async function compactEvents(context, tx, nowMs, limit, allowedCustomerIds) {
  const values = boundedList(await tx.listExpiredDiagnostics({
    nowMs, limit, allowedCustomerIds,
  }), limit, 'diagnostic_compaction_invalid');
  let count = 0;
  for (const value of values) {
    const record = await verifiedRecord(context, tx, value, 'event');
    assertCompactionRecord(record, allowedCustomerIds, nowMs, 'expiresAt');
    const tombstone = createTombstone(context, record, nowMs);
    await appendExactAudit(context, tx, recordAudit(tombstone));
    assertExactValue(
      await tx.replaceDiagnosticWithTombstone({ current: record, next: tombstone }),
      tombstone, 'compaction_conflict',
    );
    count += 1;
  }
  return count;
}

async function indexTombstones(context, tx, nowMs, limit, allowedCustomerIds) {
  const values = boundedList(await tx.listExpiredDiagnosticTombstones({
    nowMs, limit, allowedCustomerIds,
  }), limit, 'diagnostic_compaction_invalid');
  let count = 0;
  for (const value of values) {
    const record = await verifiedRecord(context, tx, value, 'tombstone');
    assertCompactionRecord(record, allowedCustomerIds, nowMs, 'deleteAfter');
    const replay = createReplayIndex(context, record, nowMs);
    await appendExactAudit(context, tx, deletionAudit(context, record, nowMs));
    await appendExactAudit(context, tx, recordAudit(replay));
    assertExactValue(
      await tx.replaceDiagnosticTombstoneWithReplay({ current: record, next: replay }),
      replay, 'compaction_conflict',
    );
    count += 1;
  }
  return count;
}

async function deleteReplayIndexes(context, tx, nowMs, limit, allowedCustomerIds) {
  const values = boundedList(await tx.listExpiredDiagnosticReplayIndexes({
    nowMs, limit, allowedCustomerIds,
  }), limit, 'diagnostic_compaction_invalid');
  let count = 0;
  for (const value of values) {
    const record = await verifiedRecord(context, tx, value, 'replay');
    assertCompactionRecord(record, allowedCustomerIds, nowMs, 'idempotencyUntil');
    await appendExactAudit(context, tx, replayDeletionAudit(context, record, nowMs));
    assertExactValue(
      await tx.deleteDiagnosticReplayIndex(record), record, 'compaction_conflict',
    );
    count += 1;
  }
  return count;
}

function assertCompactionRecord(record, allowedCustomerIds, nowMs, timeField) {
  if (!customerAllowed(record.customerId, allowedCustomerIds)) {
    throw serviceError('diagnostic_customer_scope_denied');
  }
  if (Date.parse(record[timeField]) > nowMs) throw serviceError('compaction_scope_invalid');
}

function checkedOptions(options) {
  const configuration = dependencyConfiguration(options);
  const storage = configuration.storage;
  const storageContractVersion = storage && storage.contractVersion;
  const storageTransaction = storage && storage.transaction;
  if (storageContractVersion !== STORAGE_CONTRACT_VERSION
      || typeof storageTransaction !== 'function') throw serviceError('storage_invalid');
  const storageAdapter = Object.freeze({ transaction: storageTransaction.bind(storage) });
  const fingerprints = checkedFingerprints(configuration.authorityFingerprints);
  const integrityAuthority = checkedAuthority(
    configuration.integrityAuthority, fingerprints.diagnosticIntegrity, RECORD_DOMAIN,
    KEY_PURPOSES.DIAGNOSTIC_INTEGRITY,
  );
  const accessAuthority = checkedAuthority(
    configuration.accessAuthority, fingerprints.diagnosticAccess, CAPABILITY_DOMAIN,
  );
  const ownerAuthAuthority = checkedAuthority(
    configuration.ownerAuthAuthority,
    fingerprints.diagnosticOwnerAuth,
    OWNER_AUTH_ASSERTION_DOMAIN,
  );
  const auditAuthority = checkedAuthority(
    configuration.auditAuthority, fingerprints.diagnosticAudit, AUDIT_DOMAIN,
  );
  const customerGrantAuthority = checkedAuthority(
    configuration.customerGrantAuthority,
    fingerprints.diagnosticCustomerGrant,
    CUSTOMER_GRANT_DOMAIN,
  );
  const cursorAuthority = checkedAuthority(
    configuration.cursorAuthority, fingerprints.diagnosticCursor, CURSOR_DOMAIN,
  );
  const deletionIntentKeyRegistry = checkedDeletionIntentKeyRegistry(
    configuration.deletionIntentKeyRegistry,
  );
  if (typeof configuration.currentPrincipal !== 'function'
      || (configuration.randomUUID !== undefined && typeof configuration.randomUUID !== 'function')) {
    throw serviceError('diagnostic_configuration_invalid');
  }
  return Object.freeze({
    storage: storageAdapter,
    integrityAuthority,
    accessAuthority,
    ownerAuthAuthority,
    auditAuthority,
    customerGrantAuthority,
    cursorAuthority,
    deletionIntentKeyRegistry,
    currentPrincipal: configuration.currentPrincipal,
    retentionDays: boundedInteger(
      configuration.retentionDays === undefined ? 30 : configuration.retentionDays,
      MIN_RETENTION_DAYS, MAX_RETENTION_DAYS, 'retention_invalid',
    ),
    dailyEventLimit: boundedInteger(
      configuration.dailyEventLimit === undefined
        ? DEFAULT_DAILY_EVENT_LIMIT : configuration.dailyEventLimit,
      MIN_DAILY_EVENT_LIMIT, MAX_DAILY_EVENT_LIMIT, 'diagnostic_quota_invalid',
    ),
    randomUUID: configuration.randomUUID || crypto.randomUUID,
  });
}

function dependencyConfiguration(value) {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw serviceError('diagnostic_configuration_invalid');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set([
    'storage', 'integrityAuthority', 'accessAuthority', 'authorityFingerprints',
    'auditAuthority', 'customerGrantAuthority', 'cursorAuthority', 'currentPrincipal',
    'deletionIntentKeyRegistry', 'ownerAuthAuthority',
    'retentionDays', 'dailyEventLimit', 'randomUUID',
  ]);
  if (symbolKeys(descriptors).length
      || Object.keys(descriptors).some((key) => !allowed.has(key)
        || !dataDescriptor(descriptors[key], true))) {
    throw serviceError('diagnostic_configuration_invalid');
  }
  const configuration = {};
  for (const [key, descriptor] of Object.entries(descriptors)) configuration[key] = descriptor.value;
  return configuration;
}

function checkedDeletionIntentKeyRegistry(value) {
  if (!value || typeof value !== 'object' || typeof value.verify !== 'function'
      || typeof value.manifestDigest !== 'string' || !hexDigest(value.manifestDigest)
      || typeof value.sign === 'function') {
    throw serviceError('deletion_intent_key_registry_invalid');
  }
  return Object.freeze({
    manifestDigest: value.manifestDigest,
    verify: value.verify.bind(value),
  });
}

function checkedFingerprints(value) {
  const fingerprints = plainSnapshot(value, 'authority_fingerprints_invalid');
  assertExactKeys(fingerprints, AUTHORITY_FINGERPRINT_KEYS, 'authority_fingerprints_invalid');
  const distinctKeys = AUTHORITY_FINGERPRINT_KEYS.filter(
    (key) => key !== 'diagnostic_integrity',
  );
  const values = distinctKeys.map((key) => fingerprints[key]);
  if (fingerprints.diagnosticIntegrity !== fingerprints.diagnostic_integrity
      || values.some((item) => !hexDigest(item))
      || new Set(values).size !== values.length) {
    throw serviceError('authority_fingerprints_invalid');
  }
  return Object.freeze(fingerprints);
}

function checkedAuthority(value, expectedFingerprint, probeDomain, purpose = null) {
  const sign = value && value.sign;
  const verify = value && value.verify;
  const keyId = value && value.keyId;
  const fingerprint = value && value.fingerprint;
  if (typeof sign !== 'function' || typeof verify !== 'function'
      || typeof keyId !== 'string' || !KEY_ID_RE.test(keyId)
      || (purpose !== null && !validPurposeKeyId(keyId, purpose))
      || fingerprint !== expectedFingerprint) {
    throw serviceError('integrity_authority_invalid');
  }
  const authority = Object.freeze({
    keyId,
    fingerprint,
    sign: sign.bind(value),
    verify: verify.bind(value),
  });
  proveAuthority(authority, probeDomain);
  return authority;
}

function proveAuthority(authority, probeDomain) {
  const message = crypto.randomBytes(32).toString('base64');
  let proof;
  try {
    proof = checkedProof(authority.sign(AUTHORITY_PROBE_DOMAIN, message), authority.keyId);
    if (authority.verify(AUTHORITY_PROBE_DOMAIN, message, proof) !== true
        || authority.verify(AUTHORITY_PROBE_DOMAIN, `${message}.altered`, proof) !== false
        || authority.verify(`${probeDomain}.altered`, message, proof) !== false
        || authority.verify(AUTHORITY_PROBE_DOMAIN, message, {
          ...proof, keyId: alternateKeyId(authority.keyId),
        }) !== false) throw new Error('invalid authority behavior');
  } catch { throw serviceError('integrity_authority_invalid'); }
}

function alternateKeyId(current) { return current === 'altered-key' ? 'other-key' : 'altered-key'; }

function ingestCommand(value) {
  const command = plainSnapshot(value, 'diagnostic_command_invalid');
  assertExactKeys(command, ['capability', 'payload'], 'diagnostic_command_invalid');
  return command;
}

function searchCommand(value) {
  const command = plainSnapshot(value, 'diagnostic_query_invalid');
  assertExactKeys(command, ['capability', 'cursor', 'filters', 'limit', 'mode'], 'diagnostic_query_invalid');
  if (!['view', 'export'].includes(command.mode)
      || (command.cursor !== null
        && (typeof command.cursor !== 'string' || !CURSOR_RE.test(command.cursor)))) {
    throw serviceError('diagnostic_query_invalid');
  }
  command.limit = boundedInteger(command.limit, 1, MAX_QUERY_LIMIT, 'diagnostic_query_invalid');
  command.filters = queryFilters(command.filters);
  return command;
}

function compactCommand(value) {
  const command = plainSnapshot(value, 'diagnostic_compaction_invalid');
  assertExactKeys(command, ['capability', 'limit'], 'diagnostic_compaction_invalid');
  command.limit = boundedInteger(command.limit, 1, MAX_QUERY_LIMIT, 'diagnostic_compaction_invalid');
  return command;
}

function recoveryCommand(value) {
  const command = plainSnapshot(value, 'diagnostic_clock_recovery_invalid');
  assertExactKeys(command, ['capability', 'reasonCode'], 'diagnostic_clock_recovery_invalid');
  if (!CLOCK_RECOVERY_REASONS.has(command.reasonCode)) {
    throw serviceError('diagnostic_clock_recovery_invalid');
  }
  return command;
}

function deletionIntentCommand(value) {
  const command = plainSnapshot(value, 'diagnostic_deletion_intent_invalid');
  assertExactKeys(command, ['intent'], 'diagnostic_deletion_intent_invalid');
  return command;
}

function deletionVendorCommand(value, withLimit) {
  const command = plainSnapshot(value, 'diagnostic_deletion_command_invalid');
  const keys = withLimit ? ['capability', 'jobId', 'limit'] : ['capability', 'jobId'];
  assertExactKeys(command, keys, 'diagnostic_deletion_command_invalid');
  if (!uuid(command.jobId)) throw serviceError('diagnostic_deletion_command_invalid');
  if (withLimit) {
    command.limit = boundedInteger(
      command.limit, 1, MAX_QUERY_LIMIT, 'diagnostic_deletion_command_invalid',
    );
  }
  return command;
}

function deletionTerminationCommand(value) {
  const command = plainSnapshot(value, 'diagnostic_deletion_command_invalid');
  assertExactKeys(
    command, ['capability', 'jobId', 'status'], 'diagnostic_deletion_command_invalid',
  );
  if (!uuid(command.jobId) || !VENDOR_TERMINAL_DELETION_STATUSES.has(command.status)) {
    throw serviceError('diagnostic_deletion_command_invalid');
  }
  return command;
}

function parseDiagnostic(value) {
  const snapshot = plainSnapshot(value, 'diagnostic_schema_invalid');
  try { return protocol.assertChannel(snapshot, protocol.CHANNEL_KINDS.DIAGNOSTIC); }
  catch { throw serviceError('diagnostic_schema_invalid'); }
}

async function authorizeCapability(context, tx, value, allowedPurposes, nowMs) {
  const capability = await validateCapabilityAuthorization(
    context, tx, value, allowedPurposes, nowMs,
  );
  await claimCapabilityUse(context, tx, capability, nowMs);
  return capability;
}

async function validateCapabilityAuthorization(context, tx, value, allowedPurposes, nowMs) {
  const capability = verifiedCapability(context, value, nowMs);
  const ownerAssertion = verifiedOwnerAuthAssertion(context, capability, nowMs);
  if (!allowedPurposes.includes(capability.purpose)) throw serviceError('capability_purpose_denied');
  const principal = principalSnapshot(await context.currentPrincipal());
  assertPrincipalBinding(capability, principal);
  const state = await currentAuthorization(context, tx, capability, nowMs);
  if (capability.authorizationRevision !== state.revision
      || capability.ownerAuthEventId !== state.ownerAuthEventId
      || capability.issuer !== state.issuer
      || capability.credentialPurpose !== state.credentialPurpose
      || capability.credentialVersion !== state.credentialVersion
      || Date.parse(capability.issuedAt) < Date.parse(state.updatedAt)
      || Date.parse(capability.expiresAt) > Date.parse(state.expiresAt)) {
    throw serviceError('capability_revoked');
  }
  assertFreshStepUp(capability, ownerAssertion, nowMs);
  return capability;
}

async function claimCapabilityUse(context, tx, capability, nowMs) {
  await assertCapabilityUnused(context, tx, capability);
  const useAudit = capabilityUseAudit(context, capability, nowMs);
  await appendExactAudit(context, tx, useAudit);
  const claim = capabilityClaim(context, capability, useAudit.eventId, nowMs);
  const stored = await tx.claimDiagnosticCapability(claim);
  if (stored === null) throw serviceError('capability_replayed');
  assertExactValue(stored, claim, 'capability_claim_invalid');
}

async function assertCapabilityUnused(context, tx, capability) {
  if (await verifiedCapabilityClaim(context, tx, capability) !== null) {
    throw serviceError('capability_replayed');
  }
}

async function verifiedCapabilityClaim(context, tx, capability) {
  const value = await tx.readDiagnosticCapabilityClaim(capability.capabilityId);
  if (value !== null) {
    const claim = verifyAuthenticated(
      context.integrityAuthority, CAPABILITY_CLAIM_DOMAIN, value,
      capabilityClaimCoreKeys(), 'capability_claim_invalid',
    );
    validateCapabilityClaim(claim, capability);
    assertAuditCore(
      context, await tx.readAuditDescriptor(claim.auditEventId),
      capabilityUseAudit(context, capability, Date.parse(claim.usedAt), claim.auditEventId),
      'capability_claim_invalid',
    );
    return claim;
  }
  const latest = await tx.readLatestCapabilityAudit({ capabilityId: capability.capabilityId });
  if (latest !== null) throw serviceError('capability_claim_missing');
  return null;
}

function validateCapabilityClaim(claim, capability) {
  if (claim.schemaVersion !== SCHEMA_VERSION || claim.recordType !== 'capability_claim'
      || claim.capabilityId !== capability.capabilityId
      || claim.capabilityDigest !== capability.recordDigest
      || claim.principalId !== capability.principalId || claim.sessionId !== capability.sessionId
      || claim.purpose !== capability.purpose || claim.ownerAuthEventId !== capability.ownerAuthEventId
      || claim.credentialVersion !== capability.credentialVersion
      || !uuid(claim.auditEventId) || !canonicalIso(claim.usedAt)) {
    throw serviceError('capability_claim_invalid');
  }
}

function verifiedCapability(context, value, nowMs) {
  const record = verifyAuthenticated(
    context.accessAuthority, CAPABILITY_DOMAIN, value, capabilityCoreKeys(),
    'capability_invalid',
  );
  validateCapability(record, nowMs);
  return record;
}

function validateCapability(record, nowMs) {
  if (record.schemaVersion !== SCHEMA_VERSION || record.recordType !== 'capability'
      || !uuid(record.capabilityId) || !uuid(record.principalId) || !uuid(record.sessionId)
      || !PRINCIPAL_TYPES.has(record.principalType) || !CAPABILITY_PURPOSES.has(record.purpose)
      || !referenceId(record.ownerAuthEventId) || typeof record.issuer !== 'string'
      || !KEY_ID_RE.test(record.issuer) || !CREDENTIAL_PURPOSES.has(record.credentialPurpose)
      || !Number.isSafeInteger(record.credentialVersion) || record.credentialVersion < 1
      || !Number.isSafeInteger(record.authorizationRevision) || record.authorizationRevision < 1
      || !canonicalIso(record.issuedAt) || !canonicalIso(record.expiresAt)
      || Date.parse(record.issuedAt) > nowMs + MAX_CLOCK_SKEW_MS
      || Date.parse(record.expiresAt) <= nowMs
      || Date.parse(record.expiresAt) - Date.parse(record.issuedAt) > MAX_CAPABILITY_LIFETIME_MS) {
    throw serviceError('capability_invalid');
  }
  checkedCustomerIds(record.customerIds, 'capability_invalid');
  if (record.stepUpAt !== null && (!canonicalIso(record.stepUpAt)
      || Date.parse(record.stepUpAt) > nowMs + MAX_CLOCK_SKEW_MS)) {
    throw serviceError('capability_invalid');
  }
  for (const field of ['supportCaseId', 'approvalId']) {
    if (record[field] !== null && !referenceId(record[field])) throw serviceError('capability_invalid');
  }
  if (record.deploymentId !== null && (typeof record.deploymentId !== 'string'
      || !isDeploymentId(record.deploymentId))) {
    throw serviceError('capability_invalid');
  }
  validateCapabilityShape(record);
}

function verifiedOwnerAuthAssertion(context, capability, nowMs) {
  if (capability.principalType !== 'vendor') {
    if (capability.ownerAuthAssertion !== null) throw serviceError('capability_invalid');
    return null;
  }
  const assertion = verifyAuthenticated(
    context.ownerAuthAuthority,
    OWNER_AUTH_ASSERTION_DOMAIN,
    capability.ownerAuthAssertion,
    ownerAuthAssertionCoreKeys(),
    'owner_auth_assertion_invalid',
  );
  if (assertion.schemaVersion !== SCHEMA_VERSION
      || assertion.recordType !== 'owner_auth_assertion'
      || !uuid(assertion.assertionId)
      || assertion.principalId !== capability.principalId
      || assertion.sessionId !== capability.sessionId
      || assertion.ownerAuthEventId !== capability.ownerAuthEventId
      || assertion.credentialVersion !== capability.credentialVersion
      || assertion.issuer !== capability.issuer
      || !referenceId(assertion.mfaEventId)
      || !canonicalIso(assertion.authenticatedAt)
      || !canonicalIso(assertion.mfaAt)
      || !canonicalIso(assertion.expiresAt)
      || Date.parse(assertion.authenticatedAt) > Date.parse(assertion.mfaAt)
      || Date.parse(assertion.mfaAt) > Date.parse(capability.issuedAt)
      || Date.parse(assertion.expiresAt) < Date.parse(capability.expiresAt)
      || Date.parse(assertion.expiresAt) <= nowMs
      || Date.parse(assertion.authenticatedAt) > nowMs + MAX_CLOCK_SKEW_MS) {
    throw serviceError('owner_auth_assertion_invalid');
  }
  return assertion;
}

function validateCapabilityShape(record) {
  if (record.purpose === 'diagnostic:ingest') {
    if (record.principalType !== 'connector' || !Array.isArray(record.customerIds)
        || record.customerIds.length !== 1 || record.deploymentId === null) {
      throw serviceError('capability_invalid');
    }
    return;
  }
  if (record.deploymentId !== null) throw serviceError('capability_invalid');
  if (record.purpose === 'diagnostics:export') {
    if (record.principalType !== 'vendor' || record.supportCaseId === null
        || record.approvalId === null) throw serviceError('capability_invalid');
    return;
  }
  if (['diagnostics:delete:preview', 'diagnostics:delete:approve',
    'diagnostics:delete:execute'].includes(record.purpose)) {
    if (record.principalType !== 'vendor' || !Array.isArray(record.customerIds)
        || record.customerIds.length !== 1
        || (['diagnostics:delete:approve', 'diagnostics:delete:execute']
          .includes(record.purpose) && record.approvalId === null)) {
      throw serviceError('capability_invalid');
    }
    return;
  }
  if (record.purpose === 'diagnostics:clock:recover') {
    if (record.principalType !== 'vendor' || record.customerIds !== '*'
        || record.approvalId === null) throw serviceError('capability_invalid');
    return;
  }
  if (record.purpose === 'diagnostics:compact:global') {
    if (record.principalType !== 'scheduler' || record.customerIds !== '*') {
      throw serviceError('capability_invalid');
    }
  } else if (record.principalType !== 'vendor' || (record.customerIds === '*'
      && record.purpose === 'diagnostics:compact')) {
    throw serviceError('capability_invalid');
  }
}

function assertFreshStepUp(capability, ownerAssertion, nowMs) {
  if (!['diagnostics:export', 'diagnostics:delete:preview', 'diagnostics:delete:approve',
    'diagnostics:delete:execute', 'diagnostics:clock:recover'].includes(capability.purpose)) return;
  if (!ownerAssertion || capability.stepUpAt === null
      || capability.stepUpAt !== ownerAssertion.mfaAt
      || Date.parse(capability.stepUpAt) > Date.parse(capability.issuedAt)
      || nowMs - Date.parse(ownerAssertion.mfaAt) > MAX_STEP_UP_AGE_MS) {
    throw serviceError('capability_step_up_required');
  }
}

function principalSnapshot(value) {
  const principal = plainSnapshot(value, 'current_principal_invalid');
  assertExactKeys(principal, ['principalId', 'principalType', 'sessionId'], 'current_principal_invalid');
  if (!uuid(principal.principalId) || !uuid(principal.sessionId)
      || !PRINCIPAL_TYPES.has(principal.principalType)) {
    throw serviceError('current_principal_invalid');
  }
  return Object.freeze(principal);
}

function assertPrincipalBinding(capability, principal) {
  if (capability.principalId !== principal.principalId
      || capability.sessionId !== principal.sessionId
      || capability.principalType !== principal.principalType) {
    throw serviceError('capability_principal_mismatch');
  }
}

async function currentAuthorization(context, tx, capability, nowMs) {
  const value = await tx.readDiagnosticAuthorizationState(capability.principalId);
  const state = verifyAuthenticated(
    context.accessAuthority, AUTHORIZATION_DOMAIN, value, authorizationCoreKeys(),
    'authorization_state_invalid',
  );
  validateAuthorizationState(state, capability, nowMs);
  await assertLatestStateAudit(context, tx, authorizationAudit(state));
  return state;
}

function validateAuthorizationState(state, capability, nowMs) {
  if (state.schemaVersion !== SCHEMA_VERSION || state.recordType !== 'authorization_state'
      || state.principalId !== capability.principalId
      || state.principalType !== capability.principalType
      || !referenceId(state.ownerAuthEventId) || typeof state.issuer !== 'string'
      || !KEY_ID_RE.test(state.issuer) || !CREDENTIAL_PURPOSES.has(state.credentialPurpose)
      || !Number.isSafeInteger(state.credentialVersion) || state.credentialVersion < 1
      || !Number.isSafeInteger(state.revision) || state.revision < 1
      || !Number.isSafeInteger(state.revocationRevision) || state.revocationRevision < 0
      || state.revocationRevision >= state.revision || state.status !== 'active'
      || !canonicalIso(state.updatedAt) || !canonicalIso(state.expiresAt)
      || Date.parse(state.updatedAt) > nowMs + MAX_CLOCK_SKEW_MS
      || Date.parse(state.expiresAt) <= nowMs || !uuid(state.auditEventId)) {
    throw serviceError('authorization_state_invalid');
  }
}

async function currentConsent(context, tx, payload, nowMs) {
  const grantValue = await tx.readCustomerDiagnosticGrant(scope(payload));
  const grant = verifyAuthenticated(
    context.customerGrantAuthority, CUSTOMER_GRANT_DOMAIN, grantValue,
    customerGrantCoreKeys(), 'diagnostic_customer_grant_invalid',
  );
  validateCustomerGrant(grant, payload, nowMs);
  await assertLatestStateAudit(context, tx, customerGrantAudit(grant));
  const value = await tx.readDiagnosticConsent(scope(payload));
  const consent = verifyAuthenticated(
    context.integrityAuthority, CONSENT_DOMAIN, value, consentCoreKeys(),
    'diagnostic_consent_invalid',
  );
  validateConsent(consent, grant, payload, nowMs);
  await assertLatestStateAudit(context, tx, consentAudit(consent));
  return consent;
}

function validateCustomerGrant(grant, payload, nowMs) {
  if (grant.schemaVersion !== SCHEMA_VERSION || grant.recordType !== 'customer_grant'
      || !uuid(grant.grantId) || grant.customerId !== payload.customerId
      || grant.deploymentId !== payload.deploymentId || grant.channel !== 'diagnostics'
      || grant.enabled !== true || !Number.isSafeInteger(grant.revision) || grant.revision < 1
      || !Number.isSafeInteger(grant.revocationRevision) || grant.revocationRevision < 0
      || grant.revocationRevision >= grant.revision || !canonicalIso(grant.issuedAt)
      || Date.parse(grant.issuedAt) > nowMs + MAX_CLOCK_SKEW_MS
      || !canonicalIso(grant.expiresAt) || Date.parse(grant.expiresAt) <= nowMs
      || !uuid(grant.auditEventId)) throw serviceError('diagnostic_customer_grant_invalid');
}

function validateConsent(consent, grant, payload, nowMs) {
  if (consent.schemaVersion !== SCHEMA_VERSION || consent.recordType !== 'consent_state'
      || !uuid(consent.consentId) || consent.customerId !== payload.customerId
      || consent.deploymentId !== payload.deploymentId || consent.channel !== 'diagnostics'
      || consent.enabled !== true || consent.usePolicy !== 'support_security_only'
      || consent.customerGrantId !== grant.grantId
      || consent.customerGrantDigest !== grant.recordDigest
      || consent.customerGrantRevision !== grant.revision
      || consent.customerGrantRevocationRevision !== grant.revocationRevision
      || !Number.isSafeInteger(consent.revision) || consent.revision < 1
      || !Number.isSafeInteger(consent.revocationRevision) || consent.revocationRevision < 0
      || consent.revocationRevision >= consent.revision
      || !canonicalIso(consent.updatedAt) || Date.parse(consent.updatedAt) > nowMs + MAX_CLOCK_SKEW_MS
      || !canonicalIso(consent.expiresAt) || Date.parse(consent.expiresAt) <= nowMs
      || !uuid(consent.auditEventId)) throw serviceError('diagnostic_consent_invalid');
  boundedInteger(
    consent.retentionDays, MIN_RETENTION_DAYS, MAX_RETENTION_DAYS,
    'diagnostic_consent_invalid',
  );
}

function verifiedDeletionIntent(context, value, nowMs) {
  const intent = verifyCustomerDeletionIntent(context, value);
  checkedScope(intent.customerId, intent.deploymentId, 'diagnostic_deletion_intent_invalid');
  if (intent.schemaVersion !== SCHEMA_VERSION || intent.recordType !== 'deletion_intent'
      || !uuid(intent.intentId) || intent.channel !== 'diagnostics'
      || !uuid(intent.customerGrantId) || !hexDigest(intent.customerGrantDigest)
      || !Number.isSafeInteger(intent.customerGrantRevision)
      || intent.customerGrantRevision < 1 || !Number.isSafeInteger(intent.scopeRevision)
      || intent.scopeRevision < 1 || !hexDigest(intent.subjectDigest)
      || !DELETION_REASONS.has(intent.reasonCode) || !canonicalIso(intent.issuedAt)
      || !canonicalIso(intent.expiresAt) || Date.parse(intent.issuedAt) > nowMs + MAX_CLOCK_SKEW_MS
      || Date.parse(intent.expiresAt) <= nowMs
      || Date.parse(intent.expiresAt) - Date.parse(intent.issuedAt) > DAY_MS) {
    throw serviceError('diagnostic_deletion_intent_invalid');
  }
  return intent;
}

function verifyCustomerDeletionIntent(context, value) {
  const intent = plainSnapshot(value, 'diagnostic_deletion_intent_invalid');
  assertExactKeys(intent, [
    ...deletionIntentCoreKeys(), 'keyId', 'recordDigest', 'signature',
  ], 'diagnostic_deletion_intent_invalid');
  const core = pick(intent, deletionIntentCoreKeys());
  const message = canonical(core);
  if (!KEY_ID_RE.test(String(intent.keyId || ''))
      || !hexDigest(intent.recordDigest) || intent.recordDigest !== digest(core)
      || typeof intent.signature !== 'string'
      || context.deletionIntentKeyRegistry.verify({
        customerId: core.customerId,
        deploymentId: core.deploymentId,
        domain: DELETION_INTENT_DOMAIN,
        issuedAt: core.issuedAt,
        keyId: intent.keyId,
        message,
        signature: intent.signature,
      }) !== true) {
    throw serviceError('diagnostic_deletion_intent_invalid');
  }
  return deepFreeze(intent);
}

async function currentDeletionGrant(context, tx, intent, nowMs) {
  const value = await tx.readCustomerDiagnosticGrant(scope(intent));
  const grant = verifyAuthenticated(
    context.customerGrantAuthority, CUSTOMER_GRANT_DOMAIN, value,
    customerGrantCoreKeys(), 'diagnostic_customer_grant_invalid',
  );
  validateCustomerGrant(grant, intent, nowMs);
  await assertLatestStateAudit(context, tx, customerGrantAudit(grant));
  return grant;
}

function assertDeletionGrantBinding(intent, grant) {
  if (intent.customerGrantId !== grant.grantId
      || intent.customerGrantDigest !== grant.recordDigest
      || intent.customerGrantRevision !== grant.revision
      || intent.scopeRevision !== grant.revision) {
    throw serviceError('diagnostic_deletion_grant_invalid');
  }
}

function initialDeletionJob(context, intent, grant, nowMs) {
  return authenticate(context.integrityAuthority, DELETION_JOB_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'deletion_job',
    jobId: intent.intentId,
    intentDigest: intent.recordDigest,
    customerId: intent.customerId,
    deploymentId: intent.deploymentId,
    customerGrantId: grant.grantId,
    customerGrantDigest: grant.recordDigest,
    customerGrantRevision: grant.revision,
    scopeRevision: intent.scopeRevision,
    intentExpiresAt: intent.expiresAt,
    status: 'requested',
    terminalReasonCode: null,
    revision: 1,
    previewCount: null,
    snapshotHighWater: null,
    nextAfter: null,
    batchCount: 0,
    deletedCount: 0,
    previewDigest: null,
    approvalId: null,
    supportCaseId: null,
    completion: null,
    updatedAt: iso(nowMs),
    auditEventId: randomId(context),
  });
}

async function requiredDeletionJob(context, tx, jobId) {
  const value = await tx.readDiagnosticDeletionJob(jobId);
  if (value === null) throw serviceError('diagnostic_deletion_not_found');
  const job = await verifiedDeletionJob(context, tx, value);
  const reservationValue = await tx.readDiagnosticDeletionReservation(scope(job));
  const reservation = verifiedDeletionReservation(context, reservationValue);
  if (reservation.jobId !== job.jobId || reservation.intentDigest !== job.intentDigest
      || reservation.active !== !TERMINAL_DELETION_STATUSES.has(job.status)) {
    throw serviceError('diagnostic_deletion_integrity_failed');
  }
  return job;
}

function createDeletionReservation(context, current, job, active, nowMs, releaseReason) {
  const leaseExpiresAt = active
    ? iso(Math.min(Date.parse(job.intentExpiresAt), nowMs + DELETION_LEASE_MS))
    : null;
  return authenticate(context.integrityAuthority, DELETION_RESERVATION_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'deletion_reservation',
    customerId: job.customerId,
    deploymentId: job.deploymentId,
    jobId: job.jobId,
    intentDigest: job.intentDigest,
    active,
    leaseId: current ? current.leaseId : randomId(context),
    leaseExpiresAt,
    releaseReason: active ? null : releaseReason,
    revision: current ? current.revision + 1 : 1,
    updatedAt: iso(nowMs),
  });
}

async function renewOrExpireDeletionLease(context, tx, job, nowMs) {
  const current = verifiedDeletionReservation(
    context, await tx.readDiagnosticDeletionReservation(scope(job)),
  );
  if (!current.active || current.jobId !== job.jobId
      || current.intentDigest !== job.intentDigest) {
    throw serviceError('diagnostic_deletion_integrity_failed');
  }
  if (Date.parse(current.leaseExpiresAt) <= nowMs || Date.parse(job.intentExpiresAt) <= nowMs) {
    const expired = advanceDeletionJob(context, job, {
      status: 'expired',
      terminalReasonCode: 'lease_expired',
    }, nowMs);
    await storeDeletionState(context, tx, job, expired);
    await releaseDeletionReservation(context, tx, current, expired, 'expired', nowMs);
    return { expired: true, job: expired };
  }
  const renewed = createDeletionReservation(context, current, job, true, nowMs, null);
  assertExactValue(await tx.compareAndSwapDiagnosticDeletionReservation({
    customerId: job.customerId,
    deploymentId: job.deploymentId,
    expectedRecordDigest: current.recordDigest,
    nextRecord: renewed,
  }), renewed, 'diagnostic_deletion_conflict');
  return { expired: false, job };
}

async function releaseDeletionReservation(context, tx, current, job, reason, nowMs) {
  if (!current.active || current.jobId !== job.jobId || current.intentDigest !== job.intentDigest) {
    throw serviceError('diagnostic_deletion_integrity_failed');
  }
  const released = createDeletionReservation(context, current, job, false, nowMs, reason);
  await appendExactAudit(
    context, tx, deletionReservationReleaseAudit(context, current, released, job, nowMs),
  );
  assertExactValue(await tx.compareAndSwapDiagnosticDeletionReservation({
    customerId: job.customerId,
    deploymentId: job.deploymentId,
    expectedRecordDigest: current.recordDigest,
    nextRecord: released,
  }), released, 'diagnostic_deletion_conflict');
  return released;
}

async function releaseExpiredDeletionLeases(context, tx, nowMs, limit, allowedCustomerIds) {
  const values = boundedList(await tx.listExpiredDiagnosticDeletionReservations({
    nowMs, limit, allowedCustomerIds,
  }), limit, 'diagnostic_deletion_integrity_failed');
  let releasedCount = 0;
  for (const value of values) {
    const reservation = verifiedDeletionReservation(context, value);
    if (!reservation.active || Date.parse(reservation.leaseExpiresAt) > nowMs
        || !customerAllowed(reservation.customerId, allowedCustomerIds)) {
      throw serviceError('diagnostic_deletion_integrity_failed');
    }
    const raw = await tx.readDiagnosticDeletionJob(reservation.jobId);
    if (raw === null) throw serviceError('diagnostic_deletion_integrity_failed');
    const job = await verifiedDeletionJob(context, tx, raw);
    if (TERMINAL_DELETION_STATUSES.has(job.status)) {
      throw serviceError('diagnostic_deletion_integrity_failed');
    }
    const expired = advanceDeletionJob(context, job, {
      status: 'expired', terminalReasonCode: 'lease_expired',
    }, nowMs);
    await storeDeletionState(context, tx, job, expired);
    await releaseDeletionReservation(context, tx, reservation, expired, 'expired', nowMs);
    releasedCount += 1;
  }
  return releasedCount;
}

function verifiedDeletionReservation(context, value) {
  const record = verifyAuthenticated(
    context.integrityAuthority,
    DELETION_RESERVATION_DOMAIN,
    value,
    deletionReservationCoreKeys(),
    'diagnostic_deletion_integrity_failed',
  );
  checkedScope(record.customerId, record.deploymentId, 'diagnostic_deletion_integrity_failed');
  if (record.schemaVersion !== SCHEMA_VERSION || record.recordType !== 'deletion_reservation'
      || !uuid(record.jobId) || !hexDigest(record.intentDigest)
      || typeof record.active !== 'boolean'
      || !uuid(record.leaseId)
      || (record.active && (!canonicalIso(record.leaseExpiresAt)
        || record.releaseReason !== null))
      || (!record.active && (record.leaseExpiresAt !== null
        || !['completed', 'rejected', 'canceled', 'expired', 'failed'].includes(
          record.releaseReason,
        )))
      || !Number.isSafeInteger(record.revision) || record.revision < 1
      || !canonicalIso(record.updatedAt)) {
    throw serviceError('diagnostic_deletion_integrity_failed');
  }
  return record;
}

async function verifiedDeletionJob(context, tx, value) {
  const job = verifyAuthenticated(
    context.integrityAuthority, DELETION_JOB_DOMAIN, value,
    deletionJobCoreKeys(), 'diagnostic_deletion_integrity_failed',
  );
  validateDeletionJob(context, job);
  await assertLatestStateAudit(context, tx, deletionStateAudit(job));
  return job;
}

function validateDeletionJob(context, job) {
  checkedScope(job.customerId, job.deploymentId, 'diagnostic_deletion_integrity_failed');
  const statuses = new Set([
    'requested', 'previewed', 'approved', 'running',
    'completed', 'rejected', 'canceled', 'expired', 'failed',
  ]);
  if (job.schemaVersion !== SCHEMA_VERSION || job.recordType !== 'deletion_job'
      || !uuid(job.jobId) || !hexDigest(job.intentDigest) || !uuid(job.customerGrantId)
      || !hexDigest(job.customerGrantDigest) || !Number.isSafeInteger(job.customerGrantRevision)
      || job.customerGrantRevision < 1 || job.scopeRevision !== job.customerGrantRevision
      || !canonicalIso(job.intentExpiresAt)
      || !statuses.has(job.status) || !Number.isSafeInteger(job.revision) || job.revision < 1
      || !Number.isSafeInteger(job.batchCount) || job.batchCount < 0
      || !Number.isSafeInteger(job.deletedCount) || job.deletedCount < 0
      || (TERMINAL_DELETION_STATUSES.has(job.status)
        !== (job.terminalReasonCode !== null))
      || (job.terminalReasonCode !== null
        && !/^[a-z][a-z0-9_]{2,63}$/.test(job.terminalReasonCode))
      || !canonicalIso(job.updatedAt) || !uuid(job.auditEventId)) {
    throw serviceError('diagnostic_deletion_integrity_failed');
  }
  validateDeletionProgressFields(context, job);
}

function validateDeletionProgressFields(context, job) {
  const previewed = !['requested', 'rejected', 'canceled', 'expired', 'failed'].includes(job.status)
    || job.previewCount !== null;
  if ((previewed && (!Number.isSafeInteger(job.previewCount) || job.previewCount < 0
      || !hexDigest(job.previewDigest)))
      || (!previewed && (job.previewCount !== null || job.previewDigest !== null))
      || job.deletedCount > (job.previewCount === null ? 0 : job.previewCount)
      || (job.snapshotHighWater !== null && !validHighWater(job.snapshotHighWater))
      || (job.nextAfter !== null && !validHighWater(job.nextAfter))
      || (job.nextAfter !== null && job.snapshotHighWater !== null
        && compareHighWater(job.nextAfter, job.snapshotHighWater) > 0)
      || (['approved', 'running', 'completed'].includes(job.status)
        && !referenceId(job.approvalId))
      || (job.supportCaseId !== null && !referenceId(job.supportCaseId))) {
    throw serviceError('diagnostic_deletion_integrity_failed');
  }
  if (job.status === 'completed') {
    const completion = verifyAuthenticated(
      context.integrityAuthority, DELETION_COMPLETION_DOMAIN, job.completion,
      deletionCompletionCoreKeys(), 'diagnostic_deletion_integrity_failed',
    );
    if (completion.jobId !== job.jobId || completion.intentDigest !== job.intentDigest
        || completion.customerId !== job.customerId
        || completion.deploymentId !== job.deploymentId
        || completion.previewDigest !== job.previewDigest
        || completion.deletedCount !== job.deletedCount
        || completion.batchCount !== job.batchCount
        || completion.approvalId !== job.approvalId) {
      throw serviceError('diagnostic_deletion_integrity_failed');
    }
  } else if (job.completion !== null) {
    throw serviceError('diagnostic_deletion_integrity_failed');
  }
}

function assertDeletionStatus(job, allowed) {
  if (!allowed.includes(job.status)) throw serviceError('diagnostic_deletion_state_invalid');
}

function assertDeletionCapability(job, capability) {
  if (capability.customerIds === '*' || capability.customerIds.length !== 1
      || capability.customerIds[0] !== job.customerId) {
    throw serviceError('diagnostic_customer_scope_denied');
  }
}

function deletionPreview(value) {
  const preview = plainSnapshot(value, 'diagnostic_deletion_preview_invalid');
  assertExactKeys(preview, ['count', 'snapshotHighWater'], 'diagnostic_deletion_preview_invalid');
  if (!Number.isSafeInteger(preview.count) || preview.count < 0
      || (preview.count === 0 && preview.snapshotHighWater !== null)
      || (preview.count > 0 && !validHighWater(preview.snapshotHighWater))) {
    throw serviceError('diagnostic_deletion_preview_invalid');
  }
  return deepFreeze(preview);
}

function assertDeletionCandidates(job, records) {
  if (job.snapshotHighWater === null && records.length) {
    throw serviceError('diagnostic_deletion_batch_invalid');
  }
  let previous = job.nextAfter;
  for (const record of records) {
    const point = recordPoint(record);
    if (record.customerId !== job.customerId || record.deploymentId !== job.deploymentId
        || (previous && compareHighWater(point, previous) <= 0)
        || (job.snapshotHighWater
          && compareHighWater(point, job.snapshotHighWater) > 0)) {
      throw serviceError('diagnostic_deletion_batch_invalid');
    }
    previous = point;
  }
}

function recordPoint(record) {
  return { receivedAt: record.receivedAt, messageId: record.messageId };
}

function validHighWater(value) {
  if (!value || typeof value !== 'object') return false;
  try {
    const snapshot = plainSnapshot(value, 'diagnostic_deletion_integrity_failed');
    assertExactKeys(snapshot, ['messageId', 'receivedAt'], 'diagnostic_deletion_integrity_failed');
    return canonicalIso(snapshot.receivedAt) && uuid(snapshot.messageId);
  } catch { return false; }
}

function advanceDeletionJob(context, current, changes, nowMs) {
  const core = pick(current, deletionJobCoreKeys());
  return authenticate(context.integrityAuthority, DELETION_JOB_DOMAIN, {
    ...core,
    ...changes,
    revision: current.revision + 1,
    updatedAt: iso(nowMs),
    auditEventId: randomId(context),
  });
}

function completedDeletionJob(context, current, batch, capability, nowMs) {
  const deletedCount = current.deletedCount + batch.deleted.length;
  const batchCount = current.batchCount + 1;
  if (deletedCount > current.previewCount
      || (batch.done && deletedCount !== current.previewCount)) {
    throw serviceError('diagnostic_deletion_batch_invalid');
  }
  const status = batch.done ? 'completed' : 'running';
  const nextAfter = batch.deleted.length ? batch.deleted.at(-1) : current.nextAfter;
  let completion = null;
  if (status === 'completed') {
    completion = authenticate(context.integrityAuthority, DELETION_COMPLETION_DOMAIN, {
      schemaVersion: SCHEMA_VERSION,
      recordType: 'deletion_completion',
      jobId: current.jobId,
      intentDigest: current.intentDigest,
      customerId: current.customerId,
      deploymentId: current.deploymentId,
      previewDigest: current.previewDigest,
      deletedCount,
      batchCount,
      approvalId: capability.approvalId,
      completedAt: iso(nowMs),
    });
  }
  return advanceDeletionJob(context, current, {
    status, nextAfter, deletedCount, batchCount, completion,
    terminalReasonCode: status === 'completed' ? 'completed' : null,
  }, nowMs);
}

async function storeDeletionState(context, tx, current, next) {
  await appendExactAudit(context, tx, deletionStateAudit(next));
  assertExactValue(await tx.compareAndSwapDiagnosticDeletionJob({
    jobId: next.jobId,
    expectedRecordDigest: current.recordDigest,
    nextRecord: next,
  }), next, 'diagnostic_deletion_conflict');
}

function deletionIntentReceipt(job) {
  return Object.freeze({ accepted: true, jobId: job.jobId });
}

function deletionProgress(job) {
  return deepFreeze({
    jobId: job.jobId,
    status: job.status,
    deletedCount: job.deletedCount,
    batchCount: job.batchCount,
    nextBatchRequired: job.status === 'running',
    completion: job.completion === null ? null : clone(job.completion),
  });
}

function assertIngestScope(payload, capability) {
  if (payload.customerId !== capability.customerIds[0]) {
    throw serviceError('diagnostic_customer_mismatch');
  }
  if (payload.deploymentId !== capability.deploymentId) {
    throw serviceError('diagnostic_deployment_mismatch');
  }
}

function assertEventTime(payload, nowMs) {
  const occurredMs = Date.parse(payload.occurredAt);
  if (occurredMs > nowMs + MAX_CLOCK_SKEW_MS) throw serviceError('diagnostic_event_future');
  if (nowMs - occurredMs > MAX_EVENT_AGE_MS) throw serviceError('diagnostic_event_stale');
}

async function trustedNow(context, tx, mode = 'normal') {
  const wallMs = await trustedDatabaseTime(tx);
  const raw = await tx.readTimeHighWater();
  const current = raw === null ? null : await verifiedTimeState(context, tx, raw);
  if (!current) await assertNoLatestStateAudit(tx, timeAuditQuery(), 'diagnostic_clock_integrity_failed');
  const currentMs = current ? current.timeMs : 0;
  if (wallMs + MAX_CLOCK_SKEW_MS < currentMs) throw serviceError('diagnostic_clock_rollback');
  const nextTimeMs = current
    ? Math.max(wallMs, currentMs + 1)
    : wallMs;
  if (!Number.isSafeInteger(nextTimeMs) || nextTimeMs > MAX_ISO_TIME_MS) {
    throw serviceError('diagnostic_clock_invalid');
  }
  const currentDestructiveApprovedMs = current ? current.destructiveApprovedMs : wallMs;
  if (mode === 'destructive'
      && nextTimeMs - currentDestructiveApprovedMs > MAX_DESTRUCTIVE_FORWARD_JUMP_MS) {
    throw serviceError('diagnostic_clock_recovery_required');
  }
  const destructiveApprovedMs = mode === 'destructive'
    ? nextTimeMs : currentDestructiveApprovedMs;
  if (current && nextTimeMs === currentMs
      && destructiveApprovedMs === current.destructiveApprovedMs) return currentMs;
  const next = createTimeState(context, current, nextTimeMs, destructiveApprovedMs);
  await appendExactAudit(context, tx, timeAudit(next));
  const stored = await tx.compareAndSwapTimeHighWater({
    expectedRecordDigest: current ? current.recordDigest : null,
    nextRecord: next,
  });
  assertExactValue(stored, next, 'diagnostic_clock_conflict');
  return nextTimeMs;
}

async function recoverClock(context, commandValue) {
  const command = recoveryCommand(commandValue);
  return transact(context.storage, RECOVERY_METHODS, async (tx) => {
    const wallMs = await trustedDatabaseTime(tx);
    const raw = await tx.readTimeHighWater();
    const current = raw === null ? null : await verifiedTimeState(context, tx, raw);
    if (!current) {
      await assertNoLatestStateAudit(
        tx, timeAuditQuery(), 'diagnostic_clock_integrity_failed',
      );
    }
    const currentMs = current ? current.timeMs : 0;
    if (wallMs + MAX_CLOCK_SKEW_MS < currentMs) {
      throw serviceError('diagnostic_clock_rollback');
    }
    const effectiveMs = Math.max(wallMs, currentMs);
    const capability = await authorizeCapability(
      context, tx, command.capability, ['diagnostics:clock:recover'], effectiveMs,
    );
    const next = createTimeState(context, current, effectiveMs, effectiveMs);
    await appendExactAudit(context, tx, timeAudit(next));
    assertExactValue(await tx.compareAndSwapTimeHighWater({
      expectedRecordDigest: current ? current.recordDigest : null,
      nextRecord: next,
    }), next, 'diagnostic_clock_conflict');
    await appendExactAudit(context, tx, clockRecoveryAudit(
      context, capability, current, next, command.reasonCode, effectiveMs,
    ));
    return Object.freeze({ recovered: true, approvedTime: iso(effectiveMs) });
  });
}

async function trustedDatabaseTime(tx) {
  const value = plainSnapshot(
    await tx.readTrustedDatabaseTime(), 'diagnostic_clock_invalid',
  );
  assertExactKeys(value, ['source', 'timeMs'], 'diagnostic_clock_invalid');
  if (value.source !== 'database_transaction' || !Number.isSafeInteger(value.timeMs)
      || value.timeMs < 0 || value.timeMs > MAX_ISO_TIME_MS) {
    throw serviceError('diagnostic_clock_invalid');
  }
  return value.timeMs;
}

async function verifiedTimeState(context, tx, value) {
  const state = verifyAuthenticated(
    context.integrityAuthority, TIME_DOMAIN, value, timeCoreKeys(),
    'diagnostic_clock_integrity_failed',
  );
  if (state.schemaVersion !== SCHEMA_VERSION || state.recordType !== 'time_state'
      || !Number.isSafeInteger(state.revision) || state.revision < 1
      || !Number.isSafeInteger(state.timeMs) || state.timeMs < 0 || state.timeMs > MAX_ISO_TIME_MS
      || !Number.isSafeInteger(state.destructiveApprovedMs)
      || state.destructiveApprovedMs < 0 || state.destructiveApprovedMs > state.timeMs
      || !uuid(state.auditEventId)) throw serviceError('diagnostic_clock_integrity_failed');
  await assertLatestStateAudit(context, tx, timeAudit(state));
  return state;
}

function createTimeState(context, current, timeMs, destructiveApprovedMs) {
  return authenticate(context.integrityAuthority, TIME_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'time_state',
    revision: current ? current.revision + 1 : 1,
    timeMs,
    destructiveApprovedMs,
    auditEventId: randomId(context),
  });
}

async function claimIngestQuota(context, tx, payload, nowMs) {
  const day = new Date(nowMs).toISOString().slice(0, 10);
  const raw = await tx.readDiagnosticQuota({ ...scope(payload), day });
  const current = raw === null
    ? null : await verifiedQuotaState(context, tx, raw, payload, day, nowMs);
  const query = quotaAuditQuery(payload.customerId, payload.deploymentId, day);
  if (!current) await assertNoLatestStateAudit(tx, query, 'diagnostic_quota_integrity_failed');
  const count = current ? current.count : 0;
  if (count >= context.dailyEventLimit) throw serviceError('diagnostic_rate_limited');
  const next = createQuotaState(context, current, payload, day, count + 1, nowMs);
  await appendExactAudit(context, tx, quotaAudit(next));
  assertExactValue(await tx.compareAndSwapDiagnosticQuota({
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    day,
    expectedRecordDigest: current ? current.recordDigest : null,
    nextRecord: next,
  }), next, 'diagnostic_quota_conflict');
}

async function verifiedQuotaState(context, tx, value, payload, day, nowMs) {
  const state = verifyAuthenticated(
    context.integrityAuthority, QUOTA_DOMAIN, value, quotaCoreKeys(),
    'diagnostic_quota_integrity_failed',
  );
  checkedScope(state.customerId, state.deploymentId, 'diagnostic_quota_integrity_failed');
  if (state.schemaVersion !== SCHEMA_VERSION || state.recordType !== 'quota_state'
      || state.customerId !== payload.customerId || state.deploymentId !== payload.deploymentId
      || state.day !== day || typeof state.day !== 'string' || !DAY_RE.test(state.day)
      || !Number.isSafeInteger(state.revision)
      || state.revision < 1 || !Number.isSafeInteger(state.count) || state.count < 1
      || state.count > context.dailyEventLimit || state.limit !== context.dailyEventLimit
      || !canonicalIso(state.updatedAt) || Date.parse(state.updatedAt) > nowMs + MAX_CLOCK_SKEW_MS
      || state.updatedAt.slice(0, 10) !== state.day || !uuid(state.auditEventId)) {
    throw serviceError('diagnostic_quota_integrity_failed');
  }
  await assertLatestStateAudit(context, tx, quotaAudit(state));
  return state;
}

function createQuotaState(context, current, payload, day, count, nowMs) {
  return authenticate(context.integrityAuthority, QUOTA_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'quota_state',
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    day,
    count,
    limit: context.dailyEventLimit,
    revision: current ? current.revision + 1 : 1,
    updatedAt: iso(nowMs),
    auditEventId: randomId(context),
  });
}

function createEventRecord(context, payload, capability, consent, nowMs) {
  const retentionDays = Math.min(context.retentionDays, consent.retentionDays);
  return authenticate(context.integrityAuthority, RECORD_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'event',
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    messageId: payload.messageId,
    payload: clone(payload),
    payloadDigest: protocol.payloadDigest(payload, payload.kind),
    authorizationCapabilityId: capability.capabilityId,
    authorizationPrincipalId: capability.principalId,
    consentId: consent.consentId,
    consentRevision: consent.revision,
    consentRevocationRevision: consent.revocationRevision,
    consentDigest: consent.recordDigest,
    receivedAt: iso(nowMs),
    expiresAt: iso(nowMs + retentionDays * DAY_MS),
    auditEventId: randomId(context),
  });
}

function createTombstone(context, record, nowMs) {
  return authenticate(context.integrityAuthority, RECORD_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'tombstone',
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    messageId: record.messageId,
    payloadDigest: record.payloadDigest,
    receivedAt: record.receivedAt,
    expiredAt: record.expiresAt,
    deletedAt: iso(nowMs),
    deleteAfter: iso(nowMs + TOMBSTONE_RETENTION_MS),
    auditEventId: randomId(context),
  });
}

function createReplayIndex(context, record, nowMs) {
  return authenticate(context.integrityAuthority, RECORD_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'replay',
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    messageId: record.messageId,
    payloadDigest: record.payloadDigest,
    receivedAt: record.receivedAt,
    indexedAt: iso(nowMs),
    idempotencyUntil: iso(Date.parse(record.receivedAt) + IDEMPOTENCY_HORIZON_MS),
    auditEventId: randomId(context),
  });
}

function authenticate(authority, domain, core) {
  const recordDigest = digest(core);
  let proof;
  try { proof = checkedProof(authority.sign(domain, canonical(core)), authority.keyId); }
  catch { throw serviceError('integrity_authority_invalid'); }
  if (!verifyAuthority(authority, domain, core, proof)) {
    throw serviceError('integrity_authority_invalid');
  }
  return deepFreeze({ ...core, recordDigest, integrityProof: proof });
}

function verifyAuthenticated(authority, domain, value, coreKeys, code) {
  const record = plainSnapshot(value, code);
  assertExactKeys(record, [...coreKeys, 'integrityProof', 'recordDigest'], code);
  const core = pick(record, coreKeys);
  if (!hexDigest(record.recordDigest) || digest(core) !== record.recordDigest) throw serviceError(code);
  const proof = checkedVerificationProof(record.integrityProof, code);
  if (!verifyAuthority(authority, domain, core, proof)) throw serviceError(code);
  return deepFreeze(record);
}

function verifyAuthority(authority, domain, value, proof) {
  try { return authority.verify(domain, canonical(value), proof) === true; }
  catch { return false; }
}

async function duplicateDisposition(context, tx, value, payload) {
  const record = await verifiedRecord(context, tx, value);
  const payloadDigest = protocol.payloadDigest(payload, payload.kind);
  if (record.customerId !== payload.customerId || record.deploymentId !== payload.deploymentId
      || record.messageId !== payload.messageId || record.payloadDigest !== payloadDigest) {
    throw serviceError('diagnostic_idempotency_conflict');
  }
  return DUPLICATE_RECEIPT;
}

async function assertInsertAuditDisposition(context, tx, payload) {
  const value = await tx.readLatestClaimAudit(scopeMessage(payload));
  if (value === null) return;
  const audit = auditSnapshot(context, value);
  if (audit.action !== 'diagnostic_replay_index_deleted'
      || audit.customerId !== payload.customerId || audit.deploymentId !== payload.deploymentId
      || audit.referenceId !== payload.messageId) {
    throw serviceError('diagnostic_audit_anchor_invalid');
  }
  assertExactValue(
    await tx.readAuditDescriptor(audit.eventId), audit,
    'diagnostic_audit_anchor_invalid',
  );
}

async function verifiedRecord(context, tx, value, expectedType = '') {
  const snapshot = plainSnapshot(value, 'diagnostic_store_corrupt');
  const keys = recordCoreKeys(snapshot.recordType);
  const record = verifyAuthenticated(
    context.integrityAuthority, RECORD_DOMAIN, snapshot, keys, 'diagnostic_store_corrupt',
  );
  if (expectedType && record.recordType !== expectedType) throw serviceError('diagnostic_store_corrupt');
  validateRecord(record);
  assertAuditCore(
    context, await tx.readAuditDescriptor(record.auditEventId),
    recordAudit(record), 'diagnostic_audit_anchor_invalid',
  );
  return record;
}

function validateRecord(record) {
  checkedScope(record.customerId, record.deploymentId, 'diagnostic_store_corrupt');
  if (record.schemaVersion !== SCHEMA_VERSION || !uuid(record.messageId)
      || !uuid(record.auditEventId) || !hexDigest(record.payloadDigest)) {
    throw serviceError('diagnostic_store_corrupt');
  }
  if (record.recordType === 'event') validateEventRecord(record);
  else if (record.recordType === 'tombstone') validateTombstone(record);
  else if (record.recordType === 'replay') validateReplay(record);
  else throw serviceError('diagnostic_store_corrupt');
}

function validateEventRecord(record) {
  if (!uuid(record.authorizationCapabilityId) || !uuid(record.authorizationPrincipalId)
      || !uuid(record.consentId) || !Number.isSafeInteger(record.consentRevision)
      || record.consentRevision < 1 || !Number.isSafeInteger(record.consentRevocationRevision)
      || record.consentRevocationRevision < 0
      || record.consentRevocationRevision >= record.consentRevision
      || !hexDigest(record.consentDigest) || !canonicalIso(record.receivedAt)
      || !canonicalIso(record.expiresAt)
      || Date.parse(record.expiresAt) <= Date.parse(record.receivedAt)) {
    throw serviceError('diagnostic_store_corrupt');
  }
  const payload = parseDiagnostic(record.payload);
  if (payload.customerId !== record.customerId || payload.deploymentId !== record.deploymentId
      || payload.messageId !== record.messageId
      || protocol.payloadDigest(payload, payload.kind) !== record.payloadDigest) {
    throw serviceError('diagnostic_store_corrupt');
  }
}

function validateTombstone(record) {
  if (!canonicalIso(record.receivedAt) || !canonicalIso(record.expiredAt)
      || !canonicalIso(record.deletedAt) || !canonicalIso(record.deleteAfter)
      || Date.parse(record.expiredAt) <= Date.parse(record.receivedAt)
      || Date.parse(record.deletedAt) < Date.parse(record.expiredAt)
      || Date.parse(record.deleteAfter) <= Date.parse(record.deletedAt)) {
    throw serviceError('diagnostic_store_corrupt');
  }
}

function validateReplay(record) {
  if (!canonicalIso(record.receivedAt) || !canonicalIso(record.indexedAt)
      || !canonicalIso(record.idempotencyUntil)
      || Date.parse(record.indexedAt) < Date.parse(record.receivedAt)
      || Date.parse(record.idempotencyUntil)
        !== Date.parse(record.receivedAt) + IDEMPOTENCY_HORIZON_MS) {
    throw serviceError('diagnostic_store_corrupt');
  }
}

async function verifiedSearchRecords(context, tx, values, query, nowMs) {
  const records = [];
  const seen = new Set();
  for (const value of values) {
    const record = await verifiedRecord(context, tx, value, 'event');
    assertSearchResult(record, query, nowMs);
    if (seen.has(record.recordDigest)) throw serviceError('diagnostic_search_invalid');
    seen.add(record.recordDigest);
    records.push(record);
  }
  return records;
}

function assertSearchResult(record, query, nowMs) {
  if (!customerAllowed(record.customerId, query.allowedCustomerIds)) {
    throw serviceError('diagnostic_customer_scope_denied');
  }
  if (Date.parse(record.expiresAt) <= nowMs) throw serviceError('diagnostic_record_expired');
  const filters = query.filters;
  if (filters.customerId && record.customerId !== filters.customerId) throw serviceError('diagnostic_search_invalid');
  if (filters.deploymentId && record.deploymentId !== filters.deploymentId) throw serviceError('diagnostic_search_invalid');
  for (const field of ['component', 'code', 'severity', 'outcome']) {
    if (filters[field] && record.payload[field] !== filters[field]) {
      throw serviceError('diagnostic_search_invalid');
    }
  }
  if (filters.occurredAfter && Date.parse(record.payload.occurredAt) < Date.parse(filters.occurredAfter)) {
    throw serviceError('diagnostic_search_invalid');
  }
  if (filters.occurredBefore && Date.parse(record.payload.occurredAt) >= Date.parse(filters.occurredBefore)) {
    throw serviceError('diagnostic_search_invalid');
  }
}

function boundedQuery(command, capability, nowMs) {
  const allowedCustomerIds = capability.customerIds === '*'
    ? '*' : capability.customerIds.slice();
  if (allowedCustomerIds === '*' && !command.filters.customerId) {
    throw serviceError('diagnostic_customer_scope_required');
  }
  if (command.filters.customerId && allowedCustomerIds !== '*'
      && !allowedCustomerIds.includes(command.filters.customerId)) {
    throw serviceError('diagnostic_customer_scope_denied');
  }
  return deepFreeze({
    allowedCustomerIds,
    expiresAfter: iso(nowMs),
    filters: clone(command.filters),
  });
}

function checkedSnapshotHighWater(value) {
  if (value === null) return null;
  const snapshot = plainSnapshot(value, 'diagnostic_search_invalid');
  assertExactKeys(snapshot, ['messageId', 'receivedAt'], 'diagnostic_search_invalid');
  if (!canonicalIso(snapshot.receivedAt) || !uuid(snapshot.messageId)) {
    throw serviceError('diagnostic_search_invalid');
  }
  return deepFreeze(snapshot);
}

function createCursor(
  context, command, capability, query, snapshotHighWater, record, accessManifest, nowMs,
) {
  if (!record || !snapshotHighWater) throw serviceError('diagnostic_search_invalid');
  const cursor = authenticate(context.cursorAuthority, CURSOR_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'search_cursor',
    mode: command.mode,
    allowedCustomerIds: clone(query.allowedCustomerIds),
    filterDigest: digest(query.filters),
    snapshotHighWater: clone(snapshotHighWater),
    sessionRef: staffReference(context, 'session', capability.sessionId),
    principalRef: staffReference(context, 'principal', capability.principalId),
    supportCaseId: capability.supportCaseId,
    approvalId: capability.approvalId,
    credentialVersion: capability.credentialVersion,
    pageNumber: accessManifest.pageNumber,
    cumulativeCounts: clone(accessManifest.cumulativeCounts),
    cumulativeResultCount: accessManifest.cumulativeResultCount,
    priorManifestDigest: accessManifest.recordDigest,
    lastReceivedAt: record.receivedAt,
    lastMessageId: record.messageId,
    issuedAt: iso(nowMs),
    expiresAt: iso(nowMs + MAX_CAPABILITY_LIFETIME_MS),
  });
  const token = Buffer.from(canonical(cursor), 'utf8').toString('base64url');
  if (!CURSOR_RE.test(token)) throw serviceError('diagnostic_cursor_invalid');
  return token;
}

function verifiedCursor(context, token, command, capability, query, nowMs) {
  let value;
  try {
    const bytes = Buffer.from(token, 'base64url');
    if (bytes.toString('base64url') !== token || bytes.length > 48 * 1024) {
      throw new Error('cursor encoding');
    }
    value = JSON.parse(bytes.toString('utf8'));
  } catch { throw serviceError('diagnostic_cursor_invalid'); }
  const cursor = verifyAuthenticated(
    context.cursorAuthority, CURSOR_DOMAIN, value, cursorCoreKeys(),
    'diagnostic_cursor_invalid',
  );
  if (cursor.schemaVersion !== SCHEMA_VERSION || cursor.recordType !== 'search_cursor'
      || cursor.mode !== command.mode || !sameValue(cursor.allowedCustomerIds, query.allowedCustomerIds)
      || cursor.filterDigest !== digest(query.filters)
      || cursor.sessionRef !== staffReference(
        context, 'session', capability.sessionId,
      )
      || cursor.principalRef !== staffReference(
        context, 'principal', capability.principalId,
      )
      || cursor.supportCaseId !== capability.supportCaseId
      || cursor.approvalId !== capability.approvalId
      || cursor.credentialVersion !== capability.credentialVersion
      || !Number.isSafeInteger(cursor.pageNumber) || cursor.pageNumber < 1
      || !Number.isSafeInteger(cursor.cumulativeResultCount)
      || cursor.cumulativeResultCount < 0 || !hexDigest(cursor.priorManifestDigest)
      || !validCounts(cursor.cumulativeCounts, cursor.cumulativeResultCount)
      || !canonicalIso(cursor.lastReceivedAt) || !uuid(cursor.lastMessageId)
      || !canonicalIso(cursor.issuedAt) || !canonicalIso(cursor.expiresAt)
      || Date.parse(cursor.issuedAt) > nowMs + MAX_CLOCK_SKEW_MS
      || Date.parse(cursor.expiresAt) <= nowMs) throw serviceError('diagnostic_cursor_invalid');
  checkedSnapshotHighWater(cursor.snapshotHighWater);
  return cursor;
}

function assertStrictSearchOrder(records, query) {
  let previous = query.after;
  for (const record of records) {
    const current = { receivedAt: record.receivedAt, messageId: record.messageId };
    if ((previous && compareHighWater(current, previous) <= 0)
        || (query.snapshotHighWater && compareHighWater(current, query.snapshotHighWater) > 0)) {
      throw serviceError('diagnostic_search_invalid');
    }
    previous = current;
  }
}

function compareHighWater(left, right) {
  return left.receivedAt.localeCompare(right.receivedAt)
    || left.messageId.localeCompare(right.messageId);
}

function compactionScope(capability) {
  if (capability.purpose === 'diagnostics:compact:global') return '*';
  if (capability.customerIds === '*') throw serviceError('diagnostic_customer_scope_denied');
  return capability.customerIds.slice();
}

function queryFilters(value) {
  const filters = plainSnapshot(value, 'diagnostic_query_invalid');
  const allowed = [
    'code', 'component', 'customerId', 'deploymentId', 'occurredAfter',
    'occurredBefore', 'outcome', 'severity',
  ];
  if (!filters || typeof filters !== 'object' || Array.isArray(filters)
      || Object.keys(filters).some((key) => !allowed.includes(key))) {
    throw serviceError('diagnostic_query_invalid');
  }
  if (filters.customerId !== undefined
      && (typeof filters.customerId !== 'string' || !CUSTOMER_ID_RE.test(filters.customerId))) {
    throw serviceError('diagnostic_query_invalid');
  }
  if (filters.deploymentId !== undefined
      && (typeof filters.deploymentId !== 'string'
        || !isDeploymentId(filters.deploymentId))) {
    throw serviceError('diagnostic_query_invalid');
  }
  checkSetFilter(filters, 'component', COMPONENTS);
  checkSetFilter(filters, 'code', CODES);
  checkSetFilter(filters, 'severity', SEVERITIES);
  checkSetFilter(filters, 'outcome', OUTCOMES);
  checkTimeFilter(filters, 'occurredAfter');
  checkTimeFilter(filters, 'occurredBefore');
  if (filters.occurredAfter && filters.occurredBefore) {
    const start = Date.parse(filters.occurredAfter);
    const end = Date.parse(filters.occurredBefore);
    if (end <= start || end - start > MAX_QUERY_RANGE_MS) throw serviceError('diagnostic_query_invalid');
  }
  return filters;
}

function searchResult(value, limit) {
  const result = plainSnapshot(value, 'diagnostic_search_invalid');
  assertExactKeys(result, ['items'], 'diagnostic_search_invalid');
  if (!Array.isArray(result.items) || result.items.length > limit) {
    throw serviceError('diagnostic_search_invalid');
  }
  return result;
}

function recordAudit(record) {
  const configuration = {
    event: ['diagnostic_ingested', record.receivedAt],
    tombstone: ['diagnostic_compacted', record.deletedAt],
    replay: ['diagnostic_replay_indexed', record.indexedAt],
  }[record.recordType];
  if (!configuration) throw serviceError('diagnostic_audit_invalid');
  return auditDescriptor(record.auditEventId, configuration[0], {
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    referenceId: record.messageId,
    operationDigest: record.recordDigest,
    resultDigest: record.payloadDigest,
    resultCount: 1,
    stateRevision: null,
    recordedAt: configuration[1],
  });
}

function authorizationAudit(record) {
  return stateAudit(record, 'diagnostic_authorization_state', record.principalId, null, null);
}

function consentAudit(record) {
  return stateAudit(
    record, 'diagnostic_consent_state',
    consentReference(record.customerId, record.deploymentId),
    record.customerId, record.deploymentId,
  );
}

function customerGrantAudit(record) {
  return stateAudit(
    record, 'diagnostic_customer_grant_state',
    consentReference(record.customerId, record.deploymentId),
    record.customerId, record.deploymentId,
  );
}

function timeAudit(record) {
  return stateAudit(record, 'diagnostic_clock_advanced', timeReference(), null, null);
}

function quotaAudit(record) {
  return stateAudit(
    record, 'diagnostic_quota_claimed',
    quotaReference(record.customerId, record.deploymentId, record.day),
    record.customerId, record.deploymentId,
  );
}

function deletionStateAudit(record) {
  return stateAudit(
    record, 'diagnostic_deletion_state', record.jobId,
    record.customerId, record.deploymentId,
  );
}

function stateAudit(record, action, referenceId, customerId, deploymentId) {
  return auditDescriptor(record.auditEventId, action, {
    customerId,
    deploymentId,
    referenceId,
    operationDigest: record.recordDigest,
    resultDigest: record.recordDigest,
    resultCount: record.revision,
    stateRevision: record.revision,
    recordedAt: stateRecordedAt(record),
  });
}

function stateRecordedAt(record) {
  if (record.updatedAt) return record.updatedAt;
  if (record.issuedAt) return record.issuedAt;
  if (record.timeMs !== undefined) return iso(record.timeMs);
  return `${record.day}T00:00:00.000Z`;
}

function capabilityUseAudit(context, capability, nowMs, eventId = randomId(context)) {
  return auditDescriptor(eventId, 'diagnostic_capability_used', {
    customerId: capability.customerIds === '*' || capability.customerIds.length !== 1
      ? null : capability.customerIds[0],
    deploymentId: capability.deploymentId,
    referenceId: capability.capabilityId,
    operationDigest: capability.recordDigest,
    resultDigest: digest({
      principalId: capability.principalId,
      sessionId: capability.sessionId,
      purpose: capability.purpose,
    }),
    resultCount: 1,
    stateRevision: capability.authorizationRevision,
    recordedAt: iso(nowMs),
  });
}

function createAccessManifest(
  context, command, capability, priorCursor, snapshotHighWater, records, completed,
  pageAuditEventId, nowMs,
) {
  const pageItems = records.map((record, ordinal) => accessItem(record, ordinal));
  const attemptedCustomerIds = accessCustomerScopes(command, capability);
  const pageCountsByCustomer = new Map(customerCounts(records).map((item) => [
    item.customerId, item.count,
  ]));
  const pageCounts = attemptedCustomerIds.map((customerId) => ({
    customerId, count: pageCountsByCustomer.get(customerId) || 0,
  }));
  const cumulativeCounts = mergeCounts(
    priorCursor ? priorCursor.cumulativeCounts : [], pageCounts,
  );
  const cumulativeResultCount = (priorCursor ? priorCursor.cumulativeResultCount : 0)
    + records.length;
  if (!validCounts(cumulativeCounts, cumulativeResultCount)) {
    throw serviceError('diagnostic_access_manifest_invalid');
  }
  const manifestId = randomId(context);
  const pageNumber = priorCursor ? priorCursor.pageNumber + 1 : 1;
  const cumulativeByCustomer = new Map(
    cumulativeCounts.map((item) => [item.customerId, item.count]),
  );
  const customerManifests = pageCounts.map((item) => authenticate(
    context.auditAuthority, CUSTOMER_ACCESS_MANIFEST_DOMAIN, {
      schemaVersion: SCHEMA_VERSION,
      recordType: 'diagnostic_customer_access_manifest',
      customerManifestId: randomId(context),
      parentManifestId: manifestId,
      pageAuditEventId,
      mode: command.mode,
      capabilityId: capability.capabilityId,
      capabilityDigest: capability.recordDigest,
      principalRef: staffReference(context, 'principal', capability.principalId),
      sessionRef: staffReference(context, 'session', capability.sessionId),
      customerId: item.customerId,
      pageNumber,
      pageResultCount: item.count,
      cumulativeResultCount: cumulativeByCustomer.get(item.customerId),
      items: pageItems.filter((entry) => entry.customerId === item.customerId),
      snapshotHighWater: snapshotHighWater === null ? null : clone(snapshotHighWater),
      completed,
      issuedAt: iso(nowMs),
    },
  ));
  return authenticate(context.auditAuthority, ACCESS_MANIFEST_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'diagnostic_access_manifest',
    manifestId,
    pageAuditEventId,
    mode: command.mode,
    capabilityId: capability.capabilityId,
    capabilityDigest: capability.recordDigest,
    principalRef: staffReference(context, 'principal', capability.principalId),
    sessionRef: staffReference(context, 'session', capability.sessionId),
    ownerAuthAssertionDigest: capability.ownerAuthAssertion.recordDigest,
    supportCaseId: capability.supportCaseId,
    approvalId: capability.approvalId,
    authorizedCustomerIds: capability.customerIds === '*'
      ? '*' : [...capability.customerIds].sort(),
    pageNumber,
    pageCounts,
    cumulativeCounts,
    pageResultCount: records.length,
    pageItems,
    cumulativeResultCount,
    customerManifests,
    priorManifestDigest: priorCursor ? priorCursor.priorManifestDigest : null,
    snapshotHighWater: snapshotHighWater === null ? null : clone(snapshotHighWater),
    completed,
    issuedAt: iso(nowMs),
  });
}

function accessCustomerScopes(command, capability) {
  if (command.filters.customerId) return [command.filters.customerId];
  if (capability.customerIds === '*') throw serviceError('diagnostic_customer_scope_required');
  return [...capability.customerIds].sort();
}

function accessItem(record, ordinal) {
  const response = publicEvent(record);
  return Object.freeze({
    ordinal,
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    messageId: record.messageId,
    recordDigest: record.recordDigest,
    payloadDigest: record.payloadDigest,
    responseDigest: digest(response),
  });
}

function customerCounts(records) {
  const counts = new Map();
  for (const record of records) counts.set(record.customerId, (counts.get(record.customerId) || 0) + 1);
  return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right))
    .map(([customerId, count]) => ({ customerId, count }));
}

function mergeCounts(prior, page) {
  const counts = new Map(prior.map((item) => [item.customerId, item.count]));
  for (const item of page) counts.set(item.customerId, (counts.get(item.customerId) || 0) + item.count);
  return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right))
    .map(([customerId, count]) => ({ customerId, count }));
}

function validCounts(value, expectedTotal) {
  if (!Array.isArray(value) || value.length > MAX_CUSTOMER_SCOPE) return false;
  let previous = null;
  let total = 0;
  for (const item of value) {
    if (!item || Object.keys(item).sort().join(',') !== 'count,customerId'
        || typeof item.customerId !== 'string' || !CUSTOMER_ID_RE.test(item.customerId)
        || !Number.isSafeInteger(item.count) || item.count < 0
        || (previous !== null && previous.localeCompare(item.customerId) >= 0)) return false;
    previous = item.customerId;
    total += item.count;
  }
  return Number.isSafeInteger(total) && total === expectedTotal;
}

function accessRequestDigest(command, capability) {
  return digest({
    capabilityDigest: capability.recordDigest,
    mode: command.mode,
    filters: command.filters,
    limit: command.limit,
    cursor: command.cursor,
  });
}

function createAccessEvidence(
  context, requestDigest, capability, response, pageAudit, completionAudit, nowMs,
) {
  return authenticate(context.auditAuthority, ACCESS_EVIDENCE_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'diagnostic_access_evidence',
    requestDigest,
    capabilityId: capability.capabilityId,
    capabilityDigest: capability.recordDigest,
    accessManifest: clone(response.accessManifest),
    nextCursor: response.nextCursor,
    responseDigest: digest(response),
    pageAudit: clone(pageAudit),
    completionAudit: completionAudit === null ? null : clone(completionAudit),
    persistedAt: iso(nowMs),
  });
}

async function verifiedAccessEvidence(context, tx, value, requestDigest, capability, nowMs) {
  const evidence = verifyAuthenticated(
    context.auditAuthority, ACCESS_EVIDENCE_DOMAIN, value,
    accessEvidenceCoreKeys(), 'diagnostic_access_evidence_invalid',
  );
  if (evidence.schemaVersion !== SCHEMA_VERSION
      || evidence.recordType !== 'diagnostic_access_evidence'
      || evidence.requestDigest !== requestDigest
      || evidence.capabilityId !== capability.capabilityId
      || evidence.capabilityDigest !== capability.recordDigest
      || !canonicalIso(evidence.persistedAt)) {
    throw serviceError('diagnostic_access_evidence_invalid');
  }
  const manifest = verifyAuthenticated(
    context.auditAuthority, ACCESS_MANIFEST_DOMAIN, evidence.accessManifest,
    accessManifestCoreKeys(), 'diagnostic_access_evidence_invalid',
  );
  validateAccessManifest(context, manifest, capability);
  if (!hexDigest(evidence.responseDigest)
      || ((evidence.nextCursor === null) !== manifest.completed)
      || (evidence.nextCursor !== null
        && (typeof evidence.nextCursor !== 'string' || !CURSOR_RE.test(evidence.nextCursor)))) {
    throw serviceError('diagnostic_access_evidence_invalid');
  }
  const items = [];
  for (const item of manifest.pageItems) {
    const raw = await tx.readDiagnosticAccessRecord({
      customerId: item.customerId,
      deploymentId: item.deploymentId,
      messageId: item.messageId,
      recordDigest: item.recordDigest,
    });
    if (raw === null) throw serviceError('diagnostic_access_evidence_invalid');
    const record = await verifiedRecord(context, tx, raw, 'event');
    if (Date.parse(record.expiresAt) <= nowMs) {
      throw serviceError('diagnostic_access_evidence_invalid');
    }
    assertExactValue(accessItem(record, item.ordinal), item, 'diagnostic_access_evidence_invalid');
    items.push(publicEvent(record));
  }
  const response = deepFreeze({
    items,
    nextCursor: evidence.nextCursor,
    accessManifest: clone(manifest),
  });
  if (digest(response) !== evidence.responseDigest) {
    throw serviceError('diagnostic_access_evidence_invalid');
  }
  const pageAudit = auditSnapshot(context, evidence.pageAudit);
  const expectedAction = manifest.mode === 'export' ? 'diagnostics_exported' : 'diagnostics_viewed';
  if (pageAudit.eventId !== manifest.pageAuditEventId
      || pageAudit.action !== expectedAction
      || pageAudit.referenceId !== capability.capabilityId
      || pageAudit.resultDigest !== manifest.recordDigest
      || pageAudit.resultCount !== manifest.pageResultCount
      || pageAudit.stateRevision !== capability.authorizationRevision
      || pageAudit.recordedAt !== manifest.issuedAt
      || evidence.persistedAt !== manifest.issuedAt) {
    throw serviceError('diagnostic_access_evidence_invalid');
  }
  assertExactValue(
    await tx.readAuditDescriptor(pageAudit.eventId), pageAudit,
    'diagnostic_access_evidence_invalid',
  );
  const requiresCompletion = manifest.mode === 'export' && manifest.completed;
  if ((evidence.completionAudit !== null) !== requiresCompletion) {
    throw serviceError('diagnostic_access_evidence_invalid');
  }
  if (requiresCompletion) {
    const completion = auditSnapshot(context, evidence.completionAudit);
    if (completion.action !== 'diagnostics_export_completed'
        || completion.referenceId !== capability.capabilityId
        || completion.resultDigest !== manifest.recordDigest
        || completion.resultCount !== manifest.cumulativeResultCount
        || completion.stateRevision !== capability.authorizationRevision
        || completion.recordedAt !== manifest.issuedAt) {
      throw serviceError('diagnostic_access_evidence_invalid');
    }
    assertExactValue(
      await tx.readAuditDescriptor(completion.eventId), completion,
      'diagnostic_access_evidence_invalid',
    );
  }
  return response;
}

function validateAccessManifest(context, manifest, capability) {
  const expectedMode = capability.purpose === 'diagnostics:export' ? 'export' : 'view';
  const expectedCustomers = capability.customerIds === '*'
    ? '*' : [...capability.customerIds].sort();
  const expectedPrincipalRef = staffReference(context, 'principal', capability.principalId);
  const expectedSessionRef = staffReference(context, 'session', capability.sessionId);
  if (manifest.schemaVersion !== SCHEMA_VERSION
      || manifest.recordType !== 'diagnostic_access_manifest'
      || !uuid(manifest.manifestId) || !uuid(manifest.pageAuditEventId)
      || manifest.mode !== expectedMode
      || manifest.capabilityId !== capability.capabilityId
      || manifest.capabilityDigest !== capability.recordDigest
      || manifest.principalRef !== expectedPrincipalRef
      || manifest.sessionRef !== expectedSessionRef
      || manifest.ownerAuthAssertionDigest !== capability.ownerAuthAssertion.recordDigest
      || manifest.supportCaseId !== capability.supportCaseId
      || manifest.approvalId !== capability.approvalId
      || !sameValue(manifest.authorizedCustomerIds, expectedCustomers)
      || !Number.isSafeInteger(manifest.pageNumber) || manifest.pageNumber < 1
      || ((manifest.pageNumber === 1) !== (manifest.priorManifestDigest === null))
      || (manifest.priorManifestDigest !== null && !hexDigest(manifest.priorManifestDigest))
      || !Number.isSafeInteger(manifest.pageResultCount) || manifest.pageResultCount < 0
      || !Number.isSafeInteger(manifest.cumulativeResultCount)
      || manifest.cumulativeResultCount < manifest.pageResultCount
      || !validAccessItems(manifest.pageItems, manifest.pageResultCount)
      || !validCounts(manifest.pageCounts, manifest.pageResultCount)
      || !validCounts(manifest.cumulativeCounts, manifest.cumulativeResultCount)
      || !Array.isArray(manifest.customerManifests)
      || manifest.customerManifests.length !== manifest.pageCounts.length
      || (manifest.snapshotHighWater !== null && !validHighWater(manifest.snapshotHighWater))
      || typeof manifest.completed !== 'boolean'
      || !canonicalIso(manifest.issuedAt)) {
    throw serviceError('diagnostic_access_evidence_invalid');
  }
  const pageCounts = new Map(manifest.pageCounts.map((item) => [item.customerId, item.count]));
  const cumulativeCounts = new Map(
    manifest.cumulativeCounts.map((item) => [item.customerId, item.count]),
  );
  const seen = new Set();
  const actualPageCounts = new Map();
  for (const item of manifest.pageItems) {
    actualPageCounts.set(item.customerId, (actualPageCounts.get(item.customerId) || 0) + 1);
  }
  if ([...pageCounts].some(([customerId, count]) => (
    count !== (actualPageCounts.get(customerId) || 0)
  )) || [...actualPageCounts.keys()].some((customerId) => !pageCounts.has(customerId))) {
    throw serviceError('diagnostic_access_evidence_invalid');
  }
  for (const value of manifest.customerManifests) {
    const customer = verifyAuthenticated(
      context.auditAuthority, CUSTOMER_ACCESS_MANIFEST_DOMAIN, value,
      customerAccessManifestCoreKeys(), 'diagnostic_access_evidence_invalid',
    );
    if (customer.schemaVersion !== SCHEMA_VERSION
        || customer.recordType !== 'diagnostic_customer_access_manifest'
        || !uuid(customer.customerManifestId)
        || customer.parentManifestId !== manifest.manifestId
        || customer.pageAuditEventId !== manifest.pageAuditEventId
        || customer.mode !== manifest.mode
        || customer.capabilityId !== capability.capabilityId
        || customer.capabilityDigest !== capability.recordDigest
        || customer.principalRef !== expectedPrincipalRef
        || customer.sessionRef !== expectedSessionRef
        || !pageCounts.has(customer.customerId) || seen.has(customer.customerId)
        || (expectedCustomers !== '*' && !expectedCustomers.includes(customer.customerId))
        || customer.pageNumber !== manifest.pageNumber
        || customer.pageResultCount !== pageCounts.get(customer.customerId)
        || customer.cumulativeResultCount !== cumulativeCounts.get(customer.customerId)
        || !sameValue(
          customer.items,
          manifest.pageItems.filter((item) => item.customerId === customer.customerId),
        )
        || !sameValue(customer.snapshotHighWater, manifest.snapshotHighWater)
        || customer.completed !== manifest.completed
        || customer.issuedAt !== manifest.issuedAt) {
      throw serviceError('diagnostic_access_evidence_invalid');
    }
    seen.add(customer.customerId);
  }
}

function validAccessItems(value, expectedCount) {
  if (!Array.isArray(value) || value.length !== expectedCount || value.length > MAX_QUERY_LIMIT) {
    return false;
  }
  const records = new Set();
  for (let ordinal = 0; ordinal < value.length; ordinal += 1) {
    const item = value[ordinal];
    if (!item || Object.keys(item).sort().join(',') !== [
      'customerId', 'deploymentId', 'messageId', 'ordinal', 'payloadDigest',
      'recordDigest', 'responseDigest',
    ].sort().join(',')
        || item.ordinal !== ordinal
        || typeof item.customerId !== 'string' || !CUSTOMER_ID_RE.test(item.customerId)
        || !isDeploymentId(item.deploymentId)
        || !uuid(item.messageId) || !hexDigest(item.payloadDigest)
        || !hexDigest(item.recordDigest) || !hexDigest(item.responseDigest)
        || records.has(item.recordDigest)) return false;
    records.add(item.recordDigest);
  }
  return true;
}

function searchAudit(
  command, capability, query, records, nextCursor, accessManifest, eventId, nowMs,
) {
  return auditDescriptor(
    eventId,
    command.mode === 'export' ? 'diagnostics_exported' : 'diagnostics_viewed',
    {
      customerId: command.filters.customerId || null,
      deploymentId: command.filters.deploymentId || null,
      referenceId: capability.capabilityId,
      operationDigest: digest(query),
      resultDigest: accessManifest.recordDigest,
      resultCount: records.length,
      stateRevision: capability.authorizationRevision,
      recordedAt: iso(nowMs),
    },
  );
}

function exportCompletionAudit(
  context, command, capability, query, records, accessManifest, nowMs,
) {
  return auditDescriptor(randomId(context), 'diagnostics_export_completed', {
    customerId: command.filters.customerId || null,
    deploymentId: command.filters.deploymentId || null,
    referenceId: capability.capabilityId,
    operationDigest: digest(query),
    resultDigest: accessManifest.recordDigest,
    resultCount: accessManifest.cumulativeResultCount,
    stateRevision: capability.authorizationRevision,
    recordedAt: iso(nowMs),
  });
}

function accessReplayAudit(context, capability, evidence, manifest, nowMs) {
  return auditDescriptor(randomId(context), 'diagnostic_access_replayed', {
    customerId: null,
    deploymentId: null,
    referenceId: capability.capabilityId,
    operationDigest: evidence.recordDigest,
    resultDigest: manifest.recordDigest,
    resultCount: manifest.cumulativeResultCount,
    stateRevision: capability.authorizationRevision,
    recordedAt: iso(nowMs),
  });
}

function clockRecoveryAudit(context, capability, current, next, reasonCode, nowMs) {
  return auditDescriptor(randomId(context), 'diagnostic_clock_recovered', {
    customerId: null,
    deploymentId: null,
    referenceId: capability.capabilityId,
    operationDigest: digest({
      approvalId: capability.approvalId,
      ownerAuthEventId: capability.ownerAuthEventId,
      reasonCode,
      priorRecordDigest: current ? current.recordDigest : null,
    }),
    resultDigest: next.recordDigest,
    resultCount: 1,
    stateRevision: next.revision,
    recordedAt: iso(nowMs),
  });
}

function deletionBatchAudit(context, current, next, batch, nowMs) {
  return auditDescriptor(randomId(context), 'diagnostic_deletion_batch', {
    customerId: current.customerId,
    deploymentId: current.deploymentId,
    referenceId: current.jobId,
    operationDigest: digest({
      expectedJobDigest: current.recordDigest,
      snapshotHighWater: current.snapshotHighWater,
      after: current.nextAfter,
    }),
    resultDigest: digest({ deleted: batch.deleted, done: batch.done }),
    resultCount: batch.deleted.length,
    stateRevision: next.revision,
    recordedAt: iso(nowMs),
  });
}

function deletionCompletionAudit(context, job) {
  return auditDescriptor(randomId(context), 'diagnostic_deletion_completed', {
    customerId: job.customerId,
    deploymentId: job.deploymentId,
    referenceId: job.jobId,
    operationDigest: job.previewDigest,
    resultDigest: job.completion.recordDigest,
    resultCount: job.deletedCount,
    stateRevision: job.revision,
    recordedAt: job.completion.completedAt,
  });
}

function deletionReservationReleaseAudit(context, current, released, job, nowMs) {
  return auditDescriptor(randomId(context), 'diagnostic_deletion_reservation_released', {
    customerId: job.customerId,
    deploymentId: job.deploymentId,
    referenceId: job.jobId,
    operationDigest: current.recordDigest,
    resultDigest: released.recordDigest,
    resultCount: 1,
    stateRevision: released.revision,
    recordedAt: iso(nowMs),
  });
}

function deletionAudit(context, record, nowMs) {
  return mutationAudit(context, record, nowMs, 'diagnostic_tombstone_deleted');
}

function replayDeletionAudit(context, record, nowMs) {
  return mutationAudit(context, record, nowMs, 'diagnostic_replay_index_deleted');
}

function mutationAudit(context, record, nowMs, action) {
  return auditDescriptor(randomId(context), action, {
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    referenceId: record.messageId,
    operationDigest: record.recordDigest,
    resultDigest: record.payloadDigest,
    resultCount: 1,
    stateRevision: null,
    recordedAt: iso(nowMs),
  });
}

function auditDescriptor(eventId, action, fields) {
  const descriptor = {
    schemaVersion: SCHEMA_VERSION,
    eventId,
    action,
    customerId: fields.customerId,
    deploymentId: fields.deploymentId,
    referenceId: fields.referenceId,
    operationDigest: fields.operationDigest,
    resultDigest: fields.resultDigest,
    resultCount: fields.resultCount,
    stateRevision: fields.stateRevision,
    recordedAt: fields.recordedAt,
  };
  validateAuditDescriptor(descriptor);
  return deepFreeze(descriptor);
}

function auditSnapshot(context, value) {
  const descriptor = verifyAuthenticated(
    context.auditAuthority, AUDIT_DOMAIN, value, auditCoreKeys(),
    'diagnostic_audit_invalid',
  );
  validateAuditDescriptor(pick(descriptor, auditCoreKeys()));
  return descriptor;
}

function signedAudit(context, descriptor) {
  validateAuditDescriptor(descriptor);
  return authenticate(context.auditAuthority, AUDIT_DOMAIN, descriptor);
}

function validateAuditDescriptor(value) {
  assertExactKeys(value, [
    'action', 'customerId', 'deploymentId', 'eventId', 'operationDigest',
    'recordedAt', 'referenceId', 'resultCount', 'resultDigest', 'schemaVersion',
    'stateRevision',
  ], 'diagnostic_audit_invalid');
  if (value.schemaVersion !== SCHEMA_VERSION || !uuid(value.eventId)
      || !AUDIT_ACTIONS.has(value.action) || !referenceId(value.referenceId)
      || !hexDigest(value.operationDigest) || !hexDigest(value.resultDigest)
      || !canonicalIso(value.recordedAt) || !Number.isSafeInteger(value.resultCount)
      || value.resultCount < 0
      || (value.stateRevision !== null && (!Number.isSafeInteger(value.stateRevision)
        || value.stateRevision < 1))
      || (value.customerId !== null && (typeof value.customerId !== 'string'
        || !CUSTOMER_ID_RE.test(value.customerId)))
      || (value.deploymentId !== null && (typeof value.deploymentId !== 'string'
        || !isDeploymentId(value.deploymentId)))) {
    throw serviceError('diagnostic_audit_invalid');
  }
}

async function appendExactAudit(context, tx, descriptorCore) {
  const descriptor = signedAudit(context, descriptorCore);
  assertExactValue(await tx.appendAudit(descriptor), descriptor, 'diagnostic_audit_append_failed');
  assertExactValue(
    await tx.readAuditDescriptor(descriptor.eventId), descriptor,
    'diagnostic_audit_append_failed',
  );
  return descriptor;
}

async function assertLatestStateAudit(context, tx, expectedCore) {
  const query = stateAuditQuery(expectedCore);
  const value = await tx.readLatestStateAudit(query);
  assertAuditCore(context, value, expectedCore, 'diagnostic_state_audit_invalid');
  const highWater = await tx.readStateRevisionHighWater(query);
  if (highWater !== expectedCore.stateRevision) {
    throw serviceError('diagnostic_state_revision_rollback');
  }
}

function assertAuditCore(context, value, expectedCore, code) {
  const actual = auditSnapshot(context, value);
  assertExactValue(pick(actual, auditCoreKeys()), expectedCore, code);
  return actual;
}

async function assertNoLatestStateAudit(tx, query, code) {
  const value = await tx.readLatestStateAudit(query);
  if (value !== null) throw serviceError(code);
}

function stateAuditQuery(descriptor) {
  return {
    action: descriptor.action,
    customerId: descriptor.customerId,
    deploymentId: descriptor.deploymentId,
    referenceId: descriptor.referenceId,
  };
}

function timeAuditQuery() {
  return { action: 'diagnostic_clock_advanced', customerId: null, deploymentId: null, referenceId: timeReference() };
}

function quotaAuditQuery(customerId, deploymentId, day) {
  return {
    action: 'diagnostic_quota_claimed', customerId, deploymentId,
    referenceId: quotaReference(customerId, deploymentId, day),
  };
}

function deletionStateAuditQuery(value) {
  return {
    action: 'diagnostic_deletion_state', customerId: value.customerId,
    deploymentId: value.deploymentId, referenceId: value.intentId || value.jobId,
  };
}

function capabilityClaim(context, capability, auditEventId, nowMs) {
  return authenticate(context.integrityAuthority, CAPABILITY_CLAIM_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'capability_claim',
    capabilityId: capability.capabilityId,
    capabilityDigest: capability.recordDigest,
    principalId: capability.principalId,
    sessionId: capability.sessionId,
    purpose: capability.purpose,
    ownerAuthEventId: capability.ownerAuthEventId,
    credentialVersion: capability.credentialVersion,
    auditEventId,
    usedAt: iso(nowMs),
  });
}

function publicIngest(record) {
  const expiration = record.recordType === 'event'
    ? record.expiresAt
    : record.recordType === 'tombstone' ? record.expiredAt : record.idempotencyUntil;
  const state = record.recordType === 'event'
    ? 'retained' : record.recordType === 'tombstone' ? 'expired' : 'replay_indexed';
  return Object.freeze({
    messageId: record.messageId,
    payloadDigest: record.payloadDigest,
    receivedAt: record.receivedAt,
    expiresAt: expiration,
    state,
    duplicate: false,
  });
}

function publicEvent(record) {
  return deepFreeze({
    payload: clone(record.payload),
    payloadDigest: record.payloadDigest,
    receivedAt: record.receivedAt,
    expiresAt: record.expiresAt,
  });
}

async function transact(storage, methods, work) {
  let calls = 0;
  let completed = false;
  let captured;
  const sentinel = Object.freeze({ vendorDiagnosticTransaction: true });
  let returned;
  try {
    returned = await storage.transaction(async (tx) => {
      calls += 1;
      if (calls !== 1) throw serviceError('storage_invalid');
      requireMethods(tx, methods);
      captured = await work(tx);
      completed = true;
      return sentinel;
    });
  } catch (error) { throw normalizeError(error); }
  if (calls !== 1 || !completed || returned !== sentinel) throw serviceError('storage_invalid');
  return captured;
}

function requireMethods(tx, methods) {
  if (!tx || methods.some((method) => typeof tx[method] !== 'function')) {
    throw serviceError('storage_invalid');
  }
}

async function guarded(work) {
  try { return await work(); }
  catch (error) { throw normalizeError(error); }
}

function normalizeError(error) {
  return error && error[SERVICE_ERROR]
    ? error : serviceError('diagnostic_dependency_failed');
}

function assertReferenceRuntime() {
  if (String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production') {
    throw serviceError('vendor_diagnostic_reference_runtime_forbidden');
  }
}

function recordCoreKeys(recordType) {
  if (recordType === 'event') return eventCoreKeys();
  if (recordType === 'tombstone') return tombstoneCoreKeys();
  if (recordType === 'replay') return replayCoreKeys();
  throw serviceError('diagnostic_store_corrupt');
}

function eventCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'customerId', 'deploymentId', 'messageId',
    'payload', 'payloadDigest', 'authorizationCapabilityId',
    'authorizationPrincipalId', 'consentId', 'consentRevision',
    'consentRevocationRevision', 'consentDigest', 'receivedAt', 'expiresAt',
    'auditEventId',
  ];
}

function tombstoneCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'customerId', 'deploymentId', 'messageId',
    'payloadDigest', 'receivedAt', 'expiredAt', 'deletedAt', 'deleteAfter',
    'auditEventId',
  ];
}

function replayCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'customerId', 'deploymentId', 'messageId',
    'payloadDigest', 'receivedAt', 'indexedAt', 'idempotencyUntil', 'auditEventId',
  ];
}

function capabilityCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'capabilityId', 'principalId', 'sessionId',
    'principalType', 'purpose', 'customerIds', 'deploymentId',
    'ownerAuthEventId', 'ownerAuthAssertion', 'issuer', 'credentialPurpose', 'credentialVersion',
    'authorizationRevision', 'issuedAt', 'expiresAt', 'stepUpAt',
    'supportCaseId', 'approvalId',
  ];
}

function ownerAuthAssertionCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'assertionId', 'principalId', 'sessionId',
    'ownerAuthEventId', 'mfaEventId', 'issuer', 'credentialVersion',
    'authenticatedAt', 'mfaAt', 'expiresAt',
  ];
}

function authorizationCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'principalId', 'principalType', 'revision',
    'ownerAuthEventId', 'issuer', 'credentialPurpose', 'credentialVersion',
    'revocationRevision', 'status', 'updatedAt', 'expiresAt', 'auditEventId',
  ];
}

function capabilityClaimCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'capabilityId', 'capabilityDigest',
    'principalId', 'sessionId', 'purpose', 'ownerAuthEventId',
    'credentialVersion', 'auditEventId', 'usedAt',
  ];
}

function auditCoreKeys() {
  return [
    'schemaVersion', 'eventId', 'action', 'customerId', 'deploymentId',
    'referenceId', 'operationDigest', 'resultDigest', 'resultCount',
    'stateRevision', 'recordedAt',
  ];
}

function cursorCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'mode', 'allowedCustomerIds', 'filterDigest',
    'snapshotHighWater', 'sessionRef', 'credentialVersion', 'pageNumber',
    'principalRef', 'supportCaseId', 'approvalId',
    'cumulativeCounts', 'cumulativeResultCount', 'priorManifestDigest',
    'lastReceivedAt', 'lastMessageId', 'issuedAt', 'expiresAt',
  ];
}

function accessManifestCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'manifestId', 'pageAuditEventId', 'mode',
    'capabilityId', 'capabilityDigest', 'principalRef', 'sessionRef', 'ownerAuthAssertionDigest',
    'supportCaseId', 'approvalId', 'authorizedCustomerIds', 'pageNumber',
    'pageCounts', 'cumulativeCounts', 'pageResultCount', 'cumulativeResultCount',
    'pageItems', 'customerManifests', 'priorManifestDigest', 'snapshotHighWater',
    'completed', 'issuedAt',
  ];
}

function customerAccessManifestCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'customerManifestId', 'parentManifestId',
    'pageAuditEventId', 'mode', 'capabilityId', 'capabilityDigest',
    'principalRef', 'sessionRef', 'customerId', 'pageNumber', 'pageResultCount',
    'cumulativeResultCount', 'items', 'snapshotHighWater', 'completed', 'issuedAt',
  ];
}

function accessEvidenceCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'requestDigest', 'capabilityId',
    'capabilityDigest', 'accessManifest', 'nextCursor', 'responseDigest', 'pageAudit',
    'completionAudit', 'persistedAt',
  ];
}

function consentCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'channel', 'consentId', 'customerId',
    'deploymentId', 'enabled', 'expiresAt', 'retentionDays', 'revision',
    'revocationRevision', 'updatedAt', 'usePolicy', 'customerGrantId',
    'customerGrantDigest', 'customerGrantRevision',
    'customerGrantRevocationRevision', 'auditEventId',
  ];
}

function customerGrantCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'channel', 'grantId', 'customerId',
    'deploymentId', 'enabled', 'revision', 'revocationRevision',
    'issuedAt', 'expiresAt', 'auditEventId',
  ];
}

function deletionIntentCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'intentId', 'customerId', 'deploymentId',
    'channel', 'customerGrantId', 'customerGrantDigest',
    'customerGrantRevision', 'scopeRevision', 'subjectDigest', 'reasonCode',
    'issuedAt', 'expiresAt',
  ];
}

function deletionJobCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'jobId', 'intentDigest', 'customerId',
    'deploymentId', 'customerGrantId', 'customerGrantDigest',
    'customerGrantRevision', 'scopeRevision', 'intentExpiresAt', 'status',
    'terminalReasonCode', 'revision',
    'previewCount', 'snapshotHighWater', 'nextAfter', 'batchCount',
    'deletedCount', 'previewDigest', 'approvalId', 'supportCaseId',
    'completion', 'updatedAt', 'auditEventId',
  ];
}

function deletionReservationCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'customerId', 'deploymentId', 'jobId',
    'intentDigest', 'active', 'leaseId', 'leaseExpiresAt', 'releaseReason',
    'revision', 'updatedAt',
  ];
}

function deletionCompletionCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'jobId', 'intentDigest', 'customerId',
    'deploymentId', 'previewDigest', 'deletedCount', 'batchCount',
    'approvalId', 'completedAt',
  ];
}

function timeCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'revision', 'timeMs',
    'destructiveApprovedMs', 'auditEventId',
  ];
}

function quotaCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'customerId', 'deploymentId', 'day',
    'count', 'limit', 'revision', 'updatedAt', 'auditEventId',
  ];
}

function checkedProof(value, expectedKeyId, code = 'integrity_authority_invalid') {
  if (value && typeof value.then === 'function') throw serviceError(code);
  const proof = plainSnapshot(value, code);
  assertExactKeys(proof, ['keyId', 'mac'], code);
  const encoded = proof.mac;
  if (proof.keyId !== expectedKeyId || typeof proof.keyId !== 'string'
      || !KEY_ID_RE.test(proof.keyId)
      || typeof encoded !== 'string' || encoded.length !== 44
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw serviceError(code);
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== encoded) throw serviceError(code);
  return deepFreeze(proof);
}

function checkedVerificationProof(value, code) {
  if (value && typeof value.then === 'function') throw serviceError(code);
  const proof = plainSnapshot(value, code);
  assertExactKeys(proof, ['keyId', 'mac'], code);
  const encoded = proof.mac;
  if (typeof proof.keyId !== 'string' || !KEY_ID_RE.test(proof.keyId)
      || typeof encoded !== 'string' || encoded.length !== 44
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw serviceError(code);
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== encoded) throw serviceError(code);
  return deepFreeze(proof);
}

function checkedCustomerIds(value, code) {
  if (value === '*') return;
  if (!Array.isArray(value) || !value.length || value.length > MAX_CUSTOMER_SCOPE
      || value.some((item) => typeof item !== 'string' || !CUSTOMER_ID_RE.test(item))
      || !strictSorted(value)) throw serviceError(code);
}

function checkedScope(customerId, deploymentId, code) {
  if (typeof customerId !== 'string' || !CUSTOMER_ID_RE.test(customerId)
      || !isDeploymentId(deploymentId)) {
    throw serviceError(code);
  }
}

function checkSetFilter(filters, field, allowed) {
  if (filters[field] !== undefined && !allowed.has(filters[field])) {
    throw serviceError('diagnostic_query_invalid');
  }
}

function checkTimeFilter(filters, field) {
  if (filters[field] !== undefined && !canonicalIso(filters[field])) {
    throw serviceError('diagnostic_query_invalid');
  }
}

function boundedList(value, limit, code) {
  const list = plainSnapshot(value, code);
  if (!Array.isArray(list) || list.length > limit) throw serviceError(code);
  return list;
}

function boundedInteger(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw serviceError(code);
  }
  return value;
}

function strictSorted(value) {
  return value.every((item, index) => index === 0 || value[index - 1].localeCompare(item) < 0);
}

function canonicalIso(value) {
  if (typeof value !== 'string' || value.length !== 24) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= MAX_ISO_TIME_MS
    && iso(parsed) === value;
}

function randomId(context) {
  let value;
  try { value = context.randomUUID(); }
  catch { throw serviceError('diagnostic_dependency_failed'); }
  if (!uuid(value)) throw serviceError('random_source_invalid');
  return value;
}

function digest(value) {
  return crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex');
}

function staffReference(context, kind, value) {
  let proof;
  try {
    proof = context.auditAuthority.sign(STAFF_REFERENCE_DOMAIN, canonical({
      kind, value,
    }));
  } catch { throw serviceError('diagnostic_access_manifest_invalid'); }
  if (!proof || typeof proof.keyId !== 'string' || typeof proof.mac !== 'string') {
    throw serviceError('diagnostic_access_manifest_invalid');
  }
  return digest({ keyId: proof.keyId, mac: proof.mac });
}

function canonical(value) {
  try { return protocol.canonicalJson(value); }
  catch { throw serviceError('diagnostic_serialization_invalid'); }
}

function clone(value) {
  return plainSnapshot(value, 'diagnostic_serialization_invalid');
}

function sameValue(left, right) {
  try { return canonical(left) === canonical(right); }
  catch { return false; }
}

function assertExactValue(value, expected, code) {
  const snapshot = plainSnapshot(value, code);
  if (!sameValue(snapshot, expected)) throw serviceError(code);
  return snapshot;
}

function assertExactKeys(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) {
    throw serviceError(code);
  }
}

function plainSnapshot(value, code) {
  try { return snapshotNode(value, 0, { bytes: 0, nodes: 0 }, code); }
  catch (error) { throw error && error[SERVICE_ERROR] ? error : serviceError(code); }
}

function snapshotNode(value, depth, budget, code) {
  budget.nodes += 1;
  if (budget.nodes > MAX_DOCUMENT_NODES || depth > MAX_DOCUMENT_DEPTH) throw serviceError(code);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') return snapshotString(value, budget, code);
  if (!value || typeof value !== 'object') throw serviceError(code);
  const prototype = Object.getPrototypeOf(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Array.isArray(value)) return snapshotArray(prototype, descriptors, depth, budget, code);
  return snapshotObject(prototype, descriptors, depth, budget, code);
}

function snapshotString(value, budget, code) {
  const bytes = Buffer.byteLength(value, 'utf8');
  budget.bytes += bytes;
  if (bytes > MAX_STRING_BYTES || budget.bytes > MAX_DOCUMENT_BYTES) throw serviceError(code);
  return value;
}

function snapshotArray(prototype, descriptors, depth, budget, code) {
  if (prototype !== Array.prototype || symbolKeys(descriptors).length) throw serviceError(code);
  const names = Object.getOwnPropertyNames(descriptors);
  const lengthDescriptor = descriptors.length;
  if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, 'value')
      || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0
      || lengthDescriptor.value > MAX_DOCUMENT_NODES
      || names.length !== lengthDescriptor.value + 1) throw serviceError(code);
  const result = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!dataDescriptor(descriptor, true)) throw serviceError(code);
    result.push(snapshotNode(descriptor.value, depth + 1, budget, code));
  }
  return result;
}

function snapshotObject(prototype, descriptors, depth, budget, code) {
  if ((prototype !== Object.prototype && prototype !== null) || symbolKeys(descriptors).length) {
    throw serviceError(code);
  }
  const result = {};
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (FORBIDDEN_KEYS.has(key) || !dataDescriptor(descriptor, true)) throw serviceError(code);
    snapshotString(key, budget, code);
    result[key] = snapshotNode(descriptor.value, depth + 1, budget, code);
  }
  return result;
}

function dataDescriptor(descriptor, enumerable) {
  return Boolean(descriptor && descriptor.enumerable === enumerable
    && Object.hasOwn(descriptor, 'value') && !descriptor.get && !descriptor.set);
}

function symbolKeys(value) { return Reflect.ownKeys(value).filter((key) => typeof key === 'symbol'); }

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function pick(value, keys) {
  const result = {};
  for (const key of keys) result[key] = value[key];
  return result;
}

function scope(value) { return { customerId: value.customerId, deploymentId: value.deploymentId }; }
function scopeMessage(value) { return { ...scope(value), messageId: value.messageId }; }
function customerAllowed(customerId, allowed) { return allowed === '*' || allowed.includes(customerId); }
function timeReference() { return digest({ kind: 'vendor_diagnostic_time_high_water' }); }
function quotaReference(customerId, deploymentId, day) {
  return digest({ kind: 'vendor_diagnostic_quota', customerId, deploymentId, day });
}
function consentReference(customerId, deploymentId) {
  return digest({ kind: 'vendor_diagnostic_consent', customerId, deploymentId, channel: 'diagnostics' });
}
function uuid(value) { return typeof value === 'string' && value.length === 36 && UUID_RE.test(value); }
function hexDigest(value) { return typeof value === 'string' && value.length === 64 && /^[a-f0-9]{64}$/.test(value); }
function referenceId(value) { return uuid(value) || hexDigest(value); }
function iso(value) { return new Date(value).toISOString(); }

function serviceError(code) {
  const error = new Error(SERVICE_ERROR_MESSAGE);
  error.code = code;
  Object.defineProperty(error, SERVICE_ERROR, { value: true });
  return error;
}

module.exports = {
  SCHEMA_VERSION,
  MAX_CLOCK_SKEW_MS,
  MAX_EVENT_AGE_MS,
  TOMBSTONE_RETENTION_MS,
  IDEMPOTENCY_HORIZON_MS,
  KEY_RETENTION_MARGIN_MS,
  MIN_RETENTION_DAYS,
  MAX_RETENTION_DAYS,
  MAX_QUERY_LIMIT,
  DEFAULT_DAILY_EVENT_LIMIT,
  MAX_DOCUMENT_BYTES,
  MAX_DESTRUCTIVE_FORWARD_JUMP_MS,
  MAX_STEP_UP_AGE_MS,
  STORAGE_CONTRACT_VERSION,
  RECORD_DOMAIN,
  TIME_DOMAIN,
  QUOTA_DOMAIN,
  CONSENT_DOMAIN,
  AUTHORIZATION_DOMAIN,
  CAPABILITY_DOMAIN,
  OWNER_AUTH_ASSERTION_DOMAIN,
  CAPABILITY_CLAIM_DOMAIN,
  CUSTOMER_GRANT_DOMAIN,
  AUDIT_DOMAIN,
  CURSOR_DOMAIN,
  DELETION_INTENT_DOMAIN,
  DELETION_JOB_DOMAIN,
  DELETION_COMPLETION_DOMAIN,
  DELETION_RESERVATION_DOMAIN,
  ACCESS_MANIFEST_DOMAIN,
  createVendorDiagnosticIntelligence,
};
