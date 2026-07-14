'use strict';

const crypto = require('node:crypto');
const stateEngine = require('./connected-entitlement-state');
const protocol = require('./vendor-control-protocol');
const {
  isConnectedHeartbeatTransactionCoordinator,
} = require('./connected-heartbeat-apply-store');
const { normalizePublicKeys, verifySignedArtifact } = require('./vendor-signed-artifact');

const STATE_ACTIONS = Object.freeze([
  'CONNECTED_ENTITLEMENT_APPLIED',
  'CONNECTED_ENTITLEMENT_REDELIVERED',
  'CONNECTED_ENTITLEMENT_FAILURE_RECORDED',
]);
const ACK_ACTIONS = Object.freeze([
  'CONNECTED_ENTITLEMENT_ACK_QUEUED',
  'CONNECTED_ENTITLEMENT_ACK_REUSED',
  'CONNECTED_ENTITLEMENT_ACK_RETRY',
  'CONNECTED_ENTITLEMENT_ACK_REJECTED',
  'CONNECTED_ENTITLEMENT_ACKNOWLEDGED',
]);
const ACK_LEDGER_ACTIONS = Object.freeze([
  'CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED',
]);
const RETRY_BASE_MS = 5_000;
const RETRY_MAX_MS = 60 * 60 * 1000;
const ACK_PENDING_HARD_LIMIT = 1024;
const ACK_ORDINARY_PENDING_LIMIT = 1020;
const ACK_BACKLOG_BLOCK_THRESHOLD = 1000;
const ACK_LIVE_HISTORY_LIMIT = ACK_PENDING_HARD_LIMIT + 3;
const ACK_ARCHIVE_RETAINED_LIMIT = 64;
const ACK_ARCHIVE_MUTATION_RETAINED_LIMIT = 128;
const EMPTY_ARCHIVE_DIGEST = crypto.createHash('sha256')
  .update('redactwall.connected-ack-archive.empty.v2', 'utf8').digest('hex');
const EMPTY_ARCHIVE_MUTATION_DIGEST = crypto.createHash('sha256')
  .update('redactwall.connected-ack-archive-mutations.empty.v2', 'utf8').digest('hex');
const SQLITE_ARCHIVE_CATALOG_NAMES = Object.freeze([
  'connected_ack_archive',
  'connected_ack_archive_mutations',
  'connected_ack_archive_no_update',
  'connected_ack_archive_record_delete',
  'connected_ack_archive_record_insert',
  'connected_ack_archive_record_update',
  'connected_ack_archive_mutations_no_replace',
  'connected_ack_archive_mutations_no_update',
  'idx_connected_ack_archive_mutation_scope',
  'idx_connected_ack_archive_scope',
]);
const SQLITE_RESERVED_AUTHORITY_RELATIONS = Object.freeze([
  'audit',
  'connected_entitlement_state',
  'connected_ack_outbox',
  'connected_ack_archive',
  'connected_ack_archive_mutations',
  'connected_ack_health',
]);
const SQLITE_RESERVED_AUTHORITY_OBJECTS = Object.freeze([
  ...SQLITE_RESERVED_AUTHORITY_RELATIONS,
  ...SQLITE_ARCHIVE_CATALOG_NAMES,
  'idx_connected_ack_pending',
  'idx_audit_connected_authority',
  'idx_audit_connected_ack',
  'idx_audit_connected_authority_action',
  'idx_audit_connected_ack_action',
]);
const SQLITE_ARCHIVE_CATALOG_IDENTITY =
  '73083b854241b18b60730a94277428f8eebe71049edaa5877b1c1130b7028de2';
const ACK_RETRYABLE_FAILURES = Object.freeze(new Set([
  'transport_unavailable', 'transport_ambiguous', 'rate_limited',
]));
const ACK_TERMINAL_FAILURES = Object.freeze(new Set(
  protocol.FAILURE_CLASSES.filter((value) => !ACK_RETRYABLE_FAILURES.has(value)),
));
const CAPACITY_RESTRICTION_CLASSIFICATIONS = Object.freeze(new Set([
  'status_paused',
  'status_revoked',
  'seat_reduction',
  'feature_reduction',
  'capacity_restriction',
]));
const FAILURE_KEYS = Object.freeze(new Set([
  'customerId', 'deploymentId', 'failureClass', 'nowMs', 'preserveTrustedTime',
]));
const ACK_RESULT_KEYS = Object.freeze(new Set([
  'accepted', 'customerId', 'deploymentId', 'failureClass', 'id', 'nowMs', 'payloadDigest',
]));
const ACK_LINEAGE_KEYS = Object.freeze([
  'id', 'lifecycleStage', 'payloadDigest', 'targetDigest', 'targetKind', 'targetVersion',
]);

function createConnectedEntitlementStore(options = {}) {
  const ctx = context(options);
  const apply = archiveSafeTransaction(ctx, (input) => applyInTransaction(ctx, input));
  const recordFailure = archiveSafeTransaction(ctx, (input) => failureInTransaction(ctx, input));
  const recordAckResult = archiveSafeTransaction(ctx, (input) => ackResultInTransaction(ctx, input));
  const exactReplay = archiveReadTransaction(ctx, (input) => assertExactReplay(ctx, input));
  const getState = archiveReadTransaction(
    ctx, (customerId, deploymentId) => readState(ctx, customerId, deploymentId),
  );
  const disposition = archiveReadTransaction(
    ctx, (customerId, deploymentId, input) => entitlementDisposition(
      ctx, customerId, deploymentId, input,
    ),
  );
  const health = archiveReadTransaction(
    ctx, (customerId, deploymentId) => acknowledgementHealth(
      ctx, customerId, deploymentId,
    ),
  );
  const pending = archiveReadTransaction(ctx, (input) => listPending(ctx, input));
  const acknowledgementLineages = archiveReadTransaction(
    ctx, (input) => assertAcknowledgementLineages(ctx, input),
  );
  return Object.freeze({
    applyEntitlement: apply,
    assertExactReplay: exactReplay,
    recordFailure,
    recordAckResult,
    getState,
    disposition,
    acknowledgementHealth: health,
    listPendingAcknowledgements: pending,
    assertAcknowledgementLineages: acknowledgementLineages,
  });
}

function archiveReadTransaction(ctx, callback) {
  const transaction = ctx.driver.transaction((...args) => {
    lockAuthority(ctx);
    return callback(...args);
  });
  if (typeof transaction !== 'function') {
    throw new TypeError('connected entitlement read transaction is required');
  }
  return transaction;
}

function archiveSafeTransaction(ctx, callback) {
  const transaction = ctx.driver.transaction(callback);
  return (...args) => {
    const integrityFailure = ctx.archiveIntegrityFailure;
    try {
      return transaction(...args);
    } catch (error) {
      if (!error || error.code !== 'CONNECTED_ENTITLEMENT_INTEGRITY') {
        ctx.archiveIntegrityFailure = integrityFailure;
      }
      throw error;
    }
  };
}

function assertExactReplay(ctx, input = {}) {
  assertStoreScope(ctx, input.customerId, input.deploymentId);
  const verified = verifyInputArtifact(ctx, input.signedArtifact);
  const entitlement = verified.payload;
  assertStoreScope(ctx, entitlement.customerId, entitlement.deploymentId);
  const current = readState(ctx, entitlement.customerId, entitlement.deploymentId);
  if (!current || !current.entitlement
      || current.entitlementVersion !== entitlement.entitlementVersion
      || current.entitlementDigest !== verified.payloadDigest
      || current.signingKeyId !== verified.keyId) {
    throw stateError('connected_response_replay_conflict');
  }
  const acknowledgements = acknowledgementPairForState(ctx, current);
  return Object.freeze({
    state: current,
    entitlement,
    artifactDigest: verified.artifactDigest,
    idempotent: true,
    replayOnly: true,
    outbox: publicAckRow(acknowledgements.applied),
    outboxes: Object.freeze({
      delivered: publicAckRow(acknowledgements.delivered),
      applied: publicAckRow(acknowledgements.applied),
    }),
  });
}

function context(options) {
  if (!options.driver || typeof options.driver.prepare !== 'function') throw new TypeError('driver is required');
  if (typeof options.appendAudit !== 'function') throw new TypeError('appendAudit is required');
  if (typeof options.authorityReference !== 'function') throw new TypeError('authorityReference is required');
  if (typeof options.ackReference !== 'function') throw new TypeError('ackReference is required');
  if (typeof options.verifyAuditState !== 'function') throw new TypeError('verifyAuditState is required');
  if (typeof options.verifyAuditEntry !== 'function') throw new TypeError('verifyAuditEntry is required');
  if (typeof options.verificationKeys !== 'function') throw new TypeError('verificationKeys is required');
  if (typeof options.offlinePublicKey !== 'function') throw new TypeError('offlinePublicKey is required');
  validateBinding(options.customerId, options.deploymentId);
  const driver = options.driver;
  const relation = trustedAuthorityRelations(driver);
  const ctx = {
    customerId: options.customerId,
    deploymentId: options.deploymentId,
    driver,
    appendAudit: receiverless(options.appendAudit),
    authorityReference: receiverless(options.authorityReference),
    ackReference: receiverless(options.ackReference),
    verifyAuditState: receiverless(options.verifyAuditState),
    verifyAuditEntry: receiverless(options.verifyAuditEntry),
    verificationKeys: receiverless(options.verificationKeys),
    offlinePublicKey: receiverless(options.offlinePublicKey),
    compositeCoordinator: checkedCoordinator(options.compositeCoordinator),
    archiveIntegrityFailure: false,
    stateRead: driver.prepare(`SELECT state_json, authority_ref FROM ${relation.state}
      WHERE customer_id = ? AND deployment_id = ?`),
    stateWrite: driver.prepare(`INSERT INTO ${relation.state} AS entitlement_state
      (customer_id, deployment_id, authority_ref, entitlement_version, entitlement_digest, state_json, updated_at)
      VALUES (@customerId, @deploymentId, @authorityRef, @version, @digest, @stateJson, @updatedAt)
      ON CONFLICT(customer_id, deployment_id) DO UPDATE SET
        entitlement_version = excluded.entitlement_version,
        entitlement_digest = excluded.entitlement_digest,
        state_json = excluded.state_json,
        updated_at = excluded.updated_at
      WHERE entitlement_state.authority_ref = excluded.authority_ref`),
    stateAudit: driver.prepare(`SELECT seq, action, connected_entry_action, entry FROM ${relation.audit}
      WHERE connected_authority_ref = ? AND connected_entry_action IN
        ('CONNECTED_ENTITLEMENT_APPLIED', 'CONNECTED_ENTITLEMENT_REDELIVERED',
         'CONNECTED_ENTITLEMENT_FAILURE_RECORDED')
      ORDER BY seq DESC LIMIT 1`),
    ackAudit: driver.prepare(`SELECT seq, action, connected_entry_action, entry FROM ${relation.audit}
      WHERE connected_ack_ref = ? AND connected_entry_action IN
        ('CONNECTED_ENTITLEMENT_ACK_QUEUED', 'CONNECTED_ENTITLEMENT_ACK_REUSED',
         'CONNECTED_ENTITLEMENT_ACK_RETRY', 'CONNECTED_ENTITLEMENT_ACK_REJECTED',
         'CONNECTED_ENTITLEMENT_ACKNOWLEDGED')
      ORDER BY seq DESC LIMIT 1`),
    ackAcknowledgedAudit: driver.prepare(`SELECT seq, action, connected_entry_action, entry FROM ${relation.audit}
      WHERE connected_ack_ref = ?
        AND connected_entry_action = 'CONNECTED_ENTITLEMENT_ACKNOWLEDGED'
      ORDER BY seq DESC LIMIT 1`),
    ackUpsert: driver.prepare(`INSERT INTO ${relation.outbox} AS ack_outbox
      (id, customer_id, deployment_id, target_kind, target_version, target_digest,
       lifecycle_stage, payload_json, payload_digest, status, attempts,
       next_attempt_at, created_at, updated_at)
      VALUES (@id, @customerId, @deploymentId, @targetKind, @targetVersion, @targetDigest,
       @lifecycleStage, @payloadJson, @payloadDigest, 'pending', 0, @now, @now, @now)
      ON CONFLICT(customer_id, deployment_id, target_kind, target_version, target_digest, lifecycle_stage)
      DO UPDATE SET updated_at = ack_outbox.updated_at
      RETURNING id, customer_id, deployment_id, target_kind, target_version, target_digest,
        lifecycle_stage, payload_json, payload_digest, status, failure_class, attempts,
        next_attempt_at, created_at, updated_at`),
    currentAck: driver.prepare(`SELECT id, customer_id, deployment_id, target_kind,
      target_version, target_digest, lifecycle_stage, payload_json, payload_digest,
      status, failure_class, attempts, next_attempt_at, created_at, updated_at
      FROM ${relation.outbox} WHERE customer_id = @customerId
        AND deployment_id = @deploymentId AND target_kind = @targetKind
        AND target_version = @targetVersion AND target_digest = @targetDigest
        AND lifecycle_stage = @lifecycleStage`),
    activeAcknowledgements: driver.prepare(`SELECT id, customer_id, deployment_id, target_kind,
      target_version, target_digest, lifecycle_stage, payload_json, payload_digest,
      status, failure_class, attempts, next_attempt_at, created_at, updated_at
      FROM ${relation.outbox} WHERE customer_id = @customerId
        AND deployment_id = @deploymentId AND status = 'pending'
      ORDER BY target_version,
        CASE lifecycle_stage WHEN 'delivered' THEN 0 ELSE 1 END,
        id LIMIT @integrityLimit`),
    historicalAcknowledgements: driver.prepare(`SELECT id, customer_id, deployment_id, target_kind,
      target_version, target_digest, lifecycle_stage, payload_json, payload_digest,
      status, failure_class, attempts, next_attempt_at, created_at, updated_at
      FROM ${relation.outbox} WHERE customer_id = @customerId
        AND deployment_id = @deploymentId AND status <> 'pending'
      ORDER BY target_version,
        CASE lifecycle_stage WHEN 'delivered' THEN 0 ELSE 1 END,
        target_digest, id LIMIT @integrityLimit`),
    acknowledgementArchivePage: driver.prepare(`SELECT archive_seq, id, customer_id,
      deployment_id, target_kind, target_version, target_digest, lifecycle_stage,
      payload_json, payload_digest, status, failure_class, attempts, next_attempt_at,
      created_at, updated_at, archived_at
      FROM ${relation.archive} WHERE customer_id = @customerId
        AND deployment_id = @deploymentId
      ORDER BY archive_seq LIMIT @pageSize`),
    acknowledgementArchiveInsert: driver.prepare(`INSERT INTO ${relation.archive}
      (id, customer_id, deployment_id, target_kind, target_version, target_digest,
       lifecycle_stage, payload_json, payload_digest, status, failure_class, attempts,
       next_attempt_at, created_at, updated_at, archived_at)
      VALUES (@id, @customerId, @deploymentId, @targetKind, @targetVersion, @targetDigest,
       @lifecycleStage, @payloadJson, @payloadDigest, 'acknowledged', NULL, @attempts,
       @nextAttemptAt, @createdAt, @updatedAt, @archivedAt)
      RETURNING archive_seq`),
    acknowledgementArchiveDelete: driver.prepare(`DELETE FROM ${relation.outbox}
      WHERE id = @id AND customer_id = @customerId AND deployment_id = @deploymentId
        AND payload_digest = @payloadDigest AND status = 'acknowledged'`),
    acknowledgementArchiveCompactDelete: driver.prepare(`DELETE FROM ${relation.archive}
      WHERE archive_seq = @archiveSeq AND id = @id AND customer_id = @customerId
        AND deployment_id = @deploymentId`),
    acknowledgementArchiveMutationSummary: driver.prepare(`SELECT scope_seq AS mutation_count,
      event_seq AS mutation_high_water
      FROM ${relation.archiveMutations} WHERE customer_id = @customerId
        AND deployment_id = @deploymentId
      ORDER BY scope_seq DESC LIMIT 1`),
    acknowledgementArchiveMutationPage: driver.prepare(`SELECT event_seq, scope_seq, customer_id,
      deployment_id, mutation_kind, archive_seq, archive_id
      FROM ${relation.archiveMutations} WHERE customer_id = @customerId
        AND deployment_id = @deploymentId
      ORDER BY scope_seq LIMIT @pageSize`),
    acknowledgementArchiveMutationExact: driver.prepare(`SELECT event_seq, scope_seq, customer_id,
      deployment_id, mutation_kind, archive_seq, archive_id
      FROM ${relation.archiveMutations} WHERE customer_id = @customerId
        AND deployment_id = @deploymentId AND event_seq = @eventSeq`),
    acknowledgementArchiveMutationCompactDelete: driver.prepare(`DELETE FROM
      ${relation.archiveMutations} WHERE event_seq = @eventSeq AND scope_seq = @scopeSeq
        AND customer_id = @customerId AND deployment_id = @deploymentId`),
    acknowledgementHealthRead: driver.prepare(`SELECT authority_ref, state_json
      FROM ${relation.health} WHERE customer_id = ? AND deployment_id = ?`),
    acknowledgementHealthWrite: driver.prepare(`INSERT INTO ${relation.health} AS ack_health
      (customer_id, deployment_id, authority_ref, state_json, updated_at)
      VALUES (@customerId, @deploymentId, @authorityRef, @stateJson, @updatedAt)
      ON CONFLICT(customer_id, deployment_id) DO UPDATE SET
        state_json = excluded.state_json,
        updated_at = excluded.updated_at
      WHERE ack_health.authority_ref = excluded.authority_ref`),
    acknowledgementHealthAudit: driver.prepare(`SELECT seq, action, connected_entry_action, entry
      FROM ${relation.audit} WHERE connected_authority_ref = ? AND connected_entry_action IN
        ('CONNECTED_ENTITLEMENT_ACK_LEDGER_UPDATED')
      ORDER BY seq DESC LIMIT 1`),
    ackExact: driver.prepare(`SELECT id, customer_id, deployment_id, target_kind,
      target_version, target_digest, lifecycle_stage, payload_json, payload_digest,
      status, failure_class, attempts, next_attempt_at, created_at, updated_at
      FROM ${relation.outbox} WHERE id = @id AND customer_id = @customerId
        AND deployment_id = @deploymentId AND payload_digest = @payloadDigest`),
    ackSucceeded: driver.prepare(`UPDATE ${relation.outbox}
      SET status = 'acknowledged', failure_class = NULL,
        attempts = attempts + 1, updated_at = @now
      WHERE id = @id AND customer_id = @customerId AND deployment_id = @deploymentId
        AND payload_digest = @payloadDigest AND status = 'pending'
      RETURNING id, customer_id, deployment_id, target_kind, target_version,
        target_digest, lifecycle_stage, payload_json, payload_digest, status,
        failure_class, attempts, next_attempt_at, created_at, updated_at`),
    ackFailed: driver.prepare(`UPDATE ${relation.outbox}
      SET failure_class = @failureClass, attempts = attempts + 1,
        next_attempt_at = @nextAttemptAt, updated_at = @now
      WHERE id = @id AND customer_id = @customerId AND deployment_id = @deploymentId
        AND payload_digest = @payloadDigest AND status = 'pending'
      RETURNING id, customer_id, deployment_id, target_kind, target_version,
        target_digest, lifecycle_stage, payload_json, payload_digest, status,
        failure_class, attempts, next_attempt_at, created_at, updated_at`),
    ackRejected: driver.prepare(`UPDATE ${relation.outbox}
      SET status = 'terminal', failure_class = @failureClass, attempts = attempts + 1,
        next_attempt_at = @now, updated_at = @now
      WHERE id = @id AND customer_id = @customerId AND deployment_id = @deploymentId
        AND payload_digest = @payloadDigest AND status = 'pending'
      RETURNING id, customer_id, deployment_id, target_kind, target_version,
        target_digest, lifecycle_stage, payload_json, payload_digest, status,
        failure_class, attempts, next_attempt_at, created_at, updated_at`),
  };
  Object.assign(ctx, archiveCatalogStatements(driver));
  return ctx;
}

function trustedAuthorityRelations(driver) {
  const schema = driver.kind === 'postgres' ? 'public' : 'main';
  return Object.freeze({
    state: `${schema}.connected_entitlement_state`,
    audit: `${schema}.audit`,
    outbox: `${schema}.connected_ack_outbox`,
    archive: `${schema}.connected_ack_archive`,
    archiveMutations: `${schema}.connected_ack_archive_mutations`,
    health: `${schema}.connected_ack_health`,
  });
}

function archiveCatalogStatements(driver) {
  if (driver.kind === 'postgres') {
    return {
      archiveCatalogKind: 'postgres',
      archiveCatalogRead: driver.prepare(`
        SELECT 'relation' AS object_type, c.relname AS object_name,
          c.oid::pg_catalog.text AS object_oid, c.xmin::pg_catalog.text AS object_xmin,
          pg_catalog.jsonb_build_object('relkind', c.relkind, 'rowSecurity', c.relrowsecurity,
            'forceRowSecurity', c.relforcerowsecurity)::pg_catalog.text AS object_detail
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname IN
          ('connected_ack_archive', 'connected_ack_archive_mutations')
        UNION ALL
        SELECT 'function', p.proname, p.oid::pg_catalog.text, p.xmin::pg_catalog.text,
          pg_catalog.jsonb_build_object('securityDefiner', p.prosecdef,
            'volatility', p.provolatile,
            'config', COALESCE(p.proconfig, ARRAY[]::pg_catalog.text[]),
            'source', p.prosrc)::pg_catalog.text
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname IN
          ('record_connected_ack_archive_mutation', 'reject_connected_ack_archive_mutation',
           'reject_connected_ack_archive_event_mutation')
        UNION ALL
        SELECT 'trigger', t.tgname, t.oid::pg_catalog.text, t.xmin::pg_catalog.text,
          pg_catalog.jsonb_build_object('enabled', t.tgenabled, 'type', t.tgtype,
            'functionOid', t.tgfoid::pg_catalog.text,
            'definition', pg_catalog.pg_get_triggerdef(t.oid, true))::pg_catalog.text
        FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND NOT t.tgisinternal
          AND c.relname IN ('connected_ack_archive', 'connected_ack_archive_mutations')
        UNION ALL
        SELECT 'policy', p.polname, p.oid::pg_catalog.text, p.xmin::pg_catalog.text,
          pg_catalog.jsonb_build_object('command', p.polcmd,
            'roles', p.polroles::pg_catalog.text,
            'using', pg_catalog.pg_get_expr(p.polqual, p.polrelid),
            'check', pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))::pg_catalog.text
        FROM pg_catalog.pg_policy p
        JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname IN ('connected_ack_archive', 'connected_ack_archive_mutations')
        UNION ALL
        SELECT 'index', ci.relname, ci.oid::pg_catalog.text, ci.xmin::pg_catalog.text,
          pg_catalog.jsonb_build_object(
            'definition', pg_catalog.pg_get_indexdef(i.indexrelid))::pg_catalog.text
        FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class ci ON ci.oid = i.indexrelid
          JOIN pg_catalog.pg_class ct ON ct.oid = i.indrelid
          JOIN pg_catalog.pg_namespace n ON n.oid = ct.relnamespace
        WHERE n.nspname = 'public' AND ci.relname IN
          ('idx_connected_ack_archive_scope', 'idx_connected_ack_archive_mutation_scope')
        ORDER BY object_type, object_name`),
    };
  }
  return {
    archiveCatalogKind: 'sqlite',
    archiveCatalogRead: driver.prepare(`SELECT type AS object_type, name AS object_name,
      tbl_name AS table_name, sql AS object_sql FROM main.sqlite_schema
      WHERE sql IS NOT NULL AND (
        name IN ('connected_ack_archive', 'connected_ack_archive_mutations',
          'idx_connected_ack_archive_mutation_scope', 'idx_connected_ack_archive_scope')
        OR (type = 'trigger' AND tbl_name IN
          ('connected_ack_archive', 'connected_ack_archive_mutations')))
      ORDER BY type, name`),
    archiveTempCatalogRead: driver.prepare(`SELECT type AS object_type, name AS object_name,
      tbl_name AS table_name FROM temp.sqlite_schema
      WHERE name IN (${SQLITE_RESERVED_AUTHORITY_OBJECTS
    .map((name) => `'${name}'`).join(', ')})
        OR ((type = 'trigger' OR type = 'index')
          AND tbl_name IN (${SQLITE_RESERVED_AUTHORITY_RELATIONS
    .map((name) => `'${name}'`).join(', ')}))
      ORDER BY type, name`),
  };
}

function applyInTransaction(ctx, input = {}) {
  assertStoreScope(ctx, input.customerId, input.deploymentId);
  lockAuthority(ctx);
  const verified = verifyInputArtifact(ctx, input.signedArtifact);
  const entitlement = verified.payload;
  assertStoreScope(ctx, entitlement.customerId, entitlement.deploymentId);
  if (input.customerId !== entitlement.customerId) throw stateError('customer_mismatch');
  if (input.deploymentId !== entitlement.deploymentId) throw stateError('deployment_mismatch');
  const current = readState(ctx, entitlement.customerId, entitlement.deploymentId)
    || stateEngine.initialState(entitlement.customerId, entitlement.deploymentId);
  const previousLedger = readAcknowledgementLedger(
    ctx, entitlement.customerId, entitlement.deploymentId, current.connectedEver,
  );
  const result = stateEngine.applyEntitlement(current, entitlement, {
    nowMs: input.nowMs,
    randomUUID: input.randomUUID,
    keyId: verified.keyId,
    clock: input.clock,
  });
  if (result.state.entitlementDigest !== verified.payloadDigest) throw integrityError();
  if (!result.idempotent && previousLedger.capacityRestriction) {
    assertCapacityRestrictionRetry(previousLedger.capacityRestriction, result.state);
  }
  if (!result.idempotent && !acknowledgementCapacityAvailable(
    previousLedger.pendingCount, current.entitlement, entitlement,
  )) {
    return latchCapacityRestriction(
      ctx, current, previousLedger, entitlement, verified.payloadDigest, input.nowMs,
    );
  }
  const archive = result.idempotent
    ? archiveCursor(previousLedger)
    : archiveAcknowledgedHistory(
      ctx, previousLedger, result.state.entitlementVersion, input.nowMs,
    );
  const authorityRef = referenceFor(ctx, result.state.customerId, result.state.deploymentId);
  writeState(ctx, result.state, authorityRef, input.nowMs);
  const acknowledgements = orderedAcknowledgements(result.acknowledgement);
  const acks = acknowledgements.map((value) => upsertAcknowledgement(ctx, value, input.nowMs));
  appendStateAudit(ctx, result.state, authorityRef, result.idempotent, verified.signatureDomain);
  acknowledgements.forEach((value, index) => {
    appendAckAudit(ctx, value, authorityRef, acks[index], result.idempotent);
  });
  writeAcknowledgementLedger(
    ctx, result.state.customerId, result.state.deploymentId,
    {
      ...archive,
      terminal: previousLedger.terminal,
      capacityRestriction: result.idempotent
        ? previousLedger.capacityRestriction : null,
      entitlementVersion: result.state.entitlementVersion,
    },
    input.nowMs,
  );
  return {
    ...result,
    artifactDigest: verified.artifactDigest,
    outbox: publicAckRow(acks[1]),
    outboxes: Object.freeze({
      delivered: publicAckRow(acks[0]),
      applied: publicAckRow(acks[1]),
    }),
  };
}

function acknowledgementCapacityAvailable(pendingCount, current, candidate) {
  const limit = strictStatusEscalation(current, candidate)
    ? ACK_PENDING_HARD_LIMIT : ACK_ORDINARY_PENDING_LIMIT;
  return pendingCount <= limit - 2;
}

function strictStatusEscalation(current, candidate) {
  if (!current) return false;
  return (current.status === 'active' && candidate.status === 'paused')
    || (['active', 'paused'].includes(current.status) && candidate.status === 'revoked');
}

function latchCapacityRestriction(ctx, current, ledger, entitlement, digest, nowMs) {
  const capacityRestriction = checkedCapacityRestriction({
    entitlementVersion: entitlement.entitlementVersion,
    entitlementDigest: digest,
    classification: capacityRestrictionClassification(current.entitlement, entitlement),
  });
  if (ledger.capacityRestriction
      && !sameCapacityRestriction(ledger.capacityRestriction, capacityRestriction)) {
    throw stateError('connected_capacity_latch_conflict');
  }
  if (!ledger.capacityRestriction) {
    writeAcknowledgementLedger(ctx, current.customerId, current.deploymentId, {
      ...archiveCursor(ledger),
      terminal: ledger.terminal,
      capacityRestriction,
      entitlementVersion: current.entitlementVersion,
    }, nowMs);
  }
  return Object.freeze({
    state: current,
    entitlement,
    idempotent: false,
    applied: false,
    capacityRestricted: true,
    outbox: null,
    outboxes: null,
  });
}

function capacityRestrictionClassification(current, candidate) {
  if (candidate.status === 'revoked' && current?.status !== 'revoked') return 'status_revoked';
  if (candidate.status === 'paused' && current?.status === 'active') return 'status_paused';
  if (current && candidate.seats < current.seats) return 'seat_reduction';
  const nextFeatures = new Set(candidate.features);
  if (current && current.features.some((feature) => !nextFeatures.has(feature))) {
    return 'feature_reduction';
  }
  return 'capacity_restriction';
}

function assertCapacityRestrictionRetry(restriction, state) {
  if (state.entitlementVersion !== restriction.entitlementVersion
      || state.entitlementDigest !== restriction.entitlementDigest) {
    throw stateError('connected_capacity_latch_conflict');
  }
}

function sameCapacityRestriction(left, right) {
  return left.entitlementVersion === right.entitlementVersion
    && left.entitlementDigest === right.entitlementDigest
    && left.classification === right.classification;
}

function failureInTransaction(ctx, input = {}) {
  const parsed = checkedFailureInput(input);
  assertStoreScope(ctx, parsed.customerId, parsed.deploymentId);
  lockAuthority(ctx);
  const current = readState(ctx, parsed.customerId, parsed.deploymentId)
    || stateEngine.initialState(parsed.customerId, parsed.deploymentId);
  const next = stateEngine.recordFailure(current, parsed.failureClass, {
    nowMs: parsed.nowMs,
    preserveTrustedTime: parsed.preserveTrustedTime,
  });
  const authorityRef = referenceFor(ctx, next.customerId, next.deploymentId);
  writeState(ctx, next, authorityRef, parsed.nowMs);
  appendFailureAudit(ctx, next, authorityRef);
  return next;
}

function checkedFailureInput(value) {
  if (!plainRecord(value) || Object.keys(value).some((key) => !FAILURE_KEYS.has(key))
      || typeof value.failureClass !== 'string'
      || (value.preserveTrustedTime !== undefined
        && typeof value.preserveTrustedTime !== 'boolean')) {
    throw stateError('failure_input_invalid');
  }
  const nowMs = checkedTime(value.nowMs);
  return { ...value, nowMs, preserveTrustedTime: value.preserveTrustedTime === true };
}

function ackResultInTransaction(ctx, input = {}) {
  const parsed = checkedAckResultInput(input);
  assertStoreScope(ctx, parsed.customerId, parsed.deploymentId);
  lockAuthority(ctx);
  const entitlementState = readState(ctx, parsed.customerId, parsed.deploymentId);
  const previousLedger = readAcknowledgementLedger(
    ctx, parsed.customerId, parsed.deploymentId, Boolean(entitlementState?.connectedEver),
  );
  const exact = ctx.ackExact.get(exactAckParams(parsed));
  if (!exact) return replayAcknowledgedResultFromAudit(ctx, parsed);
  const validatedExact = validateAckRow(exact);
  verifyAcknowledgementAnchor(ctx, validatedExact, referenceFor(
    ctx, validatedExact.customer_id, validatedExact.deployment_id,
  ));
  if (exact.status === 'acknowledged') return publicAckRow(exact);
  if (exact.status === 'terminal') return publicAckRow(exact);
  if (previousLedger.terminal) return null;
  if (exact.lifecycle_stage === 'applied' && !deliveredWasAccepted(ctx, exact)) return null;
  const nowMs = parsed.nowMs;
  const statement = parsed.accepted === true
    ? ctx.ackSucceeded
    : (ACK_RETRYABLE_FAILURES.has(parsed.failureClass) ? ctx.ackFailed : ctx.ackRejected);
  const changed = statement.get({
    ...exactAckParams(parsed),
    failureClass: parsed.failureClass,
    now: new Date(nowMs).toISOString(),
    nextAttemptAt: new Date(retryAt(nowMs, Number(exact.attempts))).toISOString(),
  });
  if (!changed) return null;
  const validated = validateAckRow(changed);
  appendAckResultAudit(ctx, validated);
  const terminal = previousLedger.terminal || (validated.status === 'terminal' ? {
    id: validated.id,
    payloadDigest: validated.payload_digest,
    failureClass: validated.failure_class,
  } : null);
  const archive = archiveCompletedAcknowledgement(
    ctx, previousLedger, validated, entitlementState?.entitlementVersion, nowMs,
  );
  writeAcknowledgementLedger(
    ctx, parsed.customerId, parsed.deploymentId,
    {
      ...archive,
      terminal,
      entitlementVersion: Number(validated.target_version),
    },
    parsed.nowMs,
  );
  return publicAckRow(validated);
}

function replayAcknowledgedResultFromAudit(ctx, input) {
  if (input.accepted !== true) return null;
  const ackRef = ctx.ackReference(input.id);
  const row = ctx.ackAcknowledgedAudit.get(ackRef);
  if (!row) return null;
  const anchor = verifiedAuditDetail(ctx, row, ACK_ACTIONS);
  const authorityRef = referenceFor(ctx, input.customerId, input.deploymentId);
  if (!plainRecord(anchor) || anchor.ackRef !== ackRef) throw integrityError();
  if (anchor.authorityRef !== authorityRef || anchor.payloadDigest !== input.payloadDigest) return null;
  const exactKeys = 'ackRef,attempts,authorityRef,createdAt,digest,entitlementVersion,'
    + 'failureClass,lifecycleStage,nextAttemptAt,payloadDigest,status,targetKind,updatedAt';
  if (row.action !== 'CONNECTED_ENTITLEMENT_ACKNOWLEDGED'
      || Object.keys(anchor).sort().join(',') !== exactKeys
      || anchor.status !== 'acknowledged' || anchor.failureClass !== null
      || !Number.isSafeInteger(anchor.entitlementVersion) || anchor.entitlementVersion < 1
      || !/^[a-f0-9]{64}$/.test(String(anchor.digest || ''))
      || anchor.targetKind !== protocol.CHANNEL_KINDS.ENTITLEMENT
      || !['delivered', 'applied'].includes(anchor.lifecycleStage)
      || !Number.isSafeInteger(anchor.attempts) || anchor.attempts < 1
      || !canonicalIsoTime(anchor.nextAttemptAt)
      || !canonicalIsoTime(anchor.createdAt) || !canonicalIsoTime(anchor.updatedAt)) {
    throw integrityError();
  }
  return {
    id: input.id,
    customerId: input.customerId,
    deploymentId: input.deploymentId,
    targetKind: anchor.targetKind,
    targetVersion: anchor.entitlementVersion,
    targetDigest: anchor.digest,
    lifecycleStage: anchor.lifecycleStage,
    payloadDigest: input.payloadDigest,
    status: anchor.status,
    failureClass: null,
    attempts: anchor.attempts,
    nextAttemptAt: anchor.nextAttemptAt,
  };
}

function checkedAckResultInput(value) {
  if (!plainRecord(value) || Object.keys(value).some((key) => !ACK_RESULT_KEYS.has(key))
      || typeof value.accepted !== 'boolean'
      || typeof value.id !== 'string' || value.id.length < 1
      || typeof value.customerId !== 'string' || value.customerId.length < 1
      || typeof value.deploymentId !== 'string' || value.deploymentId.length < 1
      || !/^[a-f0-9]{64}$/.test(String(value.payloadDigest || ''))) {
    throw stateError('ack_result_invalid');
  }
  if (value.accepted === true) {
    if (value.failureClass !== undefined && value.failureClass !== null) {
      throw stateError('ack_result_invalid');
    }
  } else if (!protocol.FAILURE_CLASSES.includes(value.failureClass)) {
    throw stateError('ack_result_invalid');
  }
  return {
    ...value,
    failureClass: value.accepted === true ? null : value.failureClass,
    nowMs: checkedTime(value.nowMs),
  };
}

function assertAcknowledgementLineages(ctx, input = {}) {
  if (!plainRecord(input)
      || Object.keys(input).sort().join(',') !== 'acknowledgements,customerId,deploymentId'
      || !Array.isArray(input.acknowledgements)
      || input.acknowledgements.length < 1
      || input.acknowledgements.length > ACK_PENDING_HARD_LIMIT * 2) {
    throw stateError('ack_lineage_invalid');
  }
  assertStoreScope(ctx, input.customerId, input.deploymentId);
  const state = readState(ctx, input.customerId, input.deploymentId);
  if (!state?.entitlement) throw integrityError();
  const seen = new Set();
  const lineages = input.acknowledgements.map((value) => {
    const expected = checkedAcknowledgementLineage(value);
    if (seen.has(expected.id)) throw stateError('ack_lineage_invalid');
    seen.add(expected.id);
    return verifiedAcknowledgementLineage(ctx, expected);
  });
  return Object.freeze(lineages);
}

function checkedAcknowledgementLineage(value) {
  if (!plainRecord(value) || Object.keys(value).sort().join(',') !== [...ACK_LINEAGE_KEYS].sort().join(',')
      || typeof value.id !== 'string' || value.id.length < 1
      || value.targetKind !== protocol.CHANNEL_KINDS.ENTITLEMENT
      || !Number.isSafeInteger(value.targetVersion) || value.targetVersion < 1
      || !/^[a-f0-9]{64}$/.test(String(value.targetDigest || ''))
      || !['delivered', 'applied'].includes(value.lifecycleStage)
      || !/^[a-f0-9]{64}$/.test(String(value.payloadDigest || ''))) {
    throw stateError('ack_lineage_invalid');
  }
  return Object.freeze({ ...value });
}

function verifiedAcknowledgementLineage(ctx, expected) {
  const row = ctx.ackExact.get({
    id: expected.id,
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    payloadDigest: expected.payloadDigest,
  });
  if (row) {
    const valid = validateAckRow(row);
    verifyAcknowledgementAnchor(ctx, valid, referenceFor(ctx, ctx.customerId, ctx.deploymentId));
    assertExpectedAcknowledgement(valid, expected);
    return Object.freeze({ ...expected, status: valid.status });
  }
  const ackRef = ctx.ackReference(expected.id);
  const auditRow = ctx.ackAcknowledgedAudit.get(ackRef);
  const anchor = verifiedAuditDetail(ctx, auditRow, ACK_ACTIONS);
  const authorityRef = referenceFor(ctx, ctx.customerId, ctx.deploymentId);
  if (!anchor || auditRow.action !== 'CONNECTED_ENTITLEMENT_ACKNOWLEDGED'
      || anchor.ackRef !== ackRef || anchor.authorityRef !== authorityRef
      || anchor.entitlementVersion !== expected.targetVersion
      || anchor.digest !== expected.targetDigest
      || anchor.targetKind !== expected.targetKind
      || anchor.lifecycleStage !== expected.lifecycleStage
      || anchor.payloadDigest !== expected.payloadDigest
      || anchor.status !== 'acknowledged' || anchor.failureClass !== null) {
    throw integrityError();
  }
  return Object.freeze({ ...expected, status: 'acknowledged' });
}

function assertExpectedAcknowledgement(row, expected) {
  if (row.id !== expected.id
      || row.target_kind !== expected.targetKind
      || Number(row.target_version) !== expected.targetVersion
      || row.target_digest !== expected.targetDigest
      || row.lifecycle_stage !== expected.lifecycleStage
      || row.payload_digest !== expected.payloadDigest) throw integrityError();
}

function deliveredWasAccepted(ctx, applied) {
  return deliveredAcknowledgement(ctx, applied).status === 'acknowledged';
}

function deliveredAcknowledgement(ctx, applied) {
  const row = ctx.currentAck.get({
    customerId: applied.customer_id,
    deploymentId: applied.deployment_id,
    targetKind: applied.target_kind,
    targetVersion: Number(applied.target_version),
    targetDigest: applied.target_digest,
    lifecycleStage: 'delivered',
  });
  if (!row) throw integrityError();
  const delivered = validateAckRow(row);
  verifyAcknowledgementAnchor(ctx, delivered, referenceFor(
    ctx, delivered.customer_id, delivered.deployment_id,
  ));
  return delivered;
}

function readState(ctx, customerId, deploymentId) {
  assertStoreScope(ctx, customerId, deploymentId);
  requireAuditHealthy(ctx);
  const authorityRef = referenceFor(ctx, customerId, deploymentId);
  const row = ctx.stateRead.get(customerId, deploymentId);
  const anchor = verifiedAuditDetail(ctx, ctx.stateAudit.get(authorityRef), STATE_ACTIONS);
  if (!row) {
    if (anchor) throw integrityError();
    return null;
  }
  if (row.authority_ref !== authorityRef) throw integrityError();
  let parsed;
  try { parsed = stateEngine.restoreState(JSON.parse(row.state_json), { customerId, deploymentId }); }
  catch { throw integrityError(); }
  if (!anchor || anchor.authorityRef !== authorityRef
      || anchor.stateDigest !== stateDigest(parsed)
      || Number(anchor.entitlementVersion) !== parsed.entitlementVersion) throw integrityError();
  if (parsed.entitlement) {
    requireCurrentAcknowledgements(ctx, parsed, authorityRef);
    const ledger = readAcknowledgementLedger(ctx, customerId, deploymentId, true);
    if (ledger.capacityRestriction
        && ledger.capacityRestriction.entitlementVersion <= parsed.entitlementVersion) {
      throw integrityError();
    }
  }
  return parsed;
}

function requireCurrentAcknowledgements(ctx, state, authorityRef) {
  const pair = acknowledgementPairForState(ctx, state);
  verifyAcknowledgementAnchor(ctx, pair.delivered, authorityRef);
  verifyAcknowledgementAnchor(ctx, pair.applied, authorityRef);
}

function acknowledgementPairForState(ctx, state) {
  const rows = {};
  for (const lifecycleStage of ['delivered', 'applied']) {
    const row = ctx.currentAck.get({
      customerId: state.customerId,
      deploymentId: state.deploymentId,
      targetKind: protocol.CHANNEL_KINDS.ENTITLEMENT,
      targetVersion: state.entitlementVersion,
      targetDigest: state.entitlementDigest,
      lifecycleStage,
    });
    if (!row) throw integrityError();
    rows[lifecycleStage] = validateAckRow(row);
  }
  return rows;
}

function verifyAcknowledgementAnchor(ctx, ack, authorityRef) {
  const ackRef = ctx.ackReference(ack.id);
  const anchor = verifiedAuditDetail(ctx, ctx.ackAudit.get(ackRef), ACK_ACTIONS);
  if (!anchor || anchor.authorityRef !== authorityRef
      || anchor.ackRef !== ackRef
      || anchor.entitlementVersion !== Number(ack.target_version)
      || anchor.digest !== ack.target_digest
      || anchor.targetKind !== ack.target_kind
      || anchor.lifecycleStage !== ack.lifecycle_stage
      || anchor.payloadDigest !== ack.payload_digest
      || anchor.status !== ack.status
      || (anchor.failureClass ?? null) !== (ack.failure_class ?? null)
      || anchor.attempts !== Number(ack.attempts)
      || anchor.nextAttemptAt !== ack.next_attempt_at
      || anchor.createdAt !== ack.created_at
      || anchor.updatedAt !== ack.updated_at) throw integrityError();
}

function orderedAcknowledgements(applied) {
  const delivered = protocol.assertChannel({
    ...applied,
    messageId: derivedDeliveryMessageId(applied.messageId),
    lifecycleStage: 'delivered',
    reasonCode: 'delivered',
  }, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
  return Object.freeze([delivered, applied]);
}

function derivedDeliveryMessageId(appliedMessageId) {
  const bytes = crypto.createHash('sha256')
    .update('redactwall.connected-entitlement-delivered-ack.v1\0', 'utf8')
    .update(String(appliedMessageId || ''), 'utf8').digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function writeState(ctx, state, authorityRef, nowMs) {
  const result = ctx.stateWrite.run({
    customerId: state.customerId,
    deploymentId: state.deploymentId,
    authorityRef,
    version: state.entitlementVersion,
    digest: state.entitlementDigest,
    stateJson: protocol.canonicalJson(state),
    updatedAt: isoTime(nowMs),
  });
  if (Number(result.changes) !== 1) throw integrityError();
}

function upsertAcknowledgement(ctx, acknowledgement, nowMs) {
  const payloadJson = protocol.canonicalJson(acknowledgement);
  const payloadDigest = sha256(payloadJson);
  const lookup = {
    customerId: acknowledgement.customerId,
    deploymentId: acknowledgement.deploymentId,
    targetKind: acknowledgement.targetKind,
    targetVersion: acknowledgement.targetVersion,
    targetDigest: acknowledgement.targetDigest,
    lifecycleStage: acknowledgement.lifecycleStage,
  };
  const existing = ctx.currentAck.get(lookup);
  if (existing) {
    const valid = validateAckRow(existing);
    verifyAcknowledgementAnchor(ctx, valid, referenceFor(
      ctx, valid.customer_id, valid.deployment_id,
    ));
    return valid;
  }
  const row = ctx.ackUpsert.get({
    id: acknowledgement.messageId,
    customerId: acknowledgement.customerId,
    deploymentId: acknowledgement.deploymentId,
    targetKind: acknowledgement.targetKind,
    targetVersion: acknowledgement.targetVersion,
    targetDigest: acknowledgement.targetDigest,
    lifecycleStage: acknowledgement.lifecycleStage,
    payloadJson,
    payloadDigest,
    now: isoTime(nowMs),
  });
  const valid = validateAckRow(row);
  assertExactAcknowledgement(valid, acknowledgement, payloadJson, payloadDigest);
  return valid;
}

function assertExactAcknowledgement(row, acknowledgement, payloadJson, payloadDigest) {
  if (row.id !== acknowledgement.messageId
      || row.payload_json !== payloadJson
      || row.payload_digest !== payloadDigest
      || row.customer_id !== acknowledgement.customerId
      || row.deployment_id !== acknowledgement.deploymentId
      || row.target_kind !== acknowledgement.targetKind
      || Number(row.target_version) !== acknowledgement.targetVersion
      || row.target_digest !== acknowledgement.targetDigest
      || row.lifecycle_stage !== acknowledgement.lifecycleStage) throw integrityError();
}

function appendStateAudit(ctx, state, authorityRef, idempotent, signatureDomain) {
  ctx.appendAudit({
    action: idempotent ? 'CONNECTED_ENTITLEMENT_REDELIVERED' : 'CONNECTED_ENTITLEMENT_APPLIED',
    actor: 'vendor_connector',
    connectedAuthorityRef: authorityRef,
    detail: JSON.stringify({
      authorityRef,
      entitlementVersion: state.entitlementVersion,
      status: state.entitlement.status,
      digest: state.entitlementDigest,
      stateDigest: stateDigest(state),
      signingKeyId: state.signingKeyId,
      signatureDomain,
    }),
  });
}

function appendAckAudit(ctx, acknowledgement, authorityRef, ack, idempotent) {
  const ackRef = ctx.ackReference(ack.id);
  ctx.appendAudit({
    action: idempotent ? 'CONNECTED_ENTITLEMENT_ACK_REUSED' : 'CONNECTED_ENTITLEMENT_ACK_QUEUED',
    actor: 'vendor_connector',
    connectedAuthorityRef: authorityRef,
    connectedAckRef: ackRef,
    detail: JSON.stringify({
      authorityRef,
      ackRef,
      entitlementVersion: acknowledgement.targetVersion,
      digest: acknowledgement.targetDigest,
      targetKind: acknowledgement.targetKind,
      lifecycleStage: acknowledgement.lifecycleStage,
      payloadDigest: ack.payload_digest,
      status: ack.status,
      failureClass: ack.failure_class ?? null,
      attempts: Number(ack.attempts),
      nextAttemptAt: ack.next_attempt_at,
      createdAt: ack.created_at,
      updatedAt: ack.updated_at,
    }),
  });
}

function appendFailureAudit(ctx, state, authorityRef) {
  ctx.appendAudit({
    action: 'CONNECTED_ENTITLEMENT_FAILURE_RECORDED',
    actor: 'vendor_connector',
    connectedAuthorityRef: authorityRef,
    detail: JSON.stringify({
      authorityRef,
      entitlementVersion: state.entitlementVersion,
      failureClass: state.failureClass,
      stateDigest: stateDigest(state),
    }),
  });
}

function appendAckResultAudit(ctx, row) {
  const authorityRef = referenceFor(ctx, row.customer_id, row.deployment_id);
  const ackRef = ctx.ackReference(row.id);
  const action = row.status === 'acknowledged'
    ? 'CONNECTED_ENTITLEMENT_ACKNOWLEDGED'
    : (row.status === 'terminal'
      ? 'CONNECTED_ENTITLEMENT_ACK_REJECTED' : 'CONNECTED_ENTITLEMENT_ACK_RETRY');
  ctx.appendAudit({
    action,
    actor: 'vendor_connector',
    connectedAuthorityRef: authorityRef,
    connectedAckRef: ackRef,
    detail: JSON.stringify({
      authorityRef,
      ackRef,
      entitlementVersion: Number(row.target_version),
      digest: row.target_digest,
      targetKind: row.target_kind,
      lifecycleStage: row.lifecycle_stage,
      payloadDigest: row.payload_digest,
      status: row.status,
      failureClass: row.failure_class ?? null,
      attempts: Number(row.attempts),
      nextAttemptAt: row.next_attempt_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }),
  });
}

function listPending(ctx, input = {}) {
  assertStoreScope(ctx, input.customerId, input.deploymentId);
  readState(ctx, input.customerId, input.deploymentId);
  const limit = Math.max(1, Math.min(100, Number(input.limit) || 20));
  const nowMs = checkedTime(input.nowMs);
  const ledger = readAcknowledgementLedger(ctx, input.customerId, input.deploymentId, true);
  if (ledger.terminal) return [];
  return ledger.activeRows.filter(({ valid, deliveryAccepted }) => (
    deliveryAccepted
      && Date.parse(valid.next_attempt_at) <= nowMs
  )).slice(0, limit).map(({ valid }) => ({
    id: valid.id,
    customerId: valid.customer_id,
    deploymentId: valid.deployment_id,
    payloadDigest: valid.payload_digest,
    acknowledgement: JSON.parse(valid.payload_json),
    failureClass: valid.failure_class ?? null,
    attempts: Number(valid.attempts),
    nextAttemptAt: valid.next_attempt_at,
  }));
}

function activeAcknowledgementRows(ctx, customerId, deploymentId) {
  const rows = ctx.activeAcknowledgements.all({
    customerId,
    deploymentId,
    integrityLimit: ACK_PENDING_HARD_LIMIT + 1,
  });
  if (rows.length > ACK_PENDING_HARD_LIMIT) throw integrityError();
  return rows.map((row) => {
    const valid = validateAckRow(row);
    verifyAcknowledgementAnchor(ctx, valid, referenceFor(
      ctx, valid.customer_id, valid.deployment_id,
    ));
    return {
      valid,
      deliveryAccepted: valid.lifecycle_stage === 'delivered'
        || deliveredWasAccepted(ctx, valid),
    };
  });
}

function acknowledgementHealth(ctx, customerId, deploymentId) {
  assertStoreScope(ctx, customerId, deploymentId);
  const state = readState(ctx, customerId, deploymentId);
  return acknowledgementLedgerHealth(readAcknowledgementLedger(
    ctx, customerId, deploymentId, Boolean(state?.entitlement),
  ));
}

function acknowledgementLedgerHealth(ledger) {
  if (ledger.terminal) {
    return Object.freeze({
      ok: false,
      reason: 'connected_ack_terminal_failure',
      failureClass: ledger.terminal.failureClass,
      id: ledger.terminal.id,
      payloadDigest: ledger.terminal.payloadDigest,
    });
  }
  if (ledger.capacityRestriction) {
    return Object.freeze({
      ok: false,
      reason: 'connected_entitlement_capacity_restriction',
      entitlementVersion: ledger.capacityRestriction.entitlementVersion,
      classification: ledger.capacityRestriction.classification,
    });
  }
  if (ledger.pendingCount >= ACK_BACKLOG_BLOCK_THRESHOLD) {
    return Object.freeze({
      ok: false,
      reason: 'connected_ack_backlog',
      pendingCount: ledger.pendingCount,
    });
  }
  return Object.freeze({ ok: true });
}

function entitlementDisposition(ctx, customerId, deploymentId, input) {
  const state = readState(ctx, customerId, deploymentId)
    || stateEngine.initialState(customerId, deploymentId);
  const result = stateEngine.disposition(state, input, { offlinePublicKey: ctx.offlinePublicKey });
  const health = acknowledgementLedgerHealth(readAcknowledgementLedger(
    ctx, customerId, deploymentId, Boolean(state.entitlement),
  ));
  if (health.ok) return result;
  return {
    ...result,
    protectedEgress: 'block',
    mode: 'blocked',
    reason: health.reason,
  };
}

function readAcknowledgementLedger(ctx, customerId, deploymentId, required) {
  requireAuditHealthy(ctx);
  const authorityRef = referenceFor(ctx, customerId, deploymentId);
  const row = ctx.acknowledgementHealthRead.get(customerId, deploymentId);
  const anchor = verifiedAuditDetail(
    ctx, ctx.acknowledgementHealthAudit.get(authorityRef), ACK_LEDGER_ACTIONS,
  );
  if (!row) {
    if (required || anchor) throw integrityError();
    const empty = {
      stateVersion: 4,
      customerId,
      deploymentId,
      pendingCount: 0,
      pendingDigest: pendingDigest([]),
      historicalCount: 0,
      historicalDigest: historicalDigest([]),
      archivedCount: 0,
      archivedDigest: EMPTY_ARCHIVE_DIGEST,
      archivedPrefixCount: 0,
      archivedPrefixHighWater: 0,
      archivedPrefixDigest: EMPTY_ARCHIVE_DIGEST,
      archiveMutationCount: 0,
      archiveMutationHighWater: 0,
      archiveMutationDigest: EMPTY_ARCHIVE_MUTATION_DIGEST,
      archiveMutationPrefixCount: 0,
      archiveMutationPrefixHighWater: 0,
      archiveMutationPrefixDigest: EMPTY_ARCHIVE_MUTATION_DIGEST,
      terminal: null,
      capacityRestriction: null,
      activeRows: [],
      historicalRows: [],
    };
    verifyArchivedHistory(ctx, empty);
    return empty;
  }
  if (row.authority_ref !== authorityRef || !anchor) throw integrityError();
  let parsed;
  try { parsed = checkedAcknowledgementLedger(JSON.parse(row.state_json), customerId, deploymentId); }
  catch { throw integrityError(); }
  const activeRows = activeAcknowledgementRows(ctx, customerId, deploymentId);
  const historicalRows = historicalAcknowledgementRows(ctx, customerId, deploymentId);
  const summary = acknowledgementSummary(activeRows);
  const history = acknowledgementHistorySummary(historicalRows);
  if (parsed.pendingCount !== summary.pendingCount
      || parsed.pendingDigest !== summary.pendingDigest
      || parsed.historicalCount !== history.historicalCount
      || parsed.historicalDigest !== history.historicalDigest
      || anchor.authorityRef !== authorityRef
      || anchor.archiveMutationCount !== parsed.archiveMutationCount
      || anchor.archiveMutationHighWater !== parsed.archiveMutationHighWater
      || anchor.archiveMutationDigest !== parsed.archiveMutationDigest
      || anchor.archivedPrefixCount !== parsed.archivedPrefixCount
      || anchor.archivedPrefixHighWater !== parsed.archivedPrefixHighWater
      || anchor.archivedPrefixDigest !== parsed.archivedPrefixDigest
      || anchor.archiveMutationPrefixCount !== parsed.archiveMutationPrefixCount
      || anchor.archiveMutationPrefixHighWater !== parsed.archiveMutationPrefixHighWater
      || anchor.archiveMutationPrefixDigest !== parsed.archiveMutationPrefixDigest
      || !sameNullableCapacityRestriction(
        anchor.capacityRestriction, parsed.capacityRestriction,
      )
      || anchor.stateDigest !== acknowledgementLedgerDigest(parsed)) throw integrityError();
  verifyArchivedHistory(ctx, parsed);
  if (parsed.terminal) verifyTerminalAcknowledgement(ctx, parsed.terminal, customerId, deploymentId);
  return { ...parsed, activeRows, historicalRows };
}

function writeAcknowledgementLedger(ctx, customerId, deploymentId, cursor, nowMs) {
  const authorityRef = referenceFor(ctx, customerId, deploymentId);
  const terminal = cursor.terminal;
  if (terminal) verifyTerminalAcknowledgement(ctx, terminal, customerId, deploymentId);
  const summary = acknowledgementSummary(activeAcknowledgementRows(ctx, customerId, deploymentId));
  const history = acknowledgementHistorySummary(
    historicalAcknowledgementRows(ctx, customerId, deploymentId),
  );
  const state = checkedAcknowledgementLedger({
    stateVersion: 4,
    customerId,
    deploymentId,
    ...summary,
    ...history,
    archivedCount: cursor.archivedCount,
    archivedDigest: cursor.archivedDigest,
    archivedPrefixCount: cursor.archivedPrefixCount,
    archivedPrefixHighWater: cursor.archivedPrefixHighWater,
    archivedPrefixDigest: cursor.archivedPrefixDigest,
    archiveMutationCount: cursor.archiveMutationCount,
    archiveMutationHighWater: cursor.archiveMutationHighWater,
    archiveMutationDigest: cursor.archiveMutationDigest,
    archiveMutationPrefixCount: cursor.archiveMutationPrefixCount,
    archiveMutationPrefixHighWater: cursor.archiveMutationPrefixHighWater,
    archiveMutationPrefixDigest: cursor.archiveMutationPrefixDigest,
    terminal: terminal ? { ...terminal } : null,
    capacityRestriction: cursor.capacityRestriction
      ? { ...cursor.capacityRestriction } : null,
  }, customerId, deploymentId);
  const result = ctx.acknowledgementHealthWrite.run({
    customerId,
    deploymentId,
    authorityRef,
    stateJson: protocol.canonicalJson(state),
    updatedAt: isoTime(nowMs),
  });
  if (Number(result.changes) !== 1) throw integrityError();
  ctx.appendAudit({
    action: ACK_LEDGER_ACTIONS[0],
    actor: 'vendor_connector',
    connectedAuthorityRef: authorityRef,
    detail: JSON.stringify({
      authorityRef,
      stateDigest: acknowledgementLedgerDigest(state),
      entitlementVersion: Number(cursor.entitlementVersion),
      pendingCount: state.pendingCount,
      historicalCount: state.historicalCount,
      archivedCount: state.archivedCount,
      archivedPrefixCount: state.archivedPrefixCount,
      archivedPrefixHighWater: state.archivedPrefixHighWater,
      archivedPrefixDigest: state.archivedPrefixDigest,
      archiveMutationCount: state.archiveMutationCount,
      archiveMutationHighWater: state.archiveMutationHighWater,
      archiveMutationDigest: state.archiveMutationDigest,
      archiveMutationPrefixCount: state.archiveMutationPrefixCount,
      archiveMutationPrefixHighWater: state.archiveMutationPrefixHighWater,
      archiveMutationPrefixDigest: state.archiveMutationPrefixDigest,
      terminalFailureClass: state.terminal?.failureClass || null,
      capacityRestriction: state.capacityRestriction,
    }),
  });
  return state;
}

function acknowledgementSummary(rows) {
  const records = rows.map(({ valid }) => ({
    id: valid.id,
    targetKind: valid.target_kind,
    targetVersion: Number(valid.target_version),
    targetDigest: valid.target_digest,
    lifecycleStage: valid.lifecycle_stage,
    payloadDigest: valid.payload_digest,
    failureClass: valid.failure_class ?? null,
    attempts: Number(valid.attempts),
    nextAttemptAt: valid.next_attempt_at,
    createdAt: valid.created_at,
    updatedAt: valid.updated_at,
  }));
  return { pendingCount: records.length, pendingDigest: pendingDigest(records) };
}

function pendingDigest(records) {
  return sha256(protocol.canonicalJson(records));
}

function historicalAcknowledgementRows(ctx, customerId, deploymentId) {
  const rows = ctx.historicalAcknowledgements.all({
    customerId,
    deploymentId,
    integrityLimit: ACK_LIVE_HISTORY_LIMIT + 1,
  });
  if (rows.length > ACK_LIVE_HISTORY_LIMIT) throw integrityError();
  return rows.map((row) => {
    const valid = validateAckRow(row);
    verifyAcknowledgementAnchor(ctx, valid, referenceFor(
      ctx, valid.customer_id, valid.deployment_id,
    ));
    if (valid.lifecycle_stage === 'applied' && !deliveredWasAccepted(ctx, valid)) {
      throw integrityError();
    }
    return valid;
  });
}

function acknowledgementHistorySummary(rows) {
  const records = rows.map((valid) => ({
    id: valid.id,
    targetKind: valid.target_kind,
    targetVersion: Number(valid.target_version),
    targetDigest: valid.target_digest,
    lifecycleStage: valid.lifecycle_stage,
    payloadDigest: valid.payload_digest,
    status: valid.status,
    failureClass: valid.failure_class ?? null,
    attempts: Number(valid.attempts),
    nextAttemptAt: valid.next_attempt_at,
    createdAt: valid.created_at,
    updatedAt: valid.updated_at,
  }));
  return { historicalCount: records.length, historicalDigest: historicalDigest(records) };
}

function historicalDigest(records) {
  return sha256(protocol.canonicalJson(records));
}

function archiveAcknowledgedHistory(ctx, ledger, nextVersion, nowMs) {
  const cursor = archiveCursor(ledger);
  const groups = new Map();
  for (const row of ledger.historicalRows) {
    if (row.status !== 'acknowledged' || Number(row.target_version) >= nextVersion) continue;
    const key = [row.target_kind, row.target_version, row.target_digest].join('\0');
    const rows = groups.get(key) || [];
    rows.push(row);
    groups.set(key, rows);
  }
  const archivedAt = isoTime(nowMs);
  const complete = [...groups.values()]
    .filter((rows) => rows.length === 2
      && rows.some((row) => row.lifecycle_stage === 'delivered')
      && rows.some((row) => row.lifecycle_stage === 'applied'))
    .sort((left, right) => Number(left[0].target_version) - Number(right[0].target_version));
  for (const rows of complete) {
    archiveAcknowledgementPair(ctx, rows, cursor, archivedAt);
  }
  return cursor;
}

function archiveCompletedAcknowledgement(ctx, ledger, row, currentVersion, nowMs) {
  const cursor = archiveCursor(ledger);
  if (row.status !== 'acknowledged' || row.lifecycle_stage !== 'applied'
      || !Number.isSafeInteger(Number(currentVersion))
      || Number(row.target_version) >= Number(currentVersion)) return cursor;
  const delivered = deliveredAcknowledgement(ctx, row);
  if (delivered.status !== 'acknowledged') throw integrityError();
  archiveAcknowledgementPair(ctx, [delivered, row], cursor, isoTime(nowMs));
  return cursor;
}

function archiveAcknowledgementPair(ctx, rows, cursor, archivedAt) {
  const ordered = checkedArchivablePair(ctx, rows);
  for (const row of ordered) archiveAcknowledgementRow(ctx, row, cursor, archivedAt);
  compactArchivedHistory(ctx, cursor);
  compactArchiveMutationHistory(ctx, cursor);
}

function checkedArchivablePair(ctx, rows) {
  if (!Array.isArray(rows) || rows.length !== 2) throw integrityError();
  const ordered = rows.map((row) => validateAckRow(row)).sort((left, right) => (
    left.lifecycle_stage === right.lifecycle_stage
      ? left.id.localeCompare(right.id) : (left.lifecycle_stage === 'delivered' ? -1 : 1)
  ));
  const [delivered, applied] = ordered;
  if (delivered.lifecycle_stage !== 'delivered' || applied.lifecycle_stage !== 'applied'
      || delivered.status !== 'acknowledged' || applied.status !== 'acknowledged'
      || delivered.target_kind !== applied.target_kind
      || Number(delivered.target_version) !== Number(applied.target_version)
      || delivered.target_digest !== applied.target_digest) throw integrityError();
  for (const row of ordered) verifyAcknowledgementAnchor(ctx, row, referenceFor(
    ctx, row.customer_id, row.deployment_id,
  ));
  return ordered;
}

function archiveAcknowledgementRow(ctx, row, cursor, archivedAt) {
  const baseRecord = archivedAcknowledgementRecord({ ...row, archived_at: archivedAt });
  const inserted = ctx.acknowledgementArchiveInsert.get({
    id: baseRecord.id, customerId: baseRecord.customerId,
    deploymentId: baseRecord.deploymentId,
    targetKind: baseRecord.targetKind, targetVersion: baseRecord.targetVersion,
    targetDigest: baseRecord.targetDigest, lifecycleStage: baseRecord.lifecycleStage,
    payloadJson: baseRecord.payloadJson, payloadDigest: baseRecord.payloadDigest,
    attempts: baseRecord.attempts, nextAttemptAt: baseRecord.nextAttemptAt,
    createdAt: baseRecord.createdAt, updatedAt: baseRecord.updatedAt,
    archivedAt: baseRecord.archivedAt,
  });
  const archiveSeq = Number(inserted?.archive_seq);
  if (!Number.isSafeInteger(archiveSeq) || archiveSeq < 1) throw integrityError();
  const record = { ...baseRecord, archiveSeq };
  advanceArchiveMutationCursor(ctx, cursor, {
    mutationKind: 'insert', archiveSeq, archiveId: record.id,
  });
  const removed = ctx.acknowledgementArchiveDelete.run({
    id: record.id, customerId: record.customerId, deploymentId: record.deploymentId,
    payloadDigest: record.payloadDigest,
  });
  if (Number(removed.changes) !== 1) throw integrityError();
  cursor.archivedCount += 1;
  cursor.archivedDigest = nextArchiveDigest(cursor.archivedDigest, record);
}

function advanceArchiveMutationCursor(ctx, cursor, expected) {
  const summary = readArchiveMutationSummary(ctx, ctx.customerId, ctx.deploymentId);
  if (summary.archiveMutationCount !== cursor.archiveMutationCount + 1
      || summary.archiveMutationHighWater <= cursor.archiveMutationHighWater) {
    throw integrityError();
  }
  const event = validateArchiveMutationEvent(ctx.acknowledgementArchiveMutationExact.get({
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    eventSeq: summary.archiveMutationHighWater,
  }), ctx.customerId, ctx.deploymentId);
  if (event.scopeSeq !== summary.archiveMutationCount
      || event.mutationKind !== expected.mutationKind
      || event.archiveSeq !== expected.archiveSeq
      || event.archiveId !== expected.archiveId) throw integrityError();
  cursor.archiveMutationCount = summary.archiveMutationCount;
  cursor.archiveMutationHighWater = summary.archiveMutationHighWater;
  cursor.archiveMutationDigest = nextArchiveMutationDigest(
    cursor.archiveMutationDigest, event,
  );
}

function compactArchivedHistory(ctx, cursor) {
  const entries = verifiedArchiveSuffix(ctx, cursor, ACK_ARCHIVE_RETAINED_LIMIT + 2);
  const removeCount = entries.length - ACK_ARCHIVE_RETAINED_LIMIT;
  if (removeCount <= 0) return;
  if (removeCount % 2 !== 0) throw integrityError();
  for (const { archiveSeq, record } of entries.slice(0, removeCount)) {
    const removed = ctx.acknowledgementArchiveCompactDelete.run({
      archiveSeq,
      id: record.id,
      customerId: record.customerId,
      deploymentId: record.deploymentId,
    });
    if (Number(removed.changes) !== 1) throw integrityError();
    advanceArchiveMutationCursor(ctx, cursor, {
      mutationKind: 'delete', archiveSeq, archiveId: record.id,
    });
    cursor.archivedPrefixCount += 1;
    cursor.archivedPrefixHighWater = archiveSeq;
    cursor.archivedPrefixDigest = nextArchiveDigest(cursor.archivedPrefixDigest, record);
  }
  verifiedArchiveSuffix(ctx, cursor, ACK_ARCHIVE_RETAINED_LIMIT);
}

function compactArchiveMutationHistory(ctx, cursor) {
  const maximumBeforeCompaction = ACK_ARCHIVE_MUTATION_RETAINED_LIMIT + 4;
  const archiveEntries = verifiedArchiveSuffix(ctx, cursor, ACK_ARCHIVE_RETAINED_LIMIT);
  const events = verifiedArchiveMutationSuffix(
    ctx, cursor, maximumBeforeCompaction, archiveEntries,
  );
  const removeCount = events.length - ACK_ARCHIVE_MUTATION_RETAINED_LIMIT;
  if (removeCount <= 0) return;
  for (const event of events.slice(0, removeCount)) {
    const removed = ctx.acknowledgementArchiveMutationCompactDelete.run({
      eventSeq: event.eventSeq,
      scopeSeq: event.scopeSeq,
      customerId: event.customerId,
      deploymentId: event.deploymentId,
    });
    if (Number(removed.changes) !== 1) throw integrityError();
    cursor.archiveMutationPrefixCount += 1;
    cursor.archiveMutationPrefixHighWater = event.eventSeq;
    cursor.archiveMutationPrefixDigest = nextArchiveMutationDigest(
      cursor.archiveMutationPrefixDigest, event,
    );
  }
  verifiedArchiveMutationSuffix(
    ctx, cursor, ACK_ARCHIVE_MUTATION_RETAINED_LIMIT, archiveEntries,
  );
}

function verifyArchivedHistory(ctx, ledger) {
  if (ctx.archiveIntegrityFailure) throw integrityError();
  try {
    verifyArchivedHistoryUnchecked(ctx, ledger);
  } catch {
    ctx.archiveIntegrityFailure = true;
    throw integrityError();
  }
}

function verifyArchivedHistoryUnchecked(ctx, ledger) {
  const expected = archiveCursor(ledger);
  const mutationSummary = readArchiveMutationSummary(
    ctx, ledger.customerId, ledger.deploymentId,
  );
  if (mutationSummary.archiveMutationCount !== expected.archiveMutationCount
      || mutationSummary.archiveMutationHighWater !== expected.archiveMutationHighWater) {
    throw integrityError();
  }
  readArchiveSchemaToken(ctx);
  const archiveEntries = verifiedArchiveSuffix(ctx, expected, ACK_ARCHIVE_RETAINED_LIMIT);
  verifiedArchiveMutationSuffix(
    ctx, expected, ACK_ARCHIVE_MUTATION_RETAINED_LIMIT, archiveEntries,
  );
}

function verifiedArchiveSuffix(ctx, expected, maximumRetained) {
  const retainedCount = expected.archivedCount - expected.archivedPrefixCount;
  if (!Number.isSafeInteger(retainedCount) || retainedCount < 0
      || retainedCount > maximumRetained || retainedCount % 2 !== 0) throw integrityError();
  const rows = ctx.acknowledgementArchivePage.all({
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    pageSize: maximumRetained + 1,
  });
  if (rows.length !== retainedCount) throw integrityError();
  let previousSeq = expected.archivedPrefixHighWater;
  let digest = EMPTY_ARCHIVE_DIGEST;
  digest = expected.archivedPrefixDigest;
  let expectedApplied = null;
  const entries = rows.map((row) => {
    const archiveSeq = Number(row.archive_seq);
    if (!Number.isSafeInteger(archiveSeq) || archiveSeq <= previousSeq) throw integrityError();
    previousSeq = archiveSeq;
    const valid = validateAckRow(row);
    if (valid.status !== 'acknowledged' || valid.failure_class !== null
        || !canonicalIsoTime(valid.created_at) || !canonicalIsoTime(valid.updated_at)
        || !canonicalIsoTime(valid.archived_at)) throw integrityError();
    verifyAcknowledgementAnchor(ctx, valid, referenceFor(
      ctx, valid.customer_id, valid.deployment_id,
    ));
    const record = archivedAcknowledgementRecord(valid);
    const pairKey = [record.targetKind, record.targetVersion, record.targetDigest].join('\0');
    if (expectedApplied === null) {
      if (record.lifecycleStage !== 'delivered') throw integrityError();
      expectedApplied = pairKey;
    } else {
      if (record.lifecycleStage !== 'applied' || pairKey !== expectedApplied) {
        throw integrityError();
      }
      expectedApplied = null;
    }
    digest = nextArchiveDigest(digest, record);
    return { archiveSeq, record };
  });
  if (expectedApplied !== null || digest !== expected.archivedDigest) throw integrityError();
  return entries;
}

function verifiedArchiveMutationSuffix(ctx, expected, maximumRetained, archiveEntries) {
  const retainedCount = expected.archiveMutationCount - expected.archiveMutationPrefixCount;
  if (!Number.isSafeInteger(retainedCount) || retainedCount < 0
      || retainedCount > maximumRetained) throw integrityError();
  const rows = ctx.acknowledgementArchiveMutationPage.all({
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    pageSize: maximumRetained + 1,
  });
  if (rows.length !== retainedCount) throw integrityError();
  let count = expected.archiveMutationPrefixCount;
  let eventHighWater = expected.archiveMutationPrefixHighWater;
  let digest = expected.archiveMutationPrefixDigest;
  const events = rows.map((row) => {
    const event = validateArchiveMutationEvent(row, ctx.customerId, ctx.deploymentId);
    if (event.scopeSeq !== count + 1 || event.eventSeq <= eventHighWater
        || !['insert', 'delete'].includes(event.mutationKind)) throw integrityError();
    digest = nextArchiveMutationDigest(digest, event);
    count += 1;
    eventHighWater = event.eventSeq;
    return event;
  });
  if (count !== expected.archiveMutationCount
      || eventHighWater !== expected.archiveMutationHighWater
      || digest !== expected.archiveMutationDigest) throw integrityError();
  verifyMutationArchiveRelations(events, archiveEntries, expected.archivedPrefixHighWater);
  return events;
}

function verifyMutationArchiveRelations(events, archiveEntries, archivedPrefixHighWater) {
  const retained = new Map(archiveEntries.map(({ archiveSeq, record }) => (
    [archiveSeq, record.id]
  )));
  const matched = new Set();
  for (const event of events) {
    if (event.mutationKind === 'delete') {
      if (event.archiveSeq > archivedPrefixHighWater || retained.has(event.archiveSeq)) {
        throw integrityError();
      }
      continue;
    }
    if (event.archiveSeq <= archivedPrefixHighWater) continue;
    if (retained.get(event.archiveSeq) !== event.archiveId || matched.has(event.archiveSeq)) {
      throw integrityError();
    }
    matched.add(event.archiveSeq);
  }
  if (matched.size !== retained.size) throw integrityError();
}

function readArchiveMutationSummary(ctx, customerId, deploymentId) {
  const row = ctx.acknowledgementArchiveMutationSummary.get({ customerId, deploymentId });
  const archiveMutationCount = row ? Number(row.mutation_count) : 0;
  const archiveMutationHighWater = row ? Number(row.mutation_high_water) : 0;
  if (!Number.isSafeInteger(archiveMutationCount) || archiveMutationCount < 0
      || !Number.isSafeInteger(archiveMutationHighWater) || archiveMutationHighWater < 0
      || (archiveMutationCount === 0) !== (archiveMutationHighWater === 0)) {
    throw integrityError();
  }
  return { archiveMutationCount, archiveMutationHighWater };
}

function validateArchiveMutationEvent(row, customerId, deploymentId) {
  const event = {
    eventSeq: Number(row?.event_seq),
    scopeSeq: Number(row?.scope_seq),
    customerId: row?.customer_id,
    deploymentId: row?.deployment_id,
    mutationKind: row?.mutation_kind,
    archiveSeq: Number(row?.archive_seq),
    archiveId: row?.archive_id,
  };
  if (!Number.isSafeInteger(event.eventSeq) || event.eventSeq < 1
      || !Number.isSafeInteger(event.scopeSeq) || event.scopeSeq < 1
      || event.customerId !== customerId || event.deploymentId !== deploymentId
      || !['insert', 'update', 'delete'].includes(event.mutationKind)
      || !Number.isSafeInteger(event.archiveSeq) || event.archiveSeq < 1
      || typeof event.archiveId !== 'string' || event.archiveId.length < 1) {
    throw integrityError();
  }
  return event;
}

function nextArchiveMutationDigest(previousDigest, event) {
  return crypto.createHash('sha256')
    .update('redactwall.connected-ack-archive-mutations.chain.v2\0', 'utf8')
    .update(previousDigest, 'utf8').update('\0', 'utf8')
    .update(protocol.canonicalJson(event), 'utf8').digest('hex');
}

function archivedAcknowledgementRecord(row) {
  return {
    archiveSeq: Number(row.archive_seq),
    id: row.id,
    customerId: row.customer_id,
    deploymentId: row.deployment_id,
    targetKind: row.target_kind,
    targetVersion: Number(row.target_version),
    targetDigest: row.target_digest,
    lifecycleStage: row.lifecycle_stage,
    payloadJson: row.payload_json,
    payloadDigest: row.payload_digest,
    status: row.status,
    failureClass: row.failure_class ?? null,
    attempts: Number(row.attempts),
    nextAttemptAt: row.next_attempt_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    archivedAt: row.archived_at,
  };
}

function nextArchiveDigest(previousDigest, record) {
  return crypto.createHash('sha256')
    .update('redactwall.connected-ack-archive.chain.v2\0', 'utf8')
    .update(previousDigest, 'utf8').update('\0', 'utf8')
    .update(protocol.canonicalJson(record), 'utf8').digest('hex');
}

function archiveCursor(value) {
  return {
    archivedCount: Number(value.archivedCount),
    archivedDigest: String(value.archivedDigest || ''),
    archivedPrefixCount: Number(value.archivedPrefixCount),
    archivedPrefixHighWater: Number(value.archivedPrefixHighWater),
    archivedPrefixDigest: String(value.archivedPrefixDigest || ''),
    archiveMutationCount: Number(value.archiveMutationCount),
    archiveMutationHighWater: Number(value.archiveMutationHighWater),
    archiveMutationDigest: String(value.archiveMutationDigest || ''),
    archiveMutationPrefixCount: Number(value.archiveMutationPrefixCount),
    archiveMutationPrefixHighWater: Number(value.archiveMutationPrefixHighWater),
    archiveMutationPrefixDigest: String(value.archiveMutationPrefixDigest || ''),
    capacityRestriction: value.capacityRestriction ? { ...value.capacityRestriction } : null,
  };
}

function readArchiveSchemaToken(ctx) {
  assertNoTemporaryAuthorityCollision(ctx);
  const rows = ctx.archiveCatalogRead.all();
  if (ctx.archiveCatalogKind === 'postgres') {
    validatePostgresArchiveCatalog(rows);
    return Object.freeze({
      kind: 'postgres',
      catalogIdentity: sha256(protocol.canonicalJson(rows)),
    });
  }
  const catalogIdentity = sha256(protocol.canonicalJson(rows));
  if (rows.length !== SQLITE_ARCHIVE_CATALOG_NAMES.length
      || catalogIdentity !== SQLITE_ARCHIVE_CATALOG_IDENTITY) throw integrityError();
  return Object.freeze({ kind: 'sqlite', catalogIdentity });
}

function assertNoTemporaryAuthorityCollision(ctx) {
  if (ctx.archiveCatalogKind === 'sqlite'
      && ctx.archiveTempCatalogRead.all().length !== 0) throw integrityError();
}

function validatePostgresArchiveCatalog(rows) {
  const expected = new Set([
    'relation:connected_ack_archive',
    'relation:connected_ack_archive_mutations',
    'function:record_connected_ack_archive_mutation',
    'function:reject_connected_ack_archive_mutation',
    'function:reject_connected_ack_archive_event_mutation',
    'trigger:connected_ack_archive_record_mutation',
    'trigger:connected_ack_archive_no_update',
    'trigger:connected_ack_archive_mutations_no_update',
    'policy:connected_ack_archive_tenant_isolation',
    'policy:connected_ack_archive_mutation_tenant_isolation',
    'index:idx_connected_ack_archive_scope',
    'index:idx_connected_ack_archive_mutation_scope',
  ]);
  if (!Array.isArray(rows) || rows.length !== expected.size) throw integrityError();
  const byKey = new Map();
  for (const row of rows) {
    const key = `${row.object_type}:${row.object_name}`;
    if (!expected.has(key) || byKey.has(key)
        || !/^\d+$/.test(String(row.object_oid || ''))
        || !/^\d+$/.test(String(row.object_xmin || ''))) throw integrityError();
    let detail;
    try { detail = JSON.parse(row.object_detail); } catch { throw integrityError(); }
    byKey.set(key, detail);
  }
  for (const name of ['connected_ack_archive', 'connected_ack_archive_mutations']) {
    const detail = byKey.get(`relation:${name}`);
    if (detail?.relkind !== 'r' || detail?.rowSecurity !== true
        || detail?.forceRowSecurity !== true) throw integrityError();
  }
  validatePostgresArchiveFunctions(byKey);
  validatePostgresArchiveTriggers(byKey, rows);
  validatePostgresArchivePolicies(byKey);
  validatePostgresArchiveIndexes(byKey);
}

function validatePostgresArchiveFunctions(byKey) {
  const expectedSources = {
    record_connected_ack_archive_mutation: `BEGIN
        IF TG_OP = 'INSERT' THEN
          INSERT INTO public.connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT NEW.customer_id, NEW.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'insert', NEW.archive_seq, NEW.id
          FROM public.connected_ack_archive_mutations
          WHERE customer_id = NEW.customer_id AND deployment_id = NEW.deployment_id;
        ELSIF TG_OP = 'DELETE' THEN
          INSERT INTO public.connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'delete', OLD.archive_seq, OLD.id
          FROM public.connected_ack_archive_mutations
          WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
        ELSE
          INSERT INTO public.connected_ack_archive_mutations
            (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
          SELECT OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
            'update', OLD.archive_seq, OLD.id
          FROM public.connected_ack_archive_mutations
          WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
          IF NEW.customer_id IS DISTINCT FROM OLD.customer_id
             OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id THEN
            INSERT INTO public.connected_ack_archive_mutations
              (customer_id, deployment_id, scope_seq, mutation_kind, archive_seq, archive_id)
            SELECT NEW.customer_id, NEW.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
              'update', NEW.archive_seq, NEW.id
            FROM public.connected_ack_archive_mutations
            WHERE customer_id = NEW.customer_id AND deployment_id = NEW.deployment_id;
          END IF;
        END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
      END;`,
    reject_connected_ack_archive_mutation: `BEGIN
        RAISE EXCEPTION USING
          ERRCODE = '55000',
          MESSAGE = 'connected ACK archive is append-only';
      END;`,
    reject_connected_ack_archive_event_mutation: `BEGIN
        RAISE EXCEPTION USING
          ERRCODE = '55000',
          MESSAGE = 'connected ACK archive mutation log is append-only';
      END;`,
  };
  for (const [name, source] of Object.entries(expectedSources)) {
    const detail = byKey.get(`function:${name}`);
    if (detail?.securityDefiner !== false || detail?.volatility !== 'v'
        || !Array.isArray(detail?.config) || detail.config.length !== 1
        || detail.config[0] !== 'search_path=pg_catalog'
        || normalizeCatalogSql(detail?.source) !== normalizeCatalogSql(source)) {
      throw integrityError();
    }
  }
}

function validatePostgresArchiveTriggers(byKey, rows) {
  const functionOids = new Map(rows.filter((row) => row.object_type === 'function')
    .map((row) => [row.object_name, String(row.object_oid)]));
  const expected = {
    connected_ack_archive_record_mutation: {
      type: 29, functionName: 'record_connected_ack_archive_mutation',
      definition: /after insert or delete or update on connected_ack_archive .*record_connected_ack_archive_mutation\(\)$/,
    },
    connected_ack_archive_no_update: {
      type: 19, functionName: 'reject_connected_ack_archive_mutation',
      definition: /before update on connected_ack_archive .*reject_connected_ack_archive_mutation\(\)$/,
    },
    connected_ack_archive_mutations_no_update: {
      type: 19, functionName: 'reject_connected_ack_archive_event_mutation',
      definition: /before update on connected_ack_archive_mutations .*reject_connected_ack_archive_event_mutation\(\)$/,
    },
  };
  for (const [name, value] of Object.entries(expected)) {
    const detail = byKey.get(`trigger:${name}`);
    if (detail?.enabled !== 'O' || Number(detail?.type) !== value.type
        || String(detail?.functionOid) !== functionOids.get(value.functionName)
        || !value.definition.test(normalizeCatalogSql(detail?.definition))) {
      throw integrityError();
    }
  }
}

function validatePostgresArchivePolicies(byKey) {
  const expected = "coalescecurrent_setting'redactwall.org_id',true,''<>''andcustomer_id=current_setting'redactwall.org_id',true";
  for (const name of [
    'connected_ack_archive_tenant_isolation',
    'connected_ack_archive_mutation_tenant_isolation',
  ]) {
    const detail = byKey.get(`policy:${name}`);
    if (detail?.command !== '*' || detail?.roles !== '{0}'
        || normalizedPolicyExpression(detail?.using) !== expected
        || normalizedPolicyExpression(detail?.check) !== expected) throw integrityError();
  }
}

function normalizedPolicyExpression(value) {
  return String(value || '').toLowerCase().replace(/::text/g, '').replace(/[()\s]/g, '');
}

function validatePostgresArchiveIndexes(byKey) {
  const expected = {
    idx_connected_ack_archive_scope:
      /create index idx_connected_ack_archive_scope on (?:public\.)?connected_ack_archive using btree \(customer_id, deployment_id, archive_seq\)$/,
    idx_connected_ack_archive_mutation_scope:
      /create index idx_connected_ack_archive_mutation_scope on (?:public\.)?connected_ack_archive_mutations using btree \(customer_id, deployment_id, scope_seq desc\)$/,
  };
  for (const [name, pattern] of Object.entries(expected)) {
    if (!pattern.test(normalizeCatalogSql(byKey.get(`index:${name}`)?.definition))) {
      throw integrityError();
    }
  }
}

function normalizeCatalogSql(value) {
  return String(value || '').trim().replace(/\s+/g, ' ').toLowerCase();
}

function acknowledgementLedgerDigest(value) {
  const { activeRows: _activeRows, historicalRows: _historicalRows, ...state } = value;
  return sha256(protocol.canonicalJson(state));
}

function checkedAcknowledgementLedger(value, customerId, deploymentId) {
  if (!plainRecord(value)
      || Object.keys(value).sort().join(',')
        !== 'archiveMutationCount,archiveMutationDigest,archiveMutationHighWater,archiveMutationPrefixCount,archiveMutationPrefixDigest,archiveMutationPrefixHighWater,archivedCount,archivedDigest,archivedPrefixCount,archivedPrefixDigest,archivedPrefixHighWater,capacityRestriction,customerId,deploymentId,historicalCount,historicalDigest,pendingCount,pendingDigest,stateVersion,terminal'
      || value.stateVersion !== 4
      || value.customerId !== customerId
      || value.deploymentId !== deploymentId
      || !Number.isSafeInteger(value.pendingCount) || value.pendingCount < 0
      || value.pendingCount > ACK_PENDING_HARD_LIMIT
      || !/^[a-f0-9]{64}$/.test(String(value.pendingDigest || ''))
      || !Number.isSafeInteger(value.historicalCount) || value.historicalCount < 0
      || value.historicalCount > ACK_LIVE_HISTORY_LIMIT
      || !/^[a-f0-9]{64}$/.test(String(value.historicalDigest || ''))
      || !Number.isSafeInteger(value.archivedCount) || value.archivedCount < 0
      || value.archivedCount % 2 !== 0
      || !/^[a-f0-9]{64}$/.test(String(value.archivedDigest || ''))
      || (value.archivedCount === 0) !== (value.archivedDigest === EMPTY_ARCHIVE_DIGEST)
      || !Number.isSafeInteger(value.archivedPrefixCount) || value.archivedPrefixCount < 0
      || value.archivedPrefixCount > value.archivedCount
      || value.archivedPrefixCount % 2 !== 0
      || value.archivedCount - value.archivedPrefixCount > ACK_ARCHIVE_RETAINED_LIMIT
      || !Number.isSafeInteger(value.archivedPrefixHighWater)
      || value.archivedPrefixHighWater < 0
      || !/^[a-f0-9]{64}$/.test(String(value.archivedPrefixDigest || ''))
      || (value.archivedPrefixCount === 0)
        !== (value.archivedPrefixHighWater === 0
          && value.archivedPrefixDigest === EMPTY_ARCHIVE_DIGEST)
      || (value.archivedPrefixCount > 0
        && (value.archivedPrefixHighWater === 0
          || value.archivedPrefixDigest === EMPTY_ARCHIVE_DIGEST))
      || !Number.isSafeInteger(value.archiveMutationCount) || value.archiveMutationCount < 0
      || value.archiveMutationCount !== value.archivedCount + value.archivedPrefixCount
      || !Number.isSafeInteger(value.archiveMutationHighWater)
      || value.archiveMutationHighWater < 0
      || (value.archiveMutationCount === 0) !== (value.archiveMutationHighWater === 0)
      || !/^[a-f0-9]{64}$/.test(String(value.archiveMutationDigest || ''))
      || (value.archiveMutationCount === 0)
        !== (value.archiveMutationDigest === EMPTY_ARCHIVE_MUTATION_DIGEST)
      || !Number.isSafeInteger(value.archiveMutationPrefixCount)
      || value.archiveMutationPrefixCount < 0
      || value.archiveMutationPrefixCount > value.archiveMutationCount
      || value.archiveMutationCount - value.archiveMutationPrefixCount
        > ACK_ARCHIVE_MUTATION_RETAINED_LIMIT
      || !Number.isSafeInteger(value.archiveMutationPrefixHighWater)
      || value.archiveMutationPrefixHighWater < 0
      || !/^[a-f0-9]{64}$/.test(String(value.archiveMutationPrefixDigest || ''))
      || (value.archiveMutationPrefixCount === 0)
        !== (value.archiveMutationPrefixHighWater === 0
          && value.archiveMutationPrefixDigest === EMPTY_ARCHIVE_MUTATION_DIGEST)
      || (value.archiveMutationPrefixCount > 0
        && (value.archiveMutationPrefixHighWater === 0
          || value.archiveMutationPrefixDigest === EMPTY_ARCHIVE_MUTATION_DIGEST))
      || (value.archiveMutationCount > value.archiveMutationPrefixCount
        && value.archiveMutationHighWater <= value.archiveMutationPrefixHighWater)
      || (value.terminal !== null && !validTerminal(value.terminal))
      || (value.capacityRestriction !== null
        && !validCapacityRestriction(value.capacityRestriction))) throw integrityError();
  return value;
}

function checkedCapacityRestriction(value) {
  if (!validCapacityRestriction(value)) throw integrityError();
  return Object.freeze({ ...value });
}

function validCapacityRestriction(value) {
  return plainRecord(value)
    && Object.keys(value).sort().join(',')
      === 'classification,entitlementDigest,entitlementVersion'
    && Number.isSafeInteger(value.entitlementVersion) && value.entitlementVersion >= 1
    && /^[a-f0-9]{64}$/.test(String(value.entitlementDigest || ''))
    && CAPACITY_RESTRICTION_CLASSIFICATIONS.has(value.classification);
}

function sameNullableCapacityRestriction(left, right) {
  if (left === null || right === null) return left === null && right === null;
  return validCapacityRestriction(left) && validCapacityRestriction(right)
    && sameCapacityRestriction(left, right);
}

function validTerminal(value) {
  return plainRecord(value)
    && Object.keys(value).sort().join(',') === 'failureClass,id,payloadDigest'
    && typeof value.id === 'string' && value.id.length > 0
    && /^[a-f0-9]{64}$/.test(String(value.payloadDigest || ''))
    && ACK_TERMINAL_FAILURES.has(value.failureClass);
}

function verifyTerminalAcknowledgement(ctx, terminal, customerId, deploymentId) {
  const row = ctx.ackExact.get({
    id: terminal.id,
    customerId,
    deploymentId,
    payloadDigest: terminal.payloadDigest,
  });
  const valid = validateAckRow(row);
  verifyAcknowledgementAnchor(ctx, valid, referenceFor(ctx, customerId, deploymentId));
  if (valid.status !== 'terminal' || valid.failure_class !== terminal.failureClass) {
    throw integrityError();
  }
  if (valid.lifecycle_stage === 'applied' && !deliveredWasAccepted(ctx, valid)) {
    throw integrityError();
  }
}

function validateAckRow(row) {
  if (!row) throw integrityError();
  let acknowledgement;
  try {
    acknowledgement = protocol.assertChannel(
      JSON.parse(row.payload_json),
      protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    );
  } catch { throw integrityError(); }
  const valid = row.customer_id === acknowledgement.customerId
    && row.deployment_id === acknowledgement.deploymentId
    && row.target_kind === acknowledgement.targetKind
    && Number(row.target_version) === acknowledgement.targetVersion
    && row.target_digest === acknowledgement.targetDigest
    && row.lifecycle_stage === acknowledgement.lifecycleStage
    && row.payload_digest === sha256(row.payload_json)
    && ['pending', 'acknowledged', 'terminal'].includes(row.status)
    && (row.status === 'terminal'
      ? ACK_TERMINAL_FAILURES.has(row.failure_class)
      : (row.status === 'pending'
        ? row.failure_class === null || ACK_RETRYABLE_FAILURES.has(row.failure_class)
        : row.failure_class === null))
    && Number.isSafeInteger(Number(row.attempts)) && Number(row.attempts) >= 0
    && canonicalIsoTime(row.next_attempt_at)
    && canonicalIsoTime(row.created_at)
    && canonicalIsoTime(row.updated_at);
  if (!valid) throw integrityError();
  return row;
}

function verifiedAuditDetail(ctx, row, allowedActions) {
  if (!row) return null;
  try {
    const entry = JSON.parse(row.entry);
    if (!ctx.verifyAuditEntry(entry)
        || !allowedActions.includes(entry.action)
        || row.connected_entry_action !== entry.action
        || row.action !== entry.action) throw integrityError();
    return JSON.parse(entry.detail);
  } catch (error) {
    if (error && error.code === 'CONNECTED_ENTITLEMENT_INTEGRITY') throw error;
    throw integrityError();
  }
}

function verifyInputArtifact(ctx, artifact) {
  const keyConfig = ctx.verificationKeys();
  const keys = normalizePublicKeys(keyConfig.publicKeys, {
    offlineKeyFingerprint: keyConfig.offlineKeyFingerprint,
    forbiddenPublicKeyFingerprints: keyConfig.forbiddenPublicKeyFingerprints,
    authorityRegistry: keyConfig.authorityRegistry,
    purpose: protocol.CHANNEL_KINDS.ENTITLEMENT,
    strictPurpose: true,
  });
  return verifySignedArtifact(artifact, keys, protocol.CHANNEL_KINDS.ENTITLEMENT);
}

function requireAuditHealthy(ctx) {
  if (ctx.compositeCoordinator && ctx.compositeCoordinator.isAuditVerified()) return;
  const result = ctx.verifyAuditState();
  if (!result || result.ok !== true) throw integrityError();
}

function checkedCoordinator(value) {
  if (value === undefined || value === null) return null;
  if (!isConnectedHeartbeatTransactionCoordinator(value)) {
    throw new TypeError('connected heartbeat transaction coordinator is invalid');
  }
  return value;
}

function lockAuthority(ctx) {
  if (typeof ctx.driver.lockAuditAppend === 'function') ctx.driver.lockAuditAppend();
  assertNoTemporaryAuthorityCollision(ctx);
}

function referenceFor(ctx, customerId, deploymentId) {
  return ctx.authorityReference(customerId, deploymentId);
}

function validateBinding(customerId, deploymentId) {
  stateEngine.initialState(customerId, deploymentId);
}

function assertStoreScope(ctx, customerId, deploymentId) {
  validateBinding(customerId, deploymentId);
  if (customerId !== ctx.customerId) throw stateError('customer_mismatch');
  if (deploymentId !== ctx.deploymentId) throw stateError('deployment_mismatch');
}

function exactAckParams(input) {
  return {
    id: String(input.id || ''),
    customerId: String(input.customerId || ''),
    deploymentId: String(input.deploymentId || ''),
    payloadDigest: String(input.payloadDigest || ''),
  };
}

function publicAckRow(row) {
  return {
    id: row.id,
    customerId: row.customer_id,
    deploymentId: row.deployment_id,
    targetKind: row.target_kind,
    targetVersion: Number(row.target_version),
    targetDigest: row.target_digest,
    lifecycleStage: row.lifecycle_stage,
    payloadDigest: row.payload_digest,
    status: row.status,
    failureClass: row.failure_class ?? null,
    attempts: Number(row.attempts),
    nextAttemptAt: row.next_attempt_at,
  };
}

function retryAt(nowMs, attempts) {
  const exponent = Math.max(0, Math.min(10, Number(attempts) || 0));
  return nowMs + Math.min(RETRY_MAX_MS, RETRY_BASE_MS * (2 ** exponent));
}

function stateDigest(state) {
  return sha256(protocol.canonicalJson(state));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function checkedTime(value) {
  const parsed = value === undefined || value === null ? Date.now() : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new TypeError('connected entitlement time is invalid');
  return parsed;
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function receiverless(callback) {
  return (...args) => Reflect.apply(callback, undefined, args);
}

function isoTime(value) {
  return new Date(checkedTime(value)).toISOString();
}

function canonicalIsoTime(value) {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function stateError(code) {
  const error = new Error('connected entitlement input rejected');
  error.code = code;
  return error;
}

function integrityError() {
  const error = new Error('connected entitlement state is not anchored by audit evidence');
  error.code = 'CONNECTED_ENTITLEMENT_INTEGRITY';
  return error;
}

module.exports = {
  createConnectedEntitlementStore,
  STATE_ACTIONS,
  ACK_ACTIONS,
  RETRY_BASE_MS,
  RETRY_MAX_MS,
  ACK_PENDING_HARD_LIMIT,
  ACK_ORDINARY_PENDING_LIMIT,
  ACK_BACKLOG_BLOCK_THRESHOLD,
};
