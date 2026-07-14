'use strict';

const crypto = require('node:crypto');
const Database = require('better-sqlite3');
const protocol = require('./vendor-control-protocol');
const {
  CANCELLATION_SIGNATURE_DOMAIN,
  REQUEST_SIGNATURE_DOMAIN,
  assertAuditSupportCancellation,
  assertAuditSupportRequest,
  payloadDigest: auditSupportPayloadDigest,
} = require('./audit-support-control-verifier');
const {
  CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN,
  assertCustomerAuditResponsePayload,
} = require('./customer-audit-response-signer');
const {
  INDEPENDENT_WITNESS_ASSURANCE,
  TEST_WITNESS_ASSURANCE,
} = require('./monotonic-anchor-authority');

const SCHEMA_VERSION = 2;
const OUTBOX_LEASE_MS = 60 * 1000;
const MAX_OUTBOX_ATTEMPTS = 16;
const MAX_CLOCK_ROLLBACK_MS = 5 * 60 * 1000;
const ZERO_DIGEST = '0'.repeat(64);
const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_CODE_RE = /^[a-z0-9][a-z0-9_.:-]{0,79}$/;
const LOCAL_AUDIT_REF_RE = /^local_audit_[A-Za-z0-9_-]{20,86}$/;
const REQUEST_KEY_ID_RE = /^rw-audit-request-[a-z0-9][a-z0-9_.-]{0,77}$/;
const RESPONSE_KEY_ID_RE = /^rw-customer-audit-response-[a-z0-9][a-z0-9_.-]{0,55}$/;
const INTEGRITY_BRAND = Symbol('customer-audit-integrity-authority');
const WITNESS_BRAND = Symbol('customer-audit-witness-authority');
const STORE_BRAND = Symbol('customer-audit-support-store');
const CUSTOMER_AUDIT_ANCHOR_PURPOSE = 'customer_audit_support';
const ANCHOR_NAMESPACE_RE = /^[a-z0-9][a-z0-9_.:-]{0,159}$/;
const EVENT_TYPES = new Set([
  'request_received', 'customer_decision', 'request_expired', 'response_prepared',
  'request_superseded', 'vendor_revocation_received',
]);
const EVENT_OUTCOMES = new Set([
  'accepted', 'approved', 'denied', 'expired', 'revoked', 'completed', 'superseded',
]);

const MIGRATION = `
CREATE TABLE IF NOT EXISTS customer_audit_support_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  trusted_time_ms INTEGER NOT NULL,
  state_digest TEXT NOT NULL,
  outbox_digest TEXT NOT NULL,
  audit_sequence INTEGER NOT NULL,
  audit_head TEXT NOT NULL,
  meta_mac TEXT NOT NULL
);
INSERT OR IGNORE INTO customer_audit_support_meta
  (singleton, schema_version, generation, trusted_time_ms, state_digest,
   outbox_digest, audit_sequence, audit_head, meta_mac)
VALUES (1, 2, 0, 0, '${ZERO_DIGEST}', '${ZERO_DIGEST}', 0, '${ZERO_DIGEST}', '');
CREATE TABLE IF NOT EXISTS customer_audit_support_requests (
  request_id TEXT NOT NULL,
  request_version INTEGER NOT NULL,
  request_digest TEXT NOT NULL,
  revision INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  record_mac TEXT NOT NULL,
  PRIMARY KEY(request_id, request_version)
);
CREATE INDEX IF NOT EXISTS customer_audit_support_latest
  ON customer_audit_support_requests(request_id, request_version DESC);
CREATE TABLE IF NOT EXISTS customer_audit_support_audit (
  sequence INTEGER PRIMARY KEY,
  previous_digest TEXT NOT NULL,
  event_digest TEXT NOT NULL UNIQUE,
  event_json TEXT NOT NULL,
  event_mac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS customer_audit_support_outbox (
  message_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  request_version INTEGER NOT NULL,
  request_digest TEXT NOT NULL,
  response_digest TEXT NOT NULL,
  document_json TEXT NOT NULL,
  document_mac TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  next_attempt_at TEXT NOT NULL,
  last_error_code TEXT,
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  claim_token TEXT
);
CREATE INDEX IF NOT EXISTS customer_audit_support_outbox_ready
  ON customer_audit_support_outbox(status, next_attempt_at, created_at);
`;

const WITNESS_MIGRATION = `
CREATE TABLE IF NOT EXISTS customer_audit_support_anchor (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  trusted_time_ms INTEGER NOT NULL,
  state_digest TEXT NOT NULL,
  outbox_digest TEXT NOT NULL,
  audit_sequence INTEGER NOT NULL,
  audit_head TEXT NOT NULL,
  anchor_digest TEXT NOT NULL,
  anchor_mac TEXT NOT NULL
);
`;

function createReferenceCustomerAuditIntegrityAuthority(options = {}) {
  assertReferenceRuntime();
  const keyId = checkedSafeCode(options.keyId || 'customer-audit-reference-v1',
    'customer_audit_integrity_invalid');
  const secret = checkedSecret(options.secret);
  const authority = {
    keyId,
    identity: sha256(secret),
    mac(domain, message) {
      return crypto.createHmac('sha256', secret)
        .update(`${domain}\0${message}`, 'utf8').digest('base64url');
    },
    reference(domain, message) {
      const suffix = crypto.createHmac('sha256', secret)
        .update(`reference\0${domain}\0${message}`, 'utf8').digest('base64url').slice(0, 32);
      return `local_audit_${suffix}`;
    },
  };
  Object.defineProperty(authority, INTEGRITY_BRAND, { value: true });
  return Object.freeze(authority);
}

function createReferenceCustomerAuditWitnessAuthority(options = {}) {
  assertReferenceRuntime();
  const keyId = checkedSafeCode(options.keyId || 'customer-audit-witness-reference-v1',
    'customer_audit_witness_invalid');
  const secret = checkedSecret(options.secret);
  const authority = {
    keyId,
    identity: sha256(secret),
    mac(domain, message) {
      return crypto.createHmac('sha256', secret)
        .update(`${domain}\0${message}`, 'utf8').digest('base64url');
    },
  };
  Object.defineProperty(authority, WITNESS_BRAND, { value: true });
  return Object.freeze(authority);
}

function openCustomerAuditSupportSqlite(options = {}) {
  assertReferenceRuntime();
  const driver = String(options.driver || 'sqlite').toLowerCase();
  if (driver === 'postgres' || driver === 'postgresql') {
    throw storeError('customer_audit_postgres_adapter_unavailable');
  }
  if (driver !== 'sqlite') throw storeError('customer_audit_storage_driver_invalid');
  const integrity = checkedIntegrity(options.integrityAuthority);
  const witness = checkedWitness(options.witnessAuthority, integrity);
  const anchorNamespace = checkedAnchorNamespace(options.anchorNamespace);
  const anchorAuthority = checkedAnchorAuthority(
    options.anchorAuthority, integrity, witness,
  );
  const databasePath = options.path || ':memory:';
  const witnessPath = options.witnessPath
    || (databasePath === ':memory:' ? ':memory:' : `${databasePath}.witness`);
  if (databasePath !== ':memory:' && witnessPath === databasePath) {
    throw storeError('customer_audit_witness_path_invalid');
  }
  const database = options.database || new Database(databasePath);
  try {
    database.pragma('foreign_keys = ON');
    database.pragma('journal_mode = DELETE');
    database.pragma('synchronous = FULL');
    database.pragma('busy_timeout = 30000');
    database.prepare('ATTACH DATABASE ? AS audit_witness').run(witnessPath);
    database.exec('PRAGMA audit_witness.journal_mode = DELETE');
    database.exec('PRAGMA audit_witness.synchronous = FULL');
    database.exec(MIGRATION);
    database.exec(WITNESS_MIGRATION.replace(
      'CREATE TABLE IF NOT EXISTS customer_audit_support_anchor',
      'CREATE TABLE IF NOT EXISTS audit_witness.customer_audit_support_anchor',
    ));
    const schema = database.prepare(`
      SELECT schema_version FROM customer_audit_support_meta WHERE singleton = 1
    `).get();
    if (!schema || schema.schema_version !== SCHEMA_VERSION) {
      throw storeError('customer_audit_schema_unsupported');
    }
    initializeAnchor(database, integrity, witness, anchorAuthority, anchorNamespace);
    return createStore(database, integrity, witness, anchorAuthority, anchorNamespace);
  } catch (error) {
    if (!options.database) try { database.close(); } catch {}
    throw error;
  }
}

function openProductionCustomerAuditSupportStore() {
  throw storeError('customer_audit_root_db_adapter_required');
}

function createStore(database, integrity, witness, anchorAuthority, anchorNamespace) {
  let closed = false;
  const anchorStatus = { degraded: false };
  const store = {
    kind: 'sqlite',
    runtimeProfile: 'reference-with-external-anchor',
    schemaVersion: SCHEMA_VERSION,
    transaction(callback) {
      assertOpen(closed);
      if (typeof callback !== 'function') throw storeError('customer_audit_transaction_invalid');
      return anchoredMutation(
        database, integrity, witness, anchorAuthority, anchorNamespace, anchorStatus,
        (transactionState) => {
        const result = callback(transactionMethods(database, integrity, transactionState));
        if (result && typeof result.then === 'function') {
          throw storeError('customer_audit_async_transaction_forbidden');
        }
          return result;
        },
      );
    },
    auditEvents(cursor = 0) {
      assertOpen(closed);
      if (anchorStatus.degraded) throw storeError('customer_audit_anchor_finalization_pending');
      const events = verifyCurrentSnapshot(
        database, integrity, witness, anchorAuthority, anchorNamespace,
      ).events;
      if (!Number.isSafeInteger(cursor) || cursor < 0 || cursor > events.length) {
        throw storeError('customer_audit_cursor_invalid');
      }
      return deepFreeze({ cursor: events.length, items: events.slice(cursor) });
    },
    claimOutbox(limit = 16, now = new Date().toISOString()) {
      assertOpen(closed);
      return anchoredMutation(
        database, integrity, witness, anchorAuthority, anchorNamespace, anchorStatus,
        (transactionState) => {
        trustedTime(transactionState, Date.parse(canonicalIso(
          now, 'customer_audit_clock_invalid',
        )), MAX_CLOCK_ROLLBACK_MS);
          return claimOutbox(database, integrity, limit, now);
        },
      );
    },
    markOutboxDelivered(messageId, responseDigest, deliveredAt, claimToken) {
      assertOpen(closed);
      return anchoredMutation(
        database, integrity, witness, anchorAuthority, anchorNamespace, anchorStatus,
        (transactionState) => {
        trustedTime(transactionState, Date.parse(canonicalIso(
          deliveredAt, 'customer_audit_clock_invalid',
        )), MAX_CLOCK_ROLLBACK_MS);
          return markOutboxDelivered(
          database, messageId, responseDigest, deliveredAt, claimToken,
        );
        },
      );
    },
    markOutboxRetry(messageId, responseDigest, nextAttemptAt, errorCode, claimToken) {
      assertOpen(closed);
      return anchoredMutation(
        database, integrity, witness, anchorAuthority, anchorNamespace, anchorStatus,
        () => markOutboxRetry(
          database, messageId, responseDigest, nextAttemptAt, errorCode, claimToken,
        ),
      );
    },
    readiness(now = new Date().toISOString()) {
      assertOpen(closed);
      canonicalIso(now, 'customer_audit_clock_invalid');
      let integrityReady = true;
      try {
        if (anchorStatus.degraded) throw storeError('customer_audit_anchor_finalization_pending');
        verifyCurrentSnapshot(database, integrity, witness, anchorAuthority, anchorNamespace);
      }
      catch { integrityReady = false; }
      const quick = database.pragma('quick_check', { simple: true });
      const blocked = database.prepare(`
        SELECT COUNT(*) AS count FROM customer_audit_support_outbox WHERE status = 'blocked'
      `).get().count;
      const expiredFinalLeases = database.prepare(`
        SELECT COUNT(*) AS count FROM customer_audit_support_outbox
        WHERE status = 'sending' AND attempts >= ? AND next_attempt_at <= ?
      `).get(MAX_OUTBOX_ATTEMPTS, now).count;
      return Object.freeze({
        ready: quick === 'ok' && integrityReady && blocked === 0 && expiredFinalLeases === 0,
        storage: quick === 'ok' ? 'ok' : 'failed',
        integrity: integrityReady ? 'ok' : 'failed',
        outboxBlocked: blocked,
        outboxExpiredFinalLeases: expiredFinalLeases,
        postgresSupported: false,
        runtimeProfile: 'reference-with-external-anchor',
      });
    },
    close() { if (!closed) database.close(); closed = true; },
    database,
  };
  Object.defineProperty(store, STORE_BRAND, { value: true });
  return Object.freeze(store);
}

function transactionMethods(database, integrity, transactionState) {
  return Object.freeze({
    trustedTime: (nowMs, maxRollbackMs) => trustedTime(
      transactionState, nowMs, maxRollbackMs,
    ),
    read: (requestId, requestVersion) => readRecord(
      database, integrity, requestId, requestVersion,
    ),
    readLatest: (requestId) => readLatest(database, integrity, requestId),
    insert: (record) => insertRecord(database, integrity, record),
    replace: (record, expectedRevision) => replaceRecord(
      database, integrity, record, expectedRevision,
    ),
    appendAudit: (event) => appendAudit(database, integrity, event),
    enqueue: (envelope, responseDigest, createdAt) => enqueue(
      database, integrity, envelope, responseDigest, createdAt,
    ),
    cancelResponses: (requestId, requestVersion, requestDigest) => cancelResponses(
      database, requestId, requestVersion, requestDigest,
    ),
    reference: (domain, value) => integrity.reference(domain, value),
  });
}

function readLatest(database, integrity, requestId) {
  const row = database.prepare(`
    SELECT request_version FROM customer_audit_support_requests
    WHERE request_id = ? ORDER BY request_version DESC LIMIT 1
  `).get(checkedUuid(requestId, 'customer_audit_request_id_invalid'));
  return row ? readRecord(database, integrity, requestId, row.request_version) : null;
}

function readRecord(database, integrity, requestId, requestVersion) {
  checkedUuid(requestId, 'customer_audit_request_id_invalid');
  checkedPositiveVersion(requestVersion);
  const row = database.prepare(`
    SELECT request_digest, revision, record_json, record_mac
    FROM customer_audit_support_requests WHERE request_id = ? AND request_version = ?
  `).get(requestId, requestVersion);
  if (!row) return null;
  verifyMac(integrity, 'record', `${requestId}:${requestVersion}:${row.revision}`,
    row.record_json, row.record_mac);
  const record = parseCanonical(row.record_json, 'customer_audit_record_invalid');
  if (record.requestId !== requestId || record.requestVersion !== requestVersion
      || record.requestDigest !== row.request_digest || record.revision !== row.revision) {
    throw storeError('customer_audit_record_invalid');
  }
  return deepFreeze(record);
}

function insertRecord(database, integrity, rawRecord) {
  const record = checkedRecord(rawRecord);
  if (record.revision !== 1) throw storeError('customer_audit_revision_invalid');
  const document = canonical(record);
  const result = database.prepare(`
    INSERT OR IGNORE INTO customer_audit_support_requests
      (request_id, request_version, request_digest, revision, record_json, record_mac)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(record.requestId, record.requestVersion, record.requestDigest, record.revision, document,
    mac(integrity, 'record', `${record.requestId}:${record.requestVersion}:1`, document));
  return result.changes === 1;
}

function replaceRecord(database, integrity, rawRecord, expectedRevision) {
  const record = checkedRecord(rawRecord);
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1
      || record.revision !== expectedRevision + 1) {
    throw storeError('customer_audit_revision_invalid');
  }
  const document = canonical(record);
  const result = database.prepare(`
    UPDATE customer_audit_support_requests
    SET revision = ?, request_digest = ?, record_json = ?, record_mac = ?
    WHERE request_id = ? AND request_version = ? AND revision = ?
  `).run(record.revision, record.requestDigest, document,
    mac(integrity, 'record', `${record.requestId}:${record.requestVersion}:${record.revision}`, document),
    record.requestId, record.requestVersion, expectedRevision);
  return result.changes === 1;
}

function checkedRecord(raw) {
  const record = clonePlain(raw, 'customer_audit_record_invalid');
  const keys = [
    'appliedAt', 'approvalRef', 'cancellationAppliedAt', 'cancellationArtifact',
    'cancellationDigest', 'cancellationIssuedAt', 'cancellationSignatureDomain',
    'cancellationSigningKeyId', 'decidedAt', 'digest',
    'previousDigest', 'request', 'requestDigest',
    'requestId', 'requestVersion', 'respondedAt', 'responseDigest', 'responseEnvelope',
    'revision', 'signatureDomain', 'signingKeyId', 'status',
  ];
  if (!exactKeys(record, keys)
      || !UUID_RE.test(String(record.requestId || ''))
      || !Number.isSafeInteger(record.requestVersion) || record.requestVersion < 1
      || !Number.isSafeInteger(record.revision) || record.revision < 1
      || !SHA256_RE.test(String(record.requestDigest || ''))
      || record.digest !== record.requestDigest
      || (record.previousDigest !== null && !SHA256_RE.test(String(record.previousDigest)))
      || !['pending', 'approved', 'denied', 'expired', 'revoked', 'completed', 'superseded']
        .includes(record.status)
      || (record.approvalRef !== null && !LOCAL_AUDIT_REF_RE.test(String(record.approvalRef)))) {
    throw storeError('customer_audit_record_invalid');
  }
  let request;
  try { request = assertAuditSupportRequest(record.request); }
  catch { throw storeError('customer_audit_record_invalid'); }
  if (record.signatureDomain !== REQUEST_SIGNATURE_DOMAIN
      || !REQUEST_KEY_ID_RE.test(String(record.signingKeyId || ''))
      || request.requestId !== record.requestId
      || request.requestVersion !== record.requestVersion
      || auditSupportPayloadDigest(request, REQUEST_SIGNATURE_DOMAIN) !== record.requestDigest) {
    throw storeError('customer_audit_record_invalid');
  }
  canonicalIso(record.appliedAt, 'customer_audit_record_invalid');
  if (Date.parse(record.appliedAt) < Date.parse(request.notBefore)
      || Date.parse(record.appliedAt) >= Date.parse(request.expiresAt)) {
    throw storeError('customer_audit_record_invalid');
  }
  if (record.decidedAt !== null) canonicalIso(
    record.decidedAt, 'customer_audit_record_invalid',
  );
  if (record.respondedAt !== null) canonicalIso(
    record.respondedAt, 'customer_audit_record_invalid',
  );
  if (record.cancellationDigest !== null) {
    checkedDigest(record.cancellationDigest, 'customer_audit_record_invalid');
    canonicalIso(record.cancellationAppliedAt, 'customer_audit_record_invalid');
    canonicalIso(record.cancellationIssuedAt, 'customer_audit_record_invalid');
    if (Date.parse(record.cancellationAppliedAt) < Date.parse(record.cancellationIssuedAt)) {
      throw storeError('customer_audit_record_invalid');
    }
    let cancellation;
    try { cancellation = assertAuditSupportCancellation(record.cancellationArtifact?.payload); }
    catch { throw storeError('customer_audit_record_invalid'); }
    if (!record.cancellationArtifact
        || !exactKeys(record.cancellationArtifact, ['keyId', 'payload', 'signature'])
        || !REQUEST_KEY_ID_RE.test(String(record.cancellationArtifact.keyId || ''))
        || record.cancellationSigningKeyId !== record.cancellationArtifact.keyId
        || record.cancellationSignatureDomain !== CANCELLATION_SIGNATURE_DOMAIN
        || auditSupportPayloadDigest(cancellation, CANCELLATION_SIGNATURE_DOMAIN)
          !== record.cancellationDigest
        || cancellation.customerId !== request.customerId
        || cancellation.deploymentId !== request.deploymentId
        || cancellation.requestId !== record.requestId
        || cancellation.requestVersion !== record.requestVersion
        || cancellation.requestDigest !== record.requestDigest
        || cancellation.issuedAt !== record.cancellationIssuedAt) {
      throw storeError('customer_audit_record_invalid');
    }
    canonicalSignature(record.cancellationArtifact.signature, 'customer_audit_record_invalid');
  } else if (record.cancellationAppliedAt !== null || record.cancellationArtifact !== null
      || record.cancellationIssuedAt !== null
      || record.cancellationSignatureDomain !== null
      || record.cancellationSigningKeyId !== null) {
    throw storeError('customer_audit_record_invalid');
  }
  if (record.responseEnvelope !== null) {
    const envelope = clonePlain(record.responseEnvelope, 'customer_audit_record_invalid');
    if (!exactKeys(envelope, ['keyId', 'payload', 'signature'])
        || !RESPONSE_KEY_ID_RE.test(String(envelope.keyId || ''))) {
      throw storeError('customer_audit_record_invalid');
    }
    let response;
    try { response = assertCustomerAuditResponsePayload(envelope.payload); }
    catch { throw storeError('customer_audit_record_invalid'); }
    canonicalSignature(envelope.signature, 'customer_audit_record_invalid');
    if (record.responseDigest !== sha256(canonical(envelope))
        || record.respondedAt !== response.respondedAt
        || response.requestId !== record.requestId
        || response.requestVersion !== record.requestVersion
        || response.requestDigest !== record.requestDigest
        || response.customerId !== request.customerId
        || response.deploymentId !== request.deploymentId) {
      throw storeError('customer_audit_record_invalid');
    }
  } else if (record.responseDigest !== null || record.respondedAt !== null) {
    throw storeError('customer_audit_record_invalid');
  }
  assertCustomerRecordStateCoherence(record);
  return record;
}

function assertCustomerRecordStateCoherence(record) {
  const hasApproval = record.approvalRef !== null && record.decidedAt !== null;
  const noApproval = record.approvalRef === null && record.decidedAt === null;
  const hasResponse = record.responseEnvelope !== null && record.responseDigest !== null
    && record.respondedAt !== null;
  const noResponse = record.responseEnvelope === null && record.responseDigest === null
    && record.respondedAt === null;
  const hasCancellation = record.cancellationArtifact !== null
    && record.cancellationAppliedAt !== null && record.cancellationDigest !== null
    && record.cancellationIssuedAt !== null
    && record.cancellationSignatureDomain !== null && record.cancellationSigningKeyId !== null;
  const noCancellation = record.cancellationArtifact === null
    && record.cancellationAppliedAt === null && record.cancellationDigest === null
    && record.cancellationIssuedAt === null
    && record.cancellationSignatureDomain === null && record.cancellationSigningKeyId === null;
  const valid = {
    pending: noApproval && noResponse && noCancellation,
    approved: hasApproval && noResponse && noCancellation,
    completed: hasApproval && hasResponse && noCancellation,
    denied: hasApproval && (hasResponse || noResponse) && noCancellation,
    expired: hasApproval && noResponse && noCancellation,
    revoked: hasApproval && (hasResponse || noResponse)
      && (hasCancellation || noCancellation),
    superseded: (hasApproval || noApproval) && noResponse && noCancellation,
  }[record.status];
  if (!valid) throw storeError('customer_audit_record_invalid');
}

function trustedTime(transactionState, nowMs, maxRollbackMs) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0
      || !Number.isSafeInteger(maxRollbackMs) || maxRollbackMs < 0) {
    throw storeError('customer_audit_clock_invalid');
  }
  if (nowMs + maxRollbackMs < transactionState.trustedTimeMs) {
    throw storeError('audit_clock_rollback');
  }
  transactionState.trustedTimeMs = Math.max(nowMs, transactionState.trustedTimeMs);
  return transactionState.trustedTimeMs;
}

function appendAudit(database, integrity, rawEvent) {
  const body = checkedEvent(rawEvent);
  const prior = database.prepare(`
    SELECT sequence, event_digest, event_json, event_mac
    FROM customer_audit_support_audit ORDER BY sequence DESC LIMIT 1
  `).get();
  if (prior) verifyAuditRow(integrity, prior);
  const sequence = (prior?.sequence || 0) + 1;
  const previousDigest = prior?.event_digest || ZERO_DIGEST;
  const core = { schemaVersion: 1, sequence, previousDigest, ...body };
  const eventDigest = sha256(canonical(core));
  const event = { ...core, eventDigest };
  const document = canonical(event);
  database.prepare(`
    INSERT INTO customer_audit_support_audit
      (sequence, previous_digest, event_digest, event_json, event_mac)
    VALUES (?, ?, ?, ?, ?)
  `).run(sequence, previousDigest, eventDigest, document,
    mac(integrity, 'audit', String(sequence), document));
  return Object.freeze({
    event: deepFreeze(event),
    auditRef: integrity.reference('event', eventDigest),
  });
}

function checkedEvent(raw) {
  const event = clonePlain(raw, 'customer_audit_event_invalid');
  if (!exactKeys(event, [
    'authorizationRef', 'count', 'eventType', 'occurredAt', 'outcome',
    'requestDigest', 'requestVersion',
  ]) || !EVENT_TYPES.has(event.eventType) || !EVENT_OUTCOMES.has(event.outcome)
      || !Number.isSafeInteger(event.requestVersion) || event.requestVersion < 1
      || !SHA256_RE.test(String(event.requestDigest || ''))
      || !Number.isSafeInteger(event.count) || event.count < 0
      || (event.authorizationRef !== null
        && !LOCAL_AUDIT_REF_RE.test(String(event.authorizationRef || '')))) {
    throw storeError('customer_audit_event_invalid');
  }
  canonicalIso(event.occurredAt, 'customer_audit_event_invalid');
  return event;
}

function verifyAudit(database, integrity) {
  const rows = database.prepare(`
    SELECT sequence, previous_digest, event_digest, event_json, event_mac
    FROM customer_audit_support_audit ORDER BY sequence
  `).all();
  const events = [];
  let previous = ZERO_DIGEST;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    verifyAuditRow(integrity, row);
    const event = parseCanonical(row.event_json, 'customer_audit_integrity_failed');
    const core = { ...event };
    delete core.eventDigest;
    if (row.sequence !== index + 1 || row.previous_digest !== previous
        || event.sequence !== row.sequence || event.previousDigest !== previous
        || event.eventDigest !== row.event_digest || sha256(canonical(core)) !== row.event_digest) {
      throw storeError('customer_audit_integrity_failed');
    }
    checkedEvent({
      authorizationRef: event.authorizationRef,
      count: event.count,
      eventType: event.eventType,
      occurredAt: event.occurredAt,
      outcome: event.outcome,
      requestDigest: event.requestDigest,
      requestVersion: event.requestVersion,
    });
    events.push(deepFreeze(event));
    previous = row.event_digest;
  }
  return events;
}

function verifyAuditRow(integrity, row) {
  verifyMac(integrity, 'audit', String(row.sequence), row.event_json, row.event_mac);
}

function enqueue(database, integrity, rawEnvelope, responseDigest, createdAt) {
  const envelope = checkedResponseEnvelope(
    rawEnvelope, responseDigest, 'customer_audit_outbox_invalid',
  );
  const payload = envelope.payload;
  canonicalIso(createdAt, 'customer_audit_outbox_invalid');
  const document = canonical(envelope);
  const existing = database.prepare(`
    SELECT response_digest, document_json FROM customer_audit_support_outbox WHERE message_id = ?
  `).get(payload.messageId);
  if (existing) return existing.response_digest === responseDigest && existing.document_json === document;
  database.prepare(`
    INSERT INTO customer_audit_support_outbox
      (message_id, request_id, request_version, request_digest, response_digest,
       document_json, document_mac, status, attempts, next_attempt_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)
  `).run(payload.messageId, payload.requestId, payload.requestVersion, payload.requestDigest,
    responseDigest, document, mac(integrity, 'outbox', payload.messageId, document),
    createdAt, createdAt);
  return true;
}

function cancelResponses(database, requestId, requestVersion, requestDigest) {
  checkedUuid(requestId, 'customer_audit_outbox_invalid');
  checkedPositiveVersion(requestVersion);
  checkedDigest(requestDigest, 'customer_audit_outbox_invalid');
  return database.prepare(`
    UPDATE customer_audit_support_outbox
    SET status = 'cancelled', claim_token = NULL
    WHERE request_id = ? AND request_version = ? AND request_digest = ?
      AND status IN ('pending', 'sending', 'blocked')
  `).run(requestId, requestVersion, requestDigest).changes;
}

function claimOutbox(database, integrity, limit, now) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw storeError('customer_audit_outbox_limit_invalid');
  }
  const nowMs = Date.parse(canonicalIso(now, 'customer_audit_clock_invalid'));
  const leaseUntil = new Date(nowMs + OUTBOX_LEASE_MS).toISOString();
  database.prepare(`
    UPDATE customer_audit_support_outbox
    SET status = 'blocked', claim_token = NULL, last_error_code = 'delivery_lease_expired'
    WHERE status = 'sending' AND next_attempt_at <= ? AND attempts >= ?
  `).run(now, MAX_OUTBOX_ATTEMPTS);
  database.prepare(`
    UPDATE customer_audit_support_outbox
    SET status = 'pending', claim_token = NULL
    WHERE status = 'sending' AND next_attempt_at <= ? AND attempts < ?
  `).run(now, MAX_OUTBOX_ATTEMPTS);
  const rows = database.prepare(`
    SELECT message_id, request_digest, response_digest, document_json,
      document_mac, attempts
    FROM customer_audit_support_outbox
    WHERE status = 'pending' AND next_attempt_at <= ? AND attempts < ?
    ORDER BY created_at, message_id LIMIT ?
  `).all(now, MAX_OUTBOX_ATTEMPTS, limit);
  return deepFreeze(rows.map((row) => claimRow(database, integrity, row, leaseUntil)));
}

function claimRow(database, integrity, row, leaseUntil) {
  verifyMac(integrity, 'outbox', row.message_id, row.document_json, row.document_mac);
  if (sha256(row.document_json) !== row.response_digest) {
    throw storeError('customer_audit_outbox_integrity_failed');
  }
  const claimToken = crypto.randomUUID();
  const result = database.prepare(`
    UPDATE customer_audit_support_outbox
    SET status = 'sending', attempts = attempts + 1, next_attempt_at = ?, claim_token = ?
    WHERE message_id = ? AND status = 'pending'
  `).run(leaseUntil, claimToken, row.message_id);
  if (result.changes !== 1) throw storeError('customer_audit_outbox_conflict');
  return {
    messageId: row.message_id,
    requestDigest: row.request_digest,
    responseDigest: row.response_digest,
    document: parseCanonical(row.document_json, 'customer_audit_outbox_integrity_failed'),
    attempts: row.attempts + 1,
    claimToken,
  };
}

function markOutboxDelivered(database, messageId, responseDigest, deliveredAt, claimToken) {
  checkedUuid(messageId, 'customer_audit_outbox_claim_invalid');
  checkedUuid(claimToken, 'customer_audit_outbox_claim_invalid');
  checkedDigest(responseDigest, 'customer_audit_outbox_claim_invalid');
  canonicalIso(deliveredAt, 'customer_audit_outbox_claim_invalid');
  return database.prepare(`
    UPDATE customer_audit_support_outbox
    SET status = 'delivered', delivered_at = ?, last_error_code = NULL, claim_token = NULL
    WHERE message_id = ? AND response_digest = ? AND status = 'sending' AND claim_token = ?
  `).run(deliveredAt, messageId, responseDigest, claimToken).changes === 1;
}

function markOutboxRetry(database, messageId, responseDigest, nextAt, errorCode, claimToken) {
  checkedUuid(messageId, 'customer_audit_outbox_claim_invalid');
  checkedUuid(claimToken, 'customer_audit_outbox_claim_invalid');
  checkedDigest(responseDigest, 'customer_audit_outbox_claim_invalid');
  canonicalIso(nextAt, 'customer_audit_outbox_claim_invalid');
  checkedSafeCode(errorCode, 'customer_audit_outbox_error_invalid');
  const row = database.prepare(`
    SELECT attempts FROM customer_audit_support_outbox
    WHERE message_id = ? AND response_digest = ? AND status = 'sending' AND claim_token = ?
  `).get(messageId, responseDigest, claimToken);
  if (!row) return false;
  const status = row.attempts >= MAX_OUTBOX_ATTEMPTS ? 'blocked' : 'pending';
  return database.prepare(`
    UPDATE customer_audit_support_outbox
    SET status = ?, next_attempt_at = ?, last_error_code = ?, claim_token = NULL
    WHERE message_id = ? AND response_digest = ? AND status = 'sending' AND claim_token = ?
  `).run(status, nextAt, errorCode, messageId, responseDigest, claimToken).changes === 1;
}

function createCustomerAuditResponseOutboxWorker(options = {}) {
  assertReferenceRuntime();
  if (!isCustomerAuditSupportStore(options.store) || typeof options.send !== 'function') {
    throw storeError('customer_audit_worker_invalid');
  }
  const clock = typeof options.clock === 'function' ? options.clock : Date.now;
  return Object.freeze({
    async runOnce(limit = 16) {
      const nowMs = checkedClock(clock());
      const rows = options.store.claimOutbox(limit, new Date(nowMs).toISOString());
      const outcomes = [];
      for (const row of rows) outcomes.push(await deliverRow(options, row, clock));
      return outcomes;
    },
  });
}

async function deliverRow(options, row, clock) {
  try {
    const receipt = await options.send(deepFreeze({
      messageId: row.messageId,
      responseDigest: row.responseDigest,
      envelope: row.document,
    }));
    if (!receipt || receipt.accepted !== true || receipt.messageId !== row.messageId
        || receipt.responseDigest !== row.responseDigest) {
      throw storeError('customer_audit_delivery_receipt_invalid');
    }
    const deliveredAt = new Date(checkedClock(clock())).toISOString();
    if (!options.store.markOutboxDelivered(
      row.messageId, row.responseDigest, deliveredAt, row.claimToken,
    )) throw storeError('customer_audit_outbox_conflict');
    return Object.freeze({ messageId: row.messageId, status: 'delivered' });
  } catch (error) {
    const nextAt = new Date(checkedClock(clock())
      + Math.min(60 * 60 * 1000, 1000 * (2 ** Math.min(row.attempts, 10)))).toISOString();
    const code = SAFE_CODE_RE.test(String(error?.code || '')) ? error.code : 'delivery_failed';
    options.store.markOutboxRetry(
      row.messageId, row.responseDigest, nextAt, code, row.claimToken,
    );
    return Object.freeze({ messageId: row.messageId, status: 'retrying', reasonCode: code });
  }
}

function initializeAnchor(database, integrity, witness, anchorAuthority, anchorNamespace) {
  database.exec('BEGIN IMMEDIATE');
  try {
    reconcileExternalAnchor(
      database, integrity, witness, anchorAuthority, anchorNamespace,
    );
    const meta = readMeta(database);
    const anchor = readAnchor(database);
    if (isUninitializedMeta(meta) && !anchor) {
      assertGenesisEmpty(database);
      publishGenesis(database, integrity, witness);
    }
    else verifyCurrentSnapshot(
      database, integrity, witness, anchorAuthority, anchorNamespace,
    );
    database.exec('COMMIT');
  } catch (error) {
    try { database.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

function anchoredMutation(database, integrity, witness, anchorAuthority, anchorNamespace,
  anchorStatus, callback) {
  let transition = null;
  let committed = false;
  database.exec('BEGIN IMMEDIATE');
  try {
    reconcileExternalAnchor(
      database, integrity, witness, anchorAuthority, anchorNamespace,
    );
    anchorStatus.degraded = false;
    const verified = verifyCurrentSnapshot(
      database, integrity, witness, anchorAuthority, anchorNamespace,
    );
    const transactionState = {
      generation: verified.meta.generation,
      trustedTimeMs: verified.meta.trustedTimeMs,
    };
    const result = callback(transactionState);
    const nextCore = publishSnapshot(database, integrity, witness, transactionState);
    transition = externalAnchorTransition(
      anchorNamespace, metaCoreFromMeta(verified.meta), nextCore, witness,
    );
    assertPreparedAnchor(anchorAuthority.prepare(transition), transition);
    database.exec('COMMIT');
    committed = true;
    try { assertFinalizedAnchor(anchorAuthority.finalize(transition), transition); }
    catch { anchorStatus.degraded = true; }
    return result;
  } catch (error) {
    if (!committed) try { database.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

function publishGenesis(database, integrity, witness) {
  const snapshot = computeSnapshot(database, integrity);
  const core = metaCore(0, 0, snapshot);
  writeMeta(database, integrity, core, 0);
  insertAnchor(database, witness, core);
}

function publishSnapshot(database, integrity, witness, transactionState) {
  const snapshot = computeSnapshot(database, integrity);
  const core = metaCore(
    transactionState.generation + 1, transactionState.trustedTimeMs, snapshot,
  );
  writeMeta(database, integrity, core, transactionState.generation);
  replaceAnchor(database, witness, core, transactionState.generation);
  return core;
}

function verifyCurrentSnapshot(database, integrity, witness, anchorAuthority, anchorNamespace) {
  const meta = readMeta(database);
  if (meta.metaMac === '') throw storeError('customer_audit_anchor_uninitialized');
  verifyMeta(integrity, meta);
  verifyAnchor(witness, meta, readAnchor(database));
  const snapshot = computeSnapshot(database, integrity);
  if (!snapshotMatches(meta, snapshot)) {
    throw storeError('customer_audit_snapshot_rewind');
  }
  assertExternalAnchorCurrent(anchorAuthority.read(anchorNamespace), meta);
  return { events: snapshot.events, meta };
}

function reconcileExternalAnchor(database, integrity, witness, anchorAuthority, anchorNamespace) {
  let external = checkedExternalAnchorState(anchorAuthority.read(anchorNamespace), anchorNamespace);
  const meta = readMeta(database);
  if (isUninitializedMeta(meta)) {
    if (external.pending || external.revision !== 0 || external.headDigest !== ZERO_DIGEST) {
      throw storeError('customer_audit_anchor_mismatch');
    }
    return;
  }
  verifyMeta(integrity, meta);
  verifyAnchor(witness, meta, readAnchor(database));
  const snapshot = computeSnapshot(database, integrity);
  if (!snapshotMatches(meta, snapshot)) throw storeError('customer_audit_snapshot_rewind');
  if (external.pending) {
    const transition = transitionFromExternal(anchorNamespace, external);
    const localDigest = externalHeadDigest(metaCoreFromMeta(meta));
    if (meta.generation === transition.targetRevision
        && localDigest === transition.targetDigest) {
      assertFinalizedAnchor(anchorAuthority.finalize(transition), transition);
    } else if (meta.generation === transition.expectedRevision
        && localDigest === transition.expectedDigest) {
      anchorAuthority.abort(transition);
    } else throw storeError('customer_audit_anchor_mismatch');
    external = checkedExternalAnchorState(anchorAuthority.read(anchorNamespace), anchorNamespace);
  }
  assertExternalAnchorCurrent(external, meta);
}

function externalAnchorTransition(namespace, previousCore, nextCore, witness) {
  return {
    namespace,
    expectedRevision: previousCore.generation,
    expectedDigest: externalHeadDigest(previousCore),
    targetRevision: nextCore.generation,
    targetDigest: externalHeadDigest(nextCore),
    witnessDigest: sha256(canonical(anchorDocument(witness, nextCore))),
  };
}

function transitionFromExternal(namespace, state) {
  return {
    namespace,
    expectedRevision: state.pending.expectedRevision,
    expectedDigest: state.pending.expectedDigest,
    targetRevision: state.pending.targetRevision,
    targetDigest: state.pending.targetDigest,
    witnessDigest: state.pending.witnessDigest,
  };
}

function externalHeadDigest(core) {
  return core.generation === 0 ? ZERO_DIGEST : sha256(canonical(core));
}

function assertExternalAnchorCurrent(rawState, meta) {
  const state = checkedExternalAnchorState(rawState);
  if (state.pending || state.revision !== meta.generation
      || state.headDigest !== externalHeadDigest(metaCoreFromMeta(meta))) {
    throw storeError('customer_audit_anchor_mismatch');
  }
}

function assertPreparedAnchor(rawState, transition) {
  const state = checkedExternalAnchorState(rawState, transition.namespace);
  if (!state.pending || state.revision !== transition.expectedRevision
      || state.headDigest !== transition.expectedDigest
      || canonical(transitionFromExternal(transition.namespace, state)) !== canonical(transition)) {
    throw storeError('customer_audit_anchor_prepare_failed');
  }
}

function assertFinalizedAnchor(rawState, transition) {
  const state = checkedExternalAnchorState(rawState, transition.namespace);
  if (state.pending || state.revision !== transition.targetRevision
      || state.headDigest !== transition.targetDigest) {
    throw storeError('customer_audit_anchor_finalize_failed');
  }
}

function checkedExternalAnchorState(value, namespace) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !Number.isSafeInteger(value.revision) || value.revision < 0
      || !SHA256_RE.test(String(value.headDigest || ''))
      || (namespace !== undefined && value.namespace !== namespace)
      || (value.pending !== null && (!value.pending || typeof value.pending !== 'object'))) {
    throw storeError('customer_audit_anchor_invalid');
  }
  return value;
}

function computeSnapshot(database, integrity) {
  const events = verifyAudit(database, integrity);
  return {
    auditHead: events.at(-1)?.eventDigest || ZERO_DIGEST,
    auditSequence: events.length,
    events,
    outboxDigest: outboxSnapshotDigest(database, integrity),
    stateDigest: stateSnapshotDigest(database, integrity),
  };
}

function stateSnapshotDigest(database, integrity) {
  const rows = database.prepare(`
    SELECT request_id, request_version, request_digest, revision, record_json, record_mac
    FROM customer_audit_support_requests ORDER BY request_id, request_version
  `).all();
  const commitments = rows.map((row) => stateRowCommitment(row, integrity));
  return sha256(canonical(commitments));
}

function stateRowCommitment(row, integrity) {
  verifyMac(integrity, 'record', `${row.request_id}:${row.request_version}:${row.revision}`,
    row.record_json, row.record_mac);
  const record = checkedRecord(parseCanonical(row.record_json, 'customer_audit_record_invalid'));
  if (record.requestId !== row.request_id || record.requestVersion !== row.request_version
      || record.requestDigest !== row.request_digest || record.revision !== row.revision) {
    throw storeError('customer_audit_record_invalid');
  }
  return {
    recordDigest: sha256(row.record_json),
    recordMac: row.record_mac,
    requestDigest: row.request_digest,
    requestId: row.request_id,
    requestVersion: row.request_version,
    revision: row.revision,
  };
}

function outboxSnapshotDigest(database, integrity) {
  const rows = database.prepare(`
    SELECT message_id, request_id, request_version, request_digest, response_digest,
      document_json, document_mac, status, attempts, next_attempt_at, last_error_code,
      created_at, delivered_at, claim_token
    FROM customer_audit_support_outbox ORDER BY message_id
  `).all();
  const commitments = rows.map((row) => outboxRowCommitment(row, integrity));
  return sha256(canonical(commitments));
}

function outboxRowCommitment(row, integrity) {
  verifyMac(integrity, 'outbox', row.message_id, row.document_json, row.document_mac);
  const envelope = parseCanonical(row.document_json, 'customer_audit_outbox_integrity_failed');
  const checked = checkedResponseEnvelope(
    envelope, row.response_digest, 'customer_audit_outbox_integrity_failed',
  );
  if (checked.payload.messageId !== row.message_id
      || checked.payload.requestId !== row.request_id
      || checked.payload.requestVersion !== row.request_version
      || checked.payload.requestDigest !== row.request_digest
      || sha256(row.document_json) !== row.response_digest) {
    throw storeError('customer_audit_outbox_integrity_failed');
  }
  return {
    attempts: row.attempts,
    claimToken: row.claim_token,
    createdAt: row.created_at,
    deliveredAt: row.delivered_at,
    documentDigest: sha256(row.document_json),
    documentMac: row.document_mac,
    lastErrorCode: row.last_error_code,
    messageId: row.message_id,
    nextAttemptAt: row.next_attempt_at,
    requestDigest: row.request_digest,
    requestId: row.request_id,
    requestVersion: row.request_version,
    responseDigest: row.response_digest,
    status: row.status,
  };
}

function checkedResponseEnvelope(rawEnvelope, responseDigest, code) {
  const envelope = clonePlain(rawEnvelope, code);
  if (!SHA256_RE.test(String(responseDigest || ''))
      || !exactKeys(envelope, ['keyId', 'payload', 'signature'])
      || !RESPONSE_KEY_ID_RE.test(String(envelope.keyId || ''))
      || sha256(canonical(envelope)) !== responseDigest) throw storeError(code);
  try { assertCustomerAuditResponsePayload(envelope.payload); }
  catch { throw storeError(code); }
  canonicalSignature(envelope.signature, code);
  return envelope;
}

function readMeta(database) {
  const row = database.prepare(`
    SELECT schema_version, generation, trusted_time_ms, state_digest, outbox_digest,
      audit_sequence, audit_head, meta_mac
    FROM customer_audit_support_meta WHERE singleton = 1
  `).get();
  if (!row || row.schema_version !== SCHEMA_VERSION) {
    throw storeError('customer_audit_schema_unsupported');
  }
  const meta = {
    schemaVersion: row.schema_version,
    generation: row.generation,
    trustedTimeMs: row.trusted_time_ms,
    stateDigest: row.state_digest,
    outboxDigest: row.outbox_digest,
    auditSequence: row.audit_sequence,
    auditHead: row.audit_head,
    metaMac: row.meta_mac,
  };
  validateMeta(meta);
  return meta;
}

function readAnchor(database) {
  const row = database.prepare(`
    SELECT schema_version, generation, trusted_time_ms, state_digest, outbox_digest,
      audit_sequence, audit_head, anchor_digest, anchor_mac
    FROM audit_witness.customer_audit_support_anchor WHERE singleton = 1
  `).get();
  if (!row) return null;
  return {
    schemaVersion: row.schema_version,
    generation: row.generation,
    trustedTimeMs: row.trusted_time_ms,
    stateDigest: row.state_digest,
    outboxDigest: row.outbox_digest,
    auditSequence: row.audit_sequence,
    auditHead: row.audit_head,
    anchorDigest: row.anchor_digest,
    anchorMac: row.anchor_mac,
  };
}

function metaCore(generation, trustedTimeMs, snapshot) {
  return {
    schemaVersion: SCHEMA_VERSION,
    generation,
    trustedTimeMs,
    stateDigest: snapshot.stateDigest,
    outboxDigest: snapshot.outboxDigest,
    auditSequence: snapshot.auditSequence,
    auditHead: snapshot.auditHead,
  };
}

function validateMeta(meta) {
  if (!Number.isSafeInteger(meta.generation) || meta.generation < 0
      || !Number.isSafeInteger(meta.trustedTimeMs) || meta.trustedTimeMs < 0
      || !Number.isSafeInteger(meta.auditSequence) || meta.auditSequence < 0
      || !SHA256_RE.test(String(meta.stateDigest || ''))
      || !SHA256_RE.test(String(meta.outboxDigest || ''))
      || !SHA256_RE.test(String(meta.auditHead || ''))
      || typeof meta.metaMac !== 'string') throw storeError('customer_audit_meta_invalid');
}

function verifyMeta(integrity, meta) {
  const core = metaCoreFromMeta(meta);
  verifyMac(integrity, 'meta', '1', canonical(core), meta.metaMac);
}

function verifyAnchor(witness, meta, anchor) {
  if (!anchor) throw storeError('customer_audit_witness_missing');
  const core = metaCoreFromMeta(anchor);
  const digest = sha256(canonical(core));
  if (anchor.anchorDigest !== digest || !sameMetaCore(meta, anchor)) {
    throw storeError('customer_audit_witness_mismatch');
  }
  verifyWitnessMac(witness, anchor.generation, { ...core, anchorDigest: digest },
    anchor.anchorMac);
}

function writeMeta(database, integrity, core, expectedGeneration) {
  const result = database.prepare(`
    UPDATE customer_audit_support_meta
    SET schema_version = ?, generation = ?, trusted_time_ms = ?, state_digest = ?,
      outbox_digest = ?, audit_sequence = ?, audit_head = ?, meta_mac = ?
    WHERE singleton = 1 AND generation = ?
  `).run(core.schemaVersion, core.generation, core.trustedTimeMs, core.stateDigest,
    core.outboxDigest, core.auditSequence, core.auditHead,
    mac(integrity, 'meta', '1', canonical(core)), expectedGeneration);
  if (result.changes !== 1) throw storeError('customer_audit_meta_conflict');
}

function insertAnchor(database, witness, core) {
  const anchor = anchorDocument(witness, core);
  database.prepare(`
    INSERT INTO audit_witness.customer_audit_support_anchor
      (singleton, schema_version, generation, trusted_time_ms, state_digest,
       outbox_digest, audit_sequence, audit_head, anchor_digest, anchor_mac)
    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(core.schemaVersion, core.generation, core.trustedTimeMs, core.stateDigest,
    core.outboxDigest, core.auditSequence, core.auditHead, anchor.anchorDigest,
    anchor.anchorMac);
}

function replaceAnchor(database, witness, core, expectedGeneration) {
  const anchor = anchorDocument(witness, core);
  const result = database.prepare(`
    UPDATE audit_witness.customer_audit_support_anchor
    SET schema_version = ?, generation = ?, trusted_time_ms = ?, state_digest = ?,
      outbox_digest = ?, audit_sequence = ?, audit_head = ?, anchor_digest = ?, anchor_mac = ?
    WHERE singleton = 1 AND generation = ?
  `).run(core.schemaVersion, core.generation, core.trustedTimeMs, core.stateDigest,
    core.outboxDigest, core.auditSequence, core.auditHead, anchor.anchorDigest,
    anchor.anchorMac, expectedGeneration);
  if (result.changes !== 1) throw storeError('customer_audit_witness_conflict');
}

function anchorDocument(witness, core) {
  const anchorDigest = sha256(canonical(core));
  const document = { ...core, anchorDigest };
  return {
    anchorDigest,
    anchorMac: witness.mac(
      `customer-audit-support:witness:${core.generation}`, canonical(document),
    ),
  };
}

function verifyWitnessMac(witness, generation, document, actual) {
  const expected = witness.mac(
    `customer-audit-support:witness:${generation}`, canonical(document),
  );
  const left = Buffer.from(String(actual || ''), 'utf8');
  const right = Buffer.from(expected, 'utf8');
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) {
    throw storeError('customer_audit_witness_integrity_failed');
  }
}

function metaCoreFromMeta(value) {
  return {
    schemaVersion: value.schemaVersion,
    generation: value.generation,
    trustedTimeMs: value.trustedTimeMs,
    stateDigest: value.stateDigest,
    outboxDigest: value.outboxDigest,
    auditSequence: value.auditSequence,
    auditHead: value.auditHead,
  };
}

function sameMetaCore(left, right) {
  return canonical(metaCoreFromMeta(left)) === canonical(metaCoreFromMeta(right));
}

function snapshotMatches(meta, snapshot) {
  return meta.stateDigest === snapshot.stateDigest
    && meta.outboxDigest === snapshot.outboxDigest
    && meta.auditSequence === snapshot.auditSequence
    && meta.auditHead === snapshot.auditHead;
}

function isUninitializedMeta(meta) {
  return meta.generation === 0 && meta.trustedTimeMs === 0 && meta.metaMac === '';
}

function assertGenesisEmpty(database) {
  const tables = [
    'customer_audit_support_requests',
    'customer_audit_support_audit',
    'customer_audit_support_outbox',
  ];
  for (const table of tables) {
    const row = database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get();
    if (row.count !== 0) throw storeError('customer_audit_genesis_not_empty');
  }
}

function checkedIntegrity(value) {
  if (!value || value[INTEGRITY_BRAND] !== true || typeof value.mac !== 'function'
      || typeof value.reference !== 'function' || !SAFE_CODE_RE.test(String(value.keyId || ''))
      || !SHA256_RE.test(String(value.identity || ''))) {
    throw storeError('customer_audit_integrity_required');
  }
  return value;
}

function checkedWitness(value, integrity) {
  if (!value || value[WITNESS_BRAND] !== true || typeof value.mac !== 'function'
      || !SAFE_CODE_RE.test(String(value.keyId || ''))
      || !SHA256_RE.test(String(value.identity || ''))
      || value.keyId === integrity.keyId || value.identity === integrity.identity) {
    throw storeError('customer_audit_witness_required');
  }
  return value;
}

function checkedAnchorNamespace(value) {
  if (!ANCHOR_NAMESPACE_RE.test(String(value || ''))) {
    throw storeError('customer_audit_anchor_namespace_required');
  }
  return value;
}

function checkedAnchorAuthority(value, integrity, witness) {
  const methods = ['abort', 'describe', 'finalize', 'prepare', 'read'];
  if (!value || typeof value !== 'object'
      || methods.some((method) => typeof value[method] !== 'function')) {
    throw storeError('customer_audit_anchor_authority_required');
  }
  const descriptor = value.describe();
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)
      || descriptor.purpose !== CUSTOMER_AUDIT_ANCHOR_PURPOSE
      || ![INDEPENDENT_WITNESS_ASSURANCE, TEST_WITNESS_ASSURANCE]
        .includes(descriptor.assurance)
      || !SHA256_RE.test(String(descriptor.identity || ''))
      || descriptor.identity === integrity.identity
      || descriptor.identity === witness.identity) {
    throw storeError('customer_audit_anchor_authority_required');
  }
  return value;
}

function isCustomerAuditSupportStore(value) {
  return Boolean(value && value[STORE_BRAND] === true);
}

function checkedSecret(value) {
  const bytes = Buffer.isBuffer(value) ? Buffer.from(value) : null;
  if (!bytes || bytes.length !== 32) throw storeError('customer_audit_integrity_invalid');
  return bytes;
}

function mac(integrity, domain, id, document) {
  return integrity.mac(`customer-audit-support:${domain}:${id}`, document);
}

function verifyMac(integrity, domain, id, document, actual) {
  const expected = mac(integrity, domain, id, document);
  const left = Buffer.from(String(actual || ''), 'utf8');
  const right = Buffer.from(expected, 'utf8');
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) {
    throw storeError('customer_audit_integrity_failed');
  }
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
function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function checkedUuid(value, code) {
  if (!UUID_RE.test(String(value || ''))) throw storeError(code);
  return value;
}
function checkedPositiveVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw storeError('customer_audit_version_invalid');
  return value;
}
function checkedDigest(value, code) {
  if (!SHA256_RE.test(String(value || ''))) throw storeError(code);
  return value;
}
function checkedSafeCode(value, code) {
  if (!SAFE_CODE_RE.test(String(value || ''))) throw storeError(code);
  return value;
}
function canonicalIso(value, code) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw storeError(code);
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
function checkedClock(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw storeError('customer_audit_clock_invalid');
  return value;
}
function assertOpen(closed) { if (closed) throw storeError('customer_audit_store_closed'); }
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

function storeError(code) {
  const error = new Error('customer audit support storage rejected');
  error.code = code;
  return error;
}

function assertReferenceRuntime() {
  if (process.env.NODE_ENV === 'production') {
    throw storeError('customer_audit_reference_runtime_forbidden');
  }
}

module.exports = {
  createCustomerAuditResponseOutboxWorker,
  createReferenceCustomerAuditIntegrityAuthority,
  createReferenceCustomerAuditWitnessAuthority,
  isCustomerAuditSupportStore,
  openCustomerAuditSupportSqlite,
  openProductionCustomerAuditSupportStore,
};
