'use strict';

const crypto = require('node:crypto');
const Database = require('better-sqlite3');
const policyState = require('./connected-policy-state');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');

const CONNECTED_POLICY_SCHEMA_VERSION = 2;
const MAX_OUTBOX_ATTEMPTS = 16;
const OUTBOX_LEASE_MS = 60 * 1000;
const ZERO_DIGEST = '0'.repeat(64);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const CUSTOMER_POLICY_PACKAGE_BOUNDARY = Object.freeze({
  includes: Object.freeze([
    'connected-policy-state', 'connected-policy-store', 'deployment-identity',
    'policy-control-verifier',
  ]),
  excludes: Object.freeze([
    'vendor-policy-authority', 'vendor-policy-protocol', 'vendor-policy-sqlite',
    'vendor signing private keys',
    'Owner routes', 'commercial billing secrets', 'global lifecycle ledgers',
  ]),
});

const MIGRATION = `
CREATE TABLE IF NOT EXISTS connected_policy_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL
);
INSERT OR IGNORE INTO connected_policy_meta(singleton, schema_version) VALUES (1, 2);
CREATE TABLE IF NOT EXISTS connected_policy_state (
  scope_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  deployment_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  state_json TEXT NOT NULL,
  state_mac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS connected_policy_override (
  scope_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  override_json TEXT NOT NULL,
  override_digest TEXT NOT NULL,
  override_mac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS connected_policy_audit (
  scope_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  previous_digest TEXT NOT NULL,
  event_digest TEXT NOT NULL,
  event_json TEXT NOT NULL,
  event_mac TEXT NOT NULL,
  PRIMARY KEY(scope_id, sequence)
);
CREATE TABLE IF NOT EXISTS connected_policy_outbox (
  message_id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL,
  message_kind TEXT NOT NULL,
  document_json TEXT NOT NULL,
  document_digest TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  next_attempt_at TEXT NOT NULL,
  last_error_code TEXT,
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  claim_token TEXT
);
CREATE INDEX IF NOT EXISTS connected_policy_outbox_ready
  ON connected_policy_outbox(status, next_attempt_at, created_at);
`;

function openConnectedPolicyStore(options = {}) {
  const driver = String(options.driver || 'sqlite').toLowerCase();
  if (driver === 'postgres' || driver === 'postgresql') {
    throw storeError('connected_policy_postgres_adapter_not_implemented');
  }
  if (driver !== 'sqlite') throw storeError('connected_policy_storage_driver_invalid');
  const integrity = createIntegrity(options.integrityAuthority);
  const database = options.database || new Database(options.path || ':memory:');
  database.pragma('foreign_keys = ON');
  database.pragma('journal_mode = WAL');
  database.pragma('synchronous = FULL');
  database.pragma('busy_timeout = 30000');
  database.exec(MIGRATION);
  let schema = database.prepare(
    'SELECT schema_version FROM connected_policy_meta WHERE singleton = 1',
  ).get();
  if (schema?.schema_version === 1) {
    const columns = database.prepare('PRAGMA table_info(connected_policy_outbox)').all();
    if (!columns.some((column) => column.name === 'claim_token')) {
      database.exec('ALTER TABLE connected_policy_outbox ADD COLUMN claim_token TEXT');
    }
    database.prepare(
      'UPDATE connected_policy_meta SET schema_version = 2 WHERE singleton = 1 AND schema_version = 1',
    ).run();
    schema = database.prepare(
      'SELECT schema_version FROM connected_policy_meta WHERE singleton = 1',
    ).get();
  }
  if (!schema || schema.schema_version !== CONNECTED_POLICY_SCHEMA_VERSION) {
    throw storeError('connected_policy_schema_unsupported');
  }
  return createStore(database, integrity);
}

function createStore(database, integrity) {
  let closed = false;
  const api = {
    kind: 'sqlite',
    schemaVersion: CONNECTED_POLICY_SCHEMA_VERSION,
    load(customerId, deploymentId) {
      assertOpen(closed);
      return loadState(database, integrity, customerId, deploymentId);
    },
    receive(expectedRevision, signedArtifact, options) {
      return mutate(database, integrity, options.customerId, options.deploymentId, expectedRevision,
        'policy_candidate_cached', (state) => policyState.receiveSignedPolicyRollout(
          state, signedArtifact, options,
        ).state, options.nowMs);
    },
    activate(expectedRevision, command, options) {
      return mutate(database, integrity, options.customerId, options.deploymentId, expectedRevision,
        'policy_candidate_activated', (state) => policyState.activateRequiredPolicy(
          state, command, options,
        ).state, options.nowMs);
    },
    setLocalOverride(customerId, deploymentId, expectedRevision, command, options = {}) {
      return mutate(database, integrity, customerId, deploymentId, expectedRevision,
        'policy_local_override_updated', (state) => policyState.setLocalPolicyOverride(
          state, command, { ...options, customerId, deploymentId },
        ).state, options.nowMs, true);
    },
    recordCandidateRejection(customerId, deploymentId, expectedRevision, acknowledgement, options = {}) {
      return mutate(database, integrity, customerId, deploymentId, expectedRevision,
        'policy_candidate_rejected', (state) => policyState.recordCandidateRejection(
          state, acknowledgement, { ...options, customerId, deploymentId },
        ).state, options.nowMs);
    },
    enqueue(document, messageKind, now = new Date().toISOString()) {
      assertOpen(closed);
      return enqueue(database, document, messageKind, now);
    },
    claimOutbox(limit, now = new Date().toISOString()) {
      assertOpen(closed);
      return claimOutbox(database, limit, now);
    },
    markOutboxDelivered(messageId, documentDigest, deliveredAt, claimToken) {
      assertOpen(closed);
      if (!UUID_RE.test(String(claimToken || '')) || !canonicalTime(deliveredAt)) {
        throw storeError('connected_policy_outbox_claim_invalid');
      }
      const result = database.prepare(`
        UPDATE connected_policy_outbox SET status = 'delivered', delivered_at = ?,
          last_error_code = NULL, claim_token = NULL
        WHERE message_id = ? AND document_digest = ? AND status = 'sending' AND claim_token = ?
      `).run(deliveredAt, messageId, documentDigest, claimToken);
      return result.changes === 1;
    },
    markOutboxRetry(messageId, documentDigest, nextAttemptAt, errorCode, claimToken) {
      assertOpen(closed);
      if (!/^[a-z0-9][a-z0-9_.:-]{0,79}$/.test(String(errorCode || ''))) {
        throw storeError('connected_policy_outbox_error_invalid');
      }
      if (!UUID_RE.test(String(claimToken || '')) || !canonicalTime(nextAttemptAt)) {
        throw storeError('connected_policy_outbox_claim_invalid');
      }
      const row = database.prepare(`
        SELECT attempts FROM connected_policy_outbox
        WHERE message_id = ? AND document_digest = ? AND status = 'sending' AND claim_token = ?
      `).get(messageId, documentDigest, claimToken);
      if (!row) return false;
      const status = row.attempts >= MAX_OUTBOX_ATTEMPTS ? 'blocked' : 'pending';
      return database.prepare(`
        UPDATE connected_policy_outbox SET status = ?, next_attempt_at = ?, last_error_code = ?,
          claim_token = NULL
        WHERE message_id = ? AND document_digest = ? AND status = 'sending' AND claim_token = ?
      `).run(status, nextAttemptAt, errorCode, messageId, documentDigest, claimToken).changes === 1;
    },
    readiness(now = new Date().toISOString()) {
      assertOpen(closed);
      const check = database.pragma('quick_check', { simple: true });
      const blocked = database.prepare(
        "SELECT COUNT(*) AS count FROM connected_policy_outbox WHERE status = 'blocked'",
      ).get().count;
      const due = database.prepare(`
        SELECT COUNT(*) AS count FROM connected_policy_outbox
        WHERE status IN ('pending', 'sending') AND next_attempt_at <= ?
      `).get(now).count;
      return {
        ready: check === 'ok' && blocked === 0,
        storage: check === 'ok' ? 'ok' : 'failed',
        outboxBlocked: blocked,
        outboxDue: due,
        postgresSupported: false,
      };
    },
    close() { if (!closed) database.close(); closed = true; },
    database,
  };
  return Object.freeze(api);
}

function createPolicyOutboxWorker(options = {}) {
  if (!options.store || typeof options.store.claimOutbox !== 'function'
      || typeof options.send !== 'function') throw storeError('connected_policy_worker_invalid');
  const clock = typeof options.clock === 'function' ? options.clock : Date.now;
  return Object.freeze({
    async runOnce(limit = 16) {
      const nowMs = clock();
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw storeError('connected_policy_clock_invalid');
      const rows = options.store.claimOutbox(limit, new Date(nowMs).toISOString());
      const results = [];
      for (const row of rows) {
        try {
          const response = await options.send({
            messageId: row.messageId,
            messageKind: row.messageKind,
            document: row.document,
            documentDigest: row.documentDigest,
          });
          if (!response || response.accepted !== true || response.messageId !== row.messageId
              || response.documentDigest !== row.documentDigest) {
            throw workerError('delivery_receipt_invalid');
          }
          const deliveredAt = new Date(clock()).toISOString();
          if (!options.store.markOutboxDelivered(
            row.messageId, row.documentDigest, deliveredAt, row.claimToken,
          )) {
            throw workerError('outbox_delivery_conflict');
          }
          results.push({ messageId: row.messageId, status: 'delivered' });
        } catch (error) {
          const delay = Math.min(60 * 60 * 1000, 1000 * (2 ** Math.min(row.attempts, 10)));
          const nextAttemptAt = new Date(clock() + delay).toISOString();
          const code = /^[a-z0-9][a-z0-9_.:-]{0,79}$/.test(String(error?.code || ''))
            ? error.code : 'delivery_failed';
          options.store.markOutboxRetry(
            row.messageId, row.documentDigest, nextAttemptAt, code, row.claimToken,
          );
          results.push({ messageId: row.messageId, status: 'retrying', reasonCode: code });
        }
      }
      return results;
    },
  });
}

function loadState(database, integrity, customerId, deploymentId) {
  assertScope(customerId, deploymentId);
  const scopeId = scopeDigest(customerId, deploymentId);
  const row = database.prepare(
    'SELECT revision, state_json, state_mac FROM connected_policy_state WHERE scope_id = ?',
  ).get(scopeId);
  if (!row) return { revision: 0, state: policyState.initialRolloutState(customerId, deploymentId) };
  verifyMac(integrity, 'state', scopeId, row.revision, row.state_json, row.state_mac);
  const state = policyState.restoreRolloutState(parseCanonical(row.state_json), { customerId, deploymentId });
  const override = database.prepare(`
    SELECT revision, override_json, override_digest, override_mac
    FROM connected_policy_override WHERE scope_id = ?
  `).get(scopeId);
  if (!override) throw storeError('connected_policy_override_missing');
  verifyMac(integrity, 'override', scopeId, override.revision, override.override_json, override.override_mac);
  if (override.revision !== state.localOverrideRevision
      || override.override_digest !== state.localOverrideDigest
      || canonical(state.localOverride) !== override.override_json) {
    throw storeError('connected_policy_override_invalid');
  }
  verifyAudit(database, integrity, scopeId);
  return { revision: row.revision, state };
}

function mutate(database, integrity, customerId, deploymentId, expectedRevision,
  action, transform, nowMs, overrideChanged = false) {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw storeError('connected_policy_revision_invalid');
  }
  database.exec('BEGIN IMMEDIATE');
  try {
    const loaded = loadState(database, integrity, customerId, deploymentId);
    if (loaded.revision !== expectedRevision) throw storeError('connected_policy_revision_conflict');
    const state = policyState.restoreRolloutState(transform(loaded.state), { customerId, deploymentId });
    const revision = expectedRevision + 1;
    const scopeId = scopeDigest(customerId, deploymentId);
    const stateJson = canonical(state);
    const stateMac = mac(integrity, 'state', scopeId, revision, stateJson);
    if (expectedRevision === 0) {
      database.prepare(`
        INSERT INTO connected_policy_state
          (scope_id, customer_id, deployment_id, revision, state_json, state_mac)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(scopeId, customerId, deploymentId, revision, stateJson, stateMac);
    } else {
      const result = database.prepare(`
        UPDATE connected_policy_state SET revision = ?, state_json = ?, state_mac = ?
        WHERE scope_id = ? AND revision = ?
      `).run(revision, stateJson, stateMac, scopeId, expectedRevision);
      if (result.changes !== 1) throw storeError('connected_policy_revision_conflict');
    }
    const overrideJson = canonical(state.localOverride);
    const overrideMac = mac(integrity, 'override', scopeId, state.localOverrideRevision, overrideJson);
    database.prepare(`
      INSERT INTO connected_policy_override
        (scope_id, revision, override_json, override_digest, override_mac)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(scope_id) DO UPDATE SET
        revision = excluded.revision,
        override_json = excluded.override_json,
        override_digest = excluded.override_digest,
        override_mac = excluded.override_mac
    `).run(scopeId, state.localOverrideRevision, overrideJson, state.localOverrideDigest, overrideMac);
    appendAudit(database, integrity, scopeId, {
      action,
      stateRevision: revision,
      stateDigest: digest(stateJson),
      overrideRevision: state.localOverrideRevision,
      overrideDigest: state.localOverrideDigest,
      overrideChanged,
      recordedAt: new Date(nowMs === undefined ? Date.now() : nowMs).toISOString(),
    });
    database.exec('COMMIT');
    return { revision, state };
  } catch (error) {
    try { database.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

function appendAudit(database, integrity, scopeId, body) {
  const prior = database.prepare(`
    SELECT sequence, event_digest FROM connected_policy_audit
    WHERE scope_id = ? ORDER BY sequence DESC LIMIT 1
  `).get(scopeId);
  const sequence = (prior?.sequence || 0) + 1;
  const previousDigest = prior?.event_digest || ZERO_DIGEST;
  const core = { schemaVersion: 1, sequence, previousDigest, ...body };
  const eventDigest = digest(canonical(core));
  const event = { ...core, eventDigest };
  const eventJson = canonical(event);
  database.prepare(`
    INSERT INTO connected_policy_audit
      (scope_id, sequence, previous_digest, event_digest, event_json, event_mac)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(scopeId, sequence, previousDigest, eventDigest, eventJson,
    mac(integrity, 'audit', scopeId, sequence, eventJson));
}

function verifyAudit(database, integrity, scopeId) {
  const rows = database.prepare(`
    SELECT sequence, previous_digest, event_digest, event_json, event_mac
    FROM connected_policy_audit WHERE scope_id = ? ORDER BY sequence
  `).all(scopeId);
  let previous = ZERO_DIGEST;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    verifyMac(integrity, 'audit', scopeId, row.sequence, row.event_json, row.event_mac);
    const event = parseCanonical(row.event_json);
    const core = { ...event };
    delete core.eventDigest;
    if (row.sequence !== index + 1 || row.previous_digest !== previous
        || event.previousDigest !== previous || digest(canonical(core)) !== row.event_digest
        || event.eventDigest !== row.event_digest) throw storeError('connected_policy_audit_invalid');
    previous = row.event_digest;
  }
}

function enqueue(database, document, messageKind, now) {
  if (!['acknowledgement', 'validation_receipt'].includes(messageKind)
      || !document || typeof document !== 'object' || Array.isArray(document)
      || !/^[0-9a-f-]{36}$/i.test(String(document.messageId || ''))
      || !canonicalTime(now)) throw storeError('connected_policy_outbox_invalid');
  if (messageKind === 'acknowledgement') {
    protocol.assertChannel(document, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
  } else {
    validateValidationReceipt(document);
  }
  assertScope(document.customerId, document.deploymentId);
  const documentJson = canonical(document);
  const documentDigest = digest(documentJson);
  const scopeId = scopeDigest(document.customerId, document.deploymentId);
  const existing = database.prepare(`
    SELECT document_digest, status FROM connected_policy_outbox WHERE message_id = ?
  `).get(document.messageId);
  if (existing) {
    if (existing.document_digest !== documentDigest) throw storeError('connected_policy_outbox_conflict');
    return { replay: true, status: existing.status, documentDigest };
  }
  database.prepare(`
    INSERT INTO connected_policy_outbox
      (message_id, scope_id, message_kind, document_json, document_digest, status,
       attempts, next_attempt_at, last_error_code, created_at, delivered_at)
    VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, NULL, ?, NULL)
  `).run(document.messageId, scopeId, messageKind, documentJson, documentDigest, now, now);
  return { replay: false, status: 'pending', documentDigest };
}

function claimOutbox(database, limit, now) {
  const nowMs = Date.parse(now);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100
      || !canonicalTime(now) || !Number.isSafeInteger(nowMs)) {
    throw storeError('connected_policy_outbox_invalid');
  }
  const leaseExpiresAt = new Date(nowMs + OUTBOX_LEASE_MS).toISOString();
  database.exec('BEGIN IMMEDIATE');
  try {
    database.prepare(`
      UPDATE connected_policy_outbox SET
        status = CASE WHEN attempts >= ? THEN 'blocked' ELSE 'pending' END,
        claim_token = NULL
      WHERE status = 'sending' AND next_attempt_at <= ?
    `).run(MAX_OUTBOX_ATTEMPTS, now);
    const rows = database.prepare(`
      SELECT message_id, message_kind, document_json, document_digest, attempts
      FROM connected_policy_outbox
      WHERE status = 'pending' AND next_attempt_at <= ?
      ORDER BY created_at, message_id LIMIT ?
    `).all(now, limit);
    for (const row of rows) {
      row.claim_token = crypto.randomUUID();
      database.prepare(`
        UPDATE connected_policy_outbox SET status = 'sending', attempts = attempts + 1,
          next_attempt_at = ?, claim_token = ?
        WHERE message_id = ? AND status = 'pending'
      `).run(leaseExpiresAt, row.claim_token, row.message_id);
    }
    database.exec('COMMIT');
    return rows.map((row) => ({
      messageId: row.message_id,
      messageKind: row.message_kind,
      document: parseCanonical(row.document_json),
      documentDigest: row.document_digest,
      attempts: row.attempts + 1,
      claimToken: row.claim_token,
    }));
  } catch (error) {
    try { database.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

function validateValidationReceipt(value) {
  const keys = [
    'candidateDigest', 'customerId', 'deliveryDigest', 'deploymentId', 'kind',
    'lifecycleStage', 'messageId', 'outcome', 'recordedAt', 'schemaVersion',
    'targetDigest', 'targetVersion',
  ];
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== keys.sort().join(',')
      || value.schemaVersion !== 1 || value.kind !== 'policy.cached-validation-receipt.v1'
      || value.lifecycleStage !== 'cached' || value.outcome !== 'validated'
      || !UUID_RE.test(String(value.messageId || ''))
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !Number.isSafeInteger(value.targetVersion) || value.targetVersion < 1
      || ![value.targetDigest, value.deliveryDigest, value.candidateDigest]
        .every((item) => SHA256_RE.test(String(item || '')))
      || !canonicalTime(value.recordedAt)) {
    throw storeError('connected_policy_outbox_invalid');
  }
}

function assertScope(customerId, deploymentId) {
  if (typeof customerId !== 'string' || !CUSTOMER_ID_RE.test(customerId)
      || !isDeploymentId(deploymentId)) {
    throw storeError('connected_policy_scope_invalid');
  }
}

function createIntegrity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'keyId,secret'
      || !/^rw-policy-customer-integrity-[a-z0-9_.-]+$/.test(String(value.keyId || ''))
      || !Buffer.isBuffer(value.secret) || value.secret.length !== 32) {
    throw storeError('connected_policy_integrity_invalid');
  }
  return { keyId: value.keyId, secret: Buffer.from(value.secret) };
}

function mac(authority, domain, scopeId, revision, documentJson) {
  return crypto.createHmac('sha256', authority.secret)
    .update(`redactwall.connected-policy.${domain}.v1\0${authority.keyId}\0${scopeId}\0${revision}\0${documentJson}`)
    .digest('hex');
}

function verifyMac(authority, domain, scopeId, revision, documentJson, supplied) {
  const expected = Buffer.from(mac(authority, domain, scopeId, revision, documentJson), 'hex');
  const actual = Buffer.from(String(supplied || ''), 'hex');
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    throw storeError(`connected_policy_${domain}_invalid`);
  }
}

function scopeDigest(customerId, deploymentId) {
  return digest(canonical({ customerId, deploymentId }));
}

function canonical(value) {
  try { return protocol.canonicalJson(value); }
  catch { throw storeError('connected_policy_document_invalid'); }
}

function parseCanonical(value) {
  let parsed;
  try { parsed = JSON.parse(value); }
  catch { throw storeError('connected_policy_document_invalid'); }
  if (canonical(parsed) !== value) throw storeError('connected_policy_document_invalid');
  return parsed;
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalTime(value) {
  const parsed = Date.parse(value);
  return typeof value === 'string' && Number.isFinite(parsed)
    && new Date(parsed).toISOString() === value;
}

function assertOpen(closed) {
  if (closed) throw storeError('connected_policy_store_closed');
}

function workerError(code) {
  const error = new Error('connected policy delivery failed');
  error.code = code;
  return error;
}

function storeError(code) {
  const error = new Error('connected policy store rejected');
  error.code = code;
  return error;
}

module.exports = {
  CONNECTED_POLICY_SCHEMA_VERSION,
  CUSTOMER_POLICY_PACKAGE_BOUNDARY,
  MAX_OUTBOX_ATTEMPTS,
  OUTBOX_LEASE_MS,
  MIGRATION,
  createPolicyOutboxWorker,
  openConnectedPolicyStore,
};
