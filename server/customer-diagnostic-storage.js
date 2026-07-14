'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');

const ZERO = '0'.repeat(64);
const CHECKPOINT_ACTION = 'CUSTOMER_DIAGNOSTIC_CHECKPOINTED';
const CHECKPOINT_SCHEMA_VERSION = 1;

const ROW_COLUMNS = Object.freeze([
  ['customer_id', 'customerId'],
  ['deployment_id', 'deploymentId'],
  ['message_id', 'messageId'],
  ['payload_json', 'payloadJson'],
  ['payload_digest', 'payloadDigest'],
  ['status', 'status'],
  ['state_version', 'stateVersion'],
  ['attempts', 'attempts'],
  ['next_attempt_at', 'nextAttemptAt'],
  ['lease_id', 'leaseId'],
  ['lease_until', 'leaseUntil'],
  ['settled_lease_id', 'settledLeaseId'],
  ['created_at', 'createdAt'],
  ['updated_at', 'updatedAt'],
  ['retain_until', 'retainUntil'],
  ['last_audit_action', 'lastAuditAction'],
  ['last_audit_at', 'lastAuditAt'],
  ['state_key_id', 'stateKeyId'],
  ['state_mac', 'stateMac'],
  ['audit_key_id', 'auditKeyId'],
  ['audit_anchor', 'auditAnchor'],
]);
const TIME_COLUMNS = Object.freeze([
  ['customer_id', 'customerId'],
  ['deployment_id', 'deploymentId'],
  ['observed_at', 'observedAt'],
  ['state_key_id', 'stateKeyId'],
  ['state_mac', 'stateMac'],
]);
const AUDIT_COLUMNS = Object.freeze([
  'event_seq', 'customer_id', 'deployment_id', 'message_id', 'action',
  'occurred_at', 'event_json', 'audit_key_id', 'audit_anchor',
]);
const CHECKPOINT_COLUMNS = Object.freeze([
  ['customer_id', 'customerId'],
  ['deployment_id', 'deploymentId'],
  ['checkpoint_version', 'checkpointVersion'],
  ['local_audit_count', 'localAuditCount'],
  ['local_audit_seq', 'localAuditSeq'],
  ['local_audit_head', 'localAuditHead'],
  ['time_observed_at', 'timeObservedAt'],
  ['time_state_digest', 'timeStateDigest'],
  ['row_count', 'rowCount'],
  ['pending_count', 'pendingCount'],
  ['tombstone_count', 'tombstoneCount'],
  ['tombstone_head', 'tombstoneHead'],
  ['purge_count', 'purgeCount'],
  ['purge_seq', 'purgeSeq'],
  ['purge_head', 'purgeHead'],
  ['state_digest', 'stateDigest'],
  ['checkpoint_ref', 'checkpointRef'],
  ['checkpoint_digest', 'checkpointDigest'],
  ['main_audit_id', 'mainAuditId'],
  ['main_audit_hash', 'mainAuditHash'],
  ['updated_at', 'updatedAt'],
]);
const ROW_SELECT = ROW_COLUMNS.map(([column]) => column).join(', ');
const TIME_SELECT = TIME_COLUMNS.map(([column]) => column).join(', ');
const ROW_INSERT_COLUMNS = ROW_COLUMNS.map(([column]) => column).join(', ');
const ROW_INSERT_VALUES = ROW_COLUMNS.map(([, property]) => `@${property}`).join(', ');
const ROW_UPDATE = ROW_COLUMNS
  .filter(([column]) => !['customer_id', 'deployment_id', 'message_id'].includes(column))
  .map(([column, property]) => `${column} = @${property}`)
  .join(', ');
const CHECKPOINT_SELECT = CHECKPOINT_COLUMNS.map(([column]) => column).join(', ');
const CHECKPOINT_INSERT_COLUMNS = CHECKPOINT_COLUMNS.map(([column]) => column).join(', ');
const CHECKPOINT_INSERT_VALUES = CHECKPOINT_COLUMNS.map(([, property]) => `@${property}`).join(', ');
const CHECKPOINT_UPDATE = CHECKPOINT_COLUMNS
  .filter(([column]) => !['customer_id', 'deployment_id'].includes(column))
  .map(([column, property]) => `${column} = @${property}`)
  .join(', ');

function createCustomerDiagnosticStorage(input) {
  const options = checkedOptions(input);
  const { driver, driverKind } = options;
  const relations = relationSet(driverKind);
  const statements = prepareStatements(driver, relations);
  let schemaFingerprint = null;
  return Object.freeze({
    transaction(callback) {
      if (typeof callback !== 'function') throw storageError();
      verifyMainAudit(options.verifyMainAudit);
      schemaFingerprint = verifiedSchemaFingerprint(
        driver, driverKind, relations, schemaFingerprint,
      );
      const locked = new Set();
      const scopes = new Map();
      const tx = transactionApi(driver, statements, locked, scopes, options);
      return driver.transaction(() => {
        const result = callback(tx);
        if (thenable(result)) throw storageError();
        finalizeCheckpoints(statements, scopes, options);
        return result;
      })();
    },
  });
}

function prepareStatements(driver, relations) {
  return Object.freeze({
    readRow: driver.prepare(`SELECT ${ROW_SELECT}
      FROM ${relations.outbox}
      WHERE customer_id = ? AND deployment_id = ? AND message_id = ?`),
    countPending: driver.prepare(`SELECT CAST(COUNT(*) AS INTEGER) AS count
      FROM ${relations.outbox}
      WHERE customer_id = ? AND deployment_id = ? AND status IN ('pending', 'leased')`),
    countRecords: driver.prepare(`SELECT CAST(COUNT(*) AS INTEGER) AS count
      FROM ${relations.outbox}
      WHERE customer_id = ? AND deployment_id = ?`),
    insertRow: driver.prepare(`INSERT INTO ${relations.outbox} (${ROW_INSERT_COLUMNS})
      VALUES (${ROW_INSERT_VALUES})`),
    listReady: driver.prepare(`SELECT ${ROW_SELECT}
      FROM ${relations.outbox}
      WHERE customer_id = @customerId AND deployment_id = @deploymentId
        AND ((status = 'pending' AND next_attempt_at <= @now)
          OR (status = 'leased' AND lease_until <= @now))
      ORDER BY created_at, message_id
      LIMIT @limit`),
    updateRow: driver.prepare(`UPDATE ${relations.outbox} SET ${ROW_UPDATE}
      WHERE customer_id = @customerId AND deployment_id = @deploymentId
        AND message_id = @messageId
        AND state_mac = @expectedStateMac
        AND audit_anchor = @expectedAuditAnchor
        AND state_version = @expectedStateVersion`),
    listExpired: driver.prepare(`SELECT ${ROW_SELECT}
      FROM ${relations.outbox}
      WHERE customer_id = @customerId AND deployment_id = @deploymentId
        AND status IN ('delivered', 'expired', 'dead_letter')
        AND retain_until <= @before
      ORDER BY created_at, message_id
      LIMIT @limit`),
    deleteTombstone: driver.prepare(`DELETE FROM ${relations.outbox}
      WHERE customer_id = @customerId AND deployment_id = @deploymentId
        AND message_id = @messageId
        AND state_mac = @expectedStateMac
        AND audit_anchor = @expectedAuditAnchor
        AND state_version = @expectedStateVersion
        AND retain_until = @expectedRetainUntil`),
    insertAudit: driver.prepare(`INSERT INTO ${relations.audit}
      (customer_id, deployment_id, message_id, action, occurred_at,
        event_json, audit_key_id, audit_anchor)
      VALUES (@customerId, @deploymentId, @messageId, @action, @occurredAt,
        @eventJson, @auditKeyId, @auditAnchor)`),
    latestAudit: driver.prepare(`SELECT event_json
      FROM ${relations.audit}
      WHERE customer_id = ? AND deployment_id = ? AND message_id = ?
      ORDER BY event_seq DESC LIMIT 1`),
    readTime: driver.prepare(`SELECT ${TIME_SELECT}
      FROM ${relations.time}
      WHERE customer_id = ? AND deployment_id = ?`),
    insertTime: driver.prepare(`INSERT INTO ${relations.time}
      (customer_id, deployment_id, observed_at, state_key_id, state_mac)
      VALUES (@customerId, @deploymentId, @observedAt, @stateKeyId, @stateMac)
      ON CONFLICT (customer_id, deployment_id) DO NOTHING`),
    updateTime: driver.prepare(`UPDATE ${relations.time}
      SET observed_at = @observedAt, state_key_id = @stateKeyId, state_mac = @stateMac
      WHERE customer_id = @customerId AND deployment_id = @deploymentId
        AND observed_at = @expectedObservedAt AND state_mac = @expectedStateMac`),
    snapshotRows: driver.prepare(`SELECT ${ROW_SELECT}
      FROM ${relations.outbox}
      WHERE customer_id = ? AND deployment_id = ?
      ORDER BY message_id`),
    snapshotTime: driver.prepare(`SELECT ${TIME_SELECT}
      FROM ${relations.time}
      WHERE customer_id = ? AND deployment_id = ?`),
    snapshotAudit: driver.prepare(`SELECT ${AUDIT_COLUMNS.join(', ')}
      FROM ${relations.audit}
      WHERE customer_id = ? AND deployment_id = ?
      ORDER BY event_seq`),
    readCheckpoint: driver.prepare(`SELECT ${CHECKPOINT_SELECT}
      FROM ${relations.checkpoint}
      WHERE customer_id = ? AND deployment_id = ?`),
    insertCheckpoint: driver.prepare(`INSERT INTO ${relations.checkpoint}
      (${CHECKPOINT_INSERT_COLUMNS}) VALUES (${CHECKPOINT_INSERT_VALUES})`),
    updateCheckpoint: driver.prepare(`UPDATE ${relations.checkpoint}
      SET ${CHECKPOINT_UPDATE}
      WHERE customer_id = @customerId AND deployment_id = @deploymentId
        AND checkpoint_version = @expectedCheckpointVersion
        AND checkpoint_digest = @expectedCheckpointDigest
        AND main_audit_hash = @expectedMainAuditHash`),
  });
}

function transactionApi(driver, statements, locked, scopes, options) {
  const lock = (value) => {
    const scope = lockScope(driver, locked, value);
    ensureCheckpoint(statements, scopes, options, scope);
  };
  return Object.freeze({
    readDiagnostic(query) {
      lock(query);
      return rowFromDatabase(statements.readRow.get(
        query.customerId, query.deploymentId, query.messageId,
      ));
    },
    countPendingDiagnostics(query) {
      lock(query);
      return count(statements.countPending.get(query.customerId, query.deploymentId));
    },
    countDiagnosticRecords(query) {
      lock(query);
      return count(statements.countRecords.get(query.customerId, query.deploymentId));
    },
    insertDiagnostic(row) {
      lock(row);
      if (statements.insertRow.run(rowParameters(row)).changes !== 1) throw storageError();
      return rowFromDatabase(statements.readRow.get(row.customerId, row.deploymentId, row.messageId));
    },
    listReadyDiagnostics(query) {
      lock(query);
      return statements.listReady.all(query).map(rowFromDatabase);
    },
    compareAndSwapDiagnostic(input) {
      lock(input);
      const parameters = {
        ...rowParameters(input.nextRow),
        customerId: input.customerId,
        deploymentId: input.deploymentId,
        messageId: input.messageId,
        expectedStateMac: input.expectedStateMac,
        expectedAuditAnchor: input.expectedAuditAnchor,
        expectedStateVersion: input.expectedStateVersion,
      };
      if (statements.updateRow.run(parameters).changes !== 1) return null;
      return rowFromDatabase(statements.readRow.get(
        input.customerId, input.deploymentId, input.messageId,
      ));
    },
    listExpiredDiagnosticTombstones(query) {
      lock(query);
      return statements.listExpired.all(query).map(rowFromDatabase);
    },
    deleteDiagnosticTombstone(input) {
      lock(input);
      const current = rowFromDatabase(statements.readRow.get(
        input.customerId, input.deploymentId, input.messageId,
      ));
      if (!current || current.stateMac !== input.expectedStateMac
          || current.auditAnchor !== input.expectedAuditAnchor
          || current.stateVersion !== input.expectedStateVersion
          || current.retainUntil !== input.expectedRetainUntil) return null;
      if (statements.deleteTombstone.run(input).changes !== 1) return null;
      return current;
    },
    appendDiagnosticAudit(event) {
      lock(event);
      const eventJson = protocol.canonicalJson(event);
      const accepted = JSON.parse(eventJson);
      if (statements.insertAudit.run({
        customerId: event.customerId,
        deploymentId: event.deploymentId,
        messageId: event.messageId || null,
        action: event.action,
        occurredAt: event.occurredAt,
        eventJson,
        auditKeyId: event.auditKeyId,
        auditAnchor: event.auditAnchor,
      }).changes !== 1) throw storageError();
      return accepted;
    },
    readDiagnosticTimeHighWater(query) {
      lock(query);
      return timeFromDatabase(statements.readTime.get(query.customerId, query.deploymentId));
    },
    readLatestDiagnosticAudit(query) {
      lock(query);
      const row = statements.latestAudit.get(
        query.customerId, query.deploymentId, query.messageId,
      );
      return row ? JSON.parse(row.event_json) : null;
    },
    advanceDiagnosticTimeHighWater(input) {
      lock(input);
      const next = input.nextRecord;
      const changed = input.expectedStateMac === null && input.expectedObservedAt === null
        ? statements.insertTime.run(next).changes
        : statements.updateTime.run({
          ...next,
          expectedStateMac: input.expectedStateMac,
          expectedObservedAt: input.expectedObservedAt,
        }).changes;
      if (changed !== 1) return null;
      return timeFromDatabase(statements.readTime.get(input.customerId, input.deploymentId));
    },
  });
}

function ensureCheckpoint(statements, scopes, options, scope) {
  if (scopes.has(scope.key)) return;
  const checkpointRef = callbackValue(
    options.checkpointReference,
    { customerId: scope.customerId, deploymentId: scope.deploymentId },
  );
  if (!validCheckpointReference(checkpointRef)) throw storageError();
  const checkpoint = checkpointFromDatabase(statements.readCheckpoint.get(
    scope.customerId, scope.deploymentId,
  ));
  const latest = callbackValue(options.loadMainAuditCheckpoint, {
    checkpointRef,
    customerId: scope.customerId,
    deploymentId: scope.deploymentId,
  });
  const before = scopeSnapshot(statements, scope);
  if (!checkpoint) {
    if (latest !== null && latest !== undefined) throw storageError();
    if (!emptySnapshot(before)) throw storageError();
  } else {
    verifyStoredCheckpoint(checkpoint, checkpointRef, before);
    const latestEntry = verifyCheckpointAuditEntry(options, latest, checkpoint);
    verifyStoredMainAuditBinding(checkpoint, latestEntry);
  }
  scopes.set(scope.key, Object.freeze({ ...scope, checkpointRef, checkpoint, before }));
}

function finalizeCheckpoints(statements, scopes, options) {
  for (const scope of scopes.values()) {
    const after = scopeSnapshot(statements, scope);
    if (protocol.canonicalJson(after) === protocol.canonicalJson(scope.before)) continue;
    writeCheckpoint(statements, options, scope, after);
  }
}

function writeCheckpoint(statements, options, scope, snapshot) {
  const checkpointVersion = scope.checkpoint ? scope.checkpoint.checkpointVersion + 1 : 1;
  const core = checkpointCore(scope, checkpointVersion, snapshot);
  const checkpointDigest = digest(core);
  const detail = protocol.canonicalJson({
    schemaVersion: CHECKPOINT_SCHEMA_VERSION,
    checkpointVersion,
    checkpointDigest,
  });
  const event = Object.freeze({
    action: CHECKPOINT_ACTION,
    actor: 'system',
    detail,
    diagnosticCheckpointRef: scope.checkpointRef,
  });
  const entry = callbackValue(options.appendMainAudit, event);
  const expected = { checkpointVersion, checkpointDigest, checkpointRef: scope.checkpointRef };
  const appendedEntry = verifyCheckpointAuditEntry(options, entry, expected);
  const latest = callbackValue(options.loadMainAuditCheckpoint, {
    checkpointRef: scope.checkpointRef,
    customerId: scope.customerId,
    deploymentId: scope.deploymentId,
  });
  const latestEntry = verifyCheckpointAuditEntry(options, latest, expected);
  if (latestEntry.id !== appendedEntry.id || latestEntry.hash !== appendedEntry.hash
      || latestEntry.ts !== appendedEntry.ts) throw storageError();
  const next = checkpointRecord(core, checkpointDigest, appendedEntry);
  const changed = scope.checkpoint
    ? statements.updateCheckpoint.run({
      ...next,
      expectedCheckpointVersion: scope.checkpoint.checkpointVersion,
      expectedCheckpointDigest: scope.checkpoint.checkpointDigest,
      expectedMainAuditHash: scope.checkpoint.mainAuditHash,
    }).changes
    : statements.insertCheckpoint.run(next).changes;
  if (changed !== 1) throw storageError();
  const stored = checkpointFromDatabase(statements.readCheckpoint.get(
    scope.customerId, scope.deploymentId,
  ));
  if (!stored || protocol.canonicalJson(stored) !== protocol.canonicalJson(next)) {
    throw storageError();
  }
}

function checkpointCore(scope, checkpointVersion, snapshot) {
  return Object.freeze({
    schemaVersion: CHECKPOINT_SCHEMA_VERSION,
    customerId: scope.customerId,
    deploymentId: scope.deploymentId,
    checkpointVersion,
    ...snapshot,
    checkpointRef: scope.checkpointRef,
  });
}

function checkpointRecord(core, checkpointDigest, entry) {
  const { schemaVersion, ...stored } = core;
  if (schemaVersion !== CHECKPOINT_SCHEMA_VERSION) throw storageError();
  return Object.freeze({
    ...stored,
    checkpointDigest,
    mainAuditId: entry.id,
    mainAuditHash: entry.hash,
    updatedAt: entry.ts,
  });
}

function checkpointFromDatabase(row) {
  if (!row) return null;
  return mappedRecord(row, CHECKPOINT_COLUMNS);
}

function verifyStoredCheckpoint(checkpoint, checkpointRef, snapshot) {
  if (!validCheckpointRecord(checkpoint) || checkpoint.checkpointRef !== checkpointRef) {
    throw storageError();
  }
  const scope = {
    customerId: checkpoint.customerId,
    deploymentId: checkpoint.deploymentId,
    checkpointRef,
  };
  const core = checkpointCore(scope, checkpoint.checkpointVersion, snapshotFromCheckpoint(checkpoint));
  if (digest(core) !== checkpoint.checkpointDigest
      || protocol.canonicalJson(snapshotFromCheckpoint(checkpoint)) !== protocol.canonicalJson(snapshot)) {
    throw storageError();
  }
}

function verifyStoredMainAuditBinding(checkpoint, latestEntry) {
  if (latestEntry.id !== checkpoint.mainAuditId
      || latestEntry.hash !== checkpoint.mainAuditHash
      || latestEntry.ts !== checkpoint.updatedAt) throw storageError();
}

function snapshotFromCheckpoint(checkpoint) {
  return Object.freeze({
    localAuditCount: checkpoint.localAuditCount,
    localAuditSeq: checkpoint.localAuditSeq,
    localAuditHead: checkpoint.localAuditHead,
    timeObservedAt: checkpoint.timeObservedAt,
    timeStateDigest: checkpoint.timeStateDigest,
    rowCount: checkpoint.rowCount,
    pendingCount: checkpoint.pendingCount,
    tombstoneCount: checkpoint.tombstoneCount,
    tombstoneHead: checkpoint.tombstoneHead,
    purgeCount: checkpoint.purgeCount,
    purgeSeq: checkpoint.purgeSeq,
    purgeHead: checkpoint.purgeHead,
    stateDigest: checkpoint.stateDigest,
  });
}

function validCheckpointRecord(value) {
  if (!plainRecord(value)
      || typeof value.customerId !== 'string'
      || typeof value.deploymentId !== 'string'
      || !positiveInteger(value.checkpointVersion)
      || !nonnegativeInteger(value.localAuditCount)
      || !nonnegativeInteger(value.localAuditSeq)
      || !nonnegativeInteger(value.rowCount)
      || !nonnegativeInteger(value.pendingCount)
      || !nonnegativeInteger(value.tombstoneCount)
      || !nonnegativeInteger(value.purgeCount)
      || !nonnegativeInteger(value.purgeSeq)
      || value.pendingCount + value.tombstoneCount !== value.rowCount
      || value.purgeCount > value.localAuditCount
      || !validDigest(value.localAuditHead)
      || !validDigest(value.timeStateDigest)
      || !validDigest(value.tombstoneHead)
      || !validDigest(value.purgeHead)
      || !validDigest(value.stateDigest)
      || !validDigest(value.checkpointDigest)
      || !validDigest(value.mainAuditHash)
      || !validCheckpointReference(value.checkpointRef)
      || !validOpaqueId(value.mainAuditId)
      || !validIso(value.updatedAt)
      || (value.timeObservedAt !== null && !validIso(value.timeObservedAt))) return false;
  if (value.localAuditSeq < value.localAuditCount || value.purgeSeq > value.localAuditSeq) {
    return false;
  }
  if ((value.localAuditCount === 0) !== (value.localAuditSeq === 0 && value.localAuditHead === ZERO)) {
    return false;
  }
  if ((value.purgeCount === 0) !== (value.purgeSeq === 0 && value.purgeHead === ZERO)) return false;
  if ((value.tombstoneCount === 0) !== (value.tombstoneHead === ZERO)) return false;
  return true;
}

function verifyCheckpointAuditEntry(options, value, checkpoint) {
  const entry = plainSnapshot(value);
  const detail = protocol.canonicalJson({
    schemaVersion: CHECKPOINT_SCHEMA_VERSION,
    checkpointVersion: checkpoint.checkpointVersion,
    checkpointDigest: checkpoint.checkpointDigest,
  });
  let authenticated = false;
  try { authenticated = options.verifyMainAuditEntry(entry) === true; } catch {}
  if (!authenticated || !validOpaqueId(entry.id) || !validIso(entry.ts)
      || !validDigest(entry.hash) || !validDigest(entry.prevHash)
      || entry.action !== CHECKPOINT_ACTION || entry.actor !== 'system'
      || entry.queryId !== '' || entry.detail !== detail
      || entry.diagnosticCheckpointRef !== checkpoint.checkpointRef) {
    throw storageError();
  }
  return entry;
}

function scopeSnapshot(statements, scope) {
  const rows = statements.snapshotRows.all(scope.customerId, scope.deploymentId)
    .map(rowFromDatabase);
  const time = timeFromDatabase(statements.snapshotTime.get(
    scope.customerId, scope.deploymentId,
  ));
  const auditRows = statements.snapshotAudit.all(scope.customerId, scope.deploymentId);
  return buildSnapshot(rows, time, auditRows);
}

function buildSnapshot(rows, time, auditRows) {
  if (!Array.isArray(rows) || !Array.isArray(auditRows)) throw storageError();
  let rowHead = ZERO;
  let tombstoneHead = ZERO;
  let pendingCount = 0;
  let tombstoneCount = 0;
  for (const row of rows) {
    if (!plainRecord(row)) throw storageError();
    rowHead = foldDigest('redactwall.customer-diagnostic-state-row.v1', rowHead, row);
    if (row.status === 'pending' || row.status === 'leased') pendingCount += 1;
    else if (['delivered', 'expired', 'dead_letter'].includes(row.status)) {
      tombstoneCount += 1;
      tombstoneHead = foldDigest(
        'redactwall.customer-diagnostic-tombstone.v1', tombstoneHead, row,
      );
    } else throw storageError();
  }
  const audit = auditSnapshot(auditRows);
  const timeStateDigest = digest({
    domain: 'redactwall.customer-diagnostic-time-snapshot.v1',
    value: time,
  });
  const stateDigest = digest({
    domain: 'redactwall.customer-diagnostic-state-snapshot.v1',
    rowHead,
    timeStateDigest,
    localAuditCount: audit.localAuditCount,
    localAuditSeq: audit.localAuditSeq,
    localAuditHead: audit.localAuditHead,
    purgeCount: audit.purgeCount,
    purgeSeq: audit.purgeSeq,
    purgeHead: audit.purgeHead,
    tombstoneCount,
    tombstoneHead,
  });
  return Object.freeze({
    ...audit,
    timeObservedAt: time ? time.observedAt : null,
    timeStateDigest,
    rowCount: rows.length,
    pendingCount,
    tombstoneCount,
    tombstoneHead,
    stateDigest,
  });
}

function auditSnapshot(rows) {
  let localAuditHead = ZERO;
  let localAuditSeq = 0;
  let purgeHead = ZERO;
  let purgeSeq = 0;
  let purgeCount = 0;
  for (const row of rows) {
    const eventSeq = Number(row && row.event_seq);
    if (!Number.isSafeInteger(eventSeq) || eventSeq <= localAuditSeq
        || typeof row.event_json !== 'string') throw storageError();
    const value = {};
    for (const column of AUDIT_COLUMNS) value[column] = row[column] ?? null;
    localAuditHead = foldDigest(
      'redactwall.customer-diagnostic-local-audit.v1', localAuditHead, value,
    );
    localAuditSeq = eventSeq;
    if (row.action === 'DIAGNOSTIC_TOMBSTONE_PURGED') {
      purgeHead = foldDigest(
        'redactwall.customer-diagnostic-purge.v1', purgeHead, value,
      );
      purgeSeq = eventSeq;
      purgeCount += 1;
    }
  }
  return Object.freeze({
    localAuditCount: rows.length,
    localAuditSeq,
    localAuditHead,
    purgeCount,
    purgeSeq,
    purgeHead,
  });
}

function emptySnapshot(value) {
  return value.rowCount === 0 && value.localAuditCount === 0 && value.timeObservedAt === null;
}

function foldDigest(domain, previous, value) {
  return digest({ domain, previous, value });
}

function digest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function lockScope(driver, locked, value) {
  const customerId = value && value.customerId;
  const deploymentId = value && value.deploymentId;
  if (typeof customerId !== 'string' || typeof deploymentId !== 'string') throw storageError();
  const scope = `${customerId}\0${deploymentId}`;
  if (locked.has(scope)) return { key: scope, customerId, deploymentId };
  if (locked.size > 0) throw storageError();
  if (typeof driver.lockRowForUpdate === 'function') {
    driver.lockRowForUpdate(`customer-diagnostic:${scope}`);
  }
  locked.add(scope);
  return { key: scope, customerId, deploymentId };
}

function rowParameters(row) {
  const record = {};
  for (const [, property] of ROW_COLUMNS) record[property] = row[property];
  return record;
}

function rowFromDatabase(row) {
  if (!row) return null;
  return mappedRecord(row, ROW_COLUMNS);
}

function timeFromDatabase(row) {
  if (!row) return null;
  return mappedRecord(row, TIME_COLUMNS);
}

function mappedRecord(row, columns) {
  const record = {};
  for (const [column, property] of columns) record[property] = row[column];
  return record;
}

function count(row) {
  const value = row && row.count;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw storageError();
  }
  return value;
}

function verifyMainAudit(callback) {
  const result = callbackValue(callback);
  if (result === true) return;
  if (!plainRecord(result) || result.ok !== true) throw storageError();
}

function callbackValue(callback, input) {
  try {
    const value = input === undefined ? callback() : callback(input);
    if (thenable(value)) throw storageError();
    return value;
  } catch (error) {
    if (error && error.code === 'CUSTOMER_DIAGNOSTIC_STORAGE_FAILED') throw error;
    throw storageError();
  }
}

function verifiedSchemaFingerprint(driver, driverKind, relations, previous) {
  let current;
  try {
    current = driverKind === 'sqlite'
      ? sqliteSchemaFingerprint(driver, relations)
      : postgresSchemaFingerprint(driver, relations);
  } catch (error) {
    if (error && error.code === 'CUSTOMER_DIAGNOSTIC_STORAGE_FAILED') throw error;
    throw storageError();
  }
  if (previous !== null && current !== previous) throw storageError();
  return current;
}

function sqliteSchemaFingerprint(driver) {
  const tableNames = schemaTableNames();
  const placeholders = tableNames.map(() => '?').join(', ');
  const objects = driver.prepare(`SELECT type, name, tbl_name, sql
    FROM main.sqlite_master
    WHERE tbl_name IN (${placeholders}) OR name IN (${placeholders})
    ORDER BY type, name`).all(...tableNames, ...tableNames);
  const tables = objects.filter(({ type }) => type === 'table');
  if (protocol.canonicalJson(tables.map(({ name }) => name))
      !== protocol.canonicalJson([...tableNames].sort())) throw storageError();
  const triggers = objects.filter(({ type }) => type === 'trigger');
  if (protocol.canonicalJson(triggers.map(({ name }) => name).sort()) !== protocol.canonicalJson([
    'customer_diagnostic_audit_no_delete',
    'customer_diagnostic_audit_no_update',
  ])) throw storageError();
  for (const trigger of triggers) validateSqliteAuditTrigger(trigger);
  const indexes = new Set(objects.filter(({ type }) => type === 'index').map(({ name }) => name));
  for (const name of [
    'idx_customer_diagnostic_audit_message',
    'idx_customer_diagnostic_ready',
    'idx_customer_diagnostic_tombstone',
  ]) if (!indexes.has(name)) throw storageError();
  const columns = {};
  for (const [table, expected] of Object.entries(schemaColumns())) {
    const rows = driver.prepare(`PRAGMA main.table_xinfo('${table}')`).all();
    columns[table] = rows.map(({ name, type, notnull, pk, hidden }) => ({
      name, type: String(type || '').toUpperCase(), notnull, pk, hidden,
    }));
    if (protocol.canonicalJson(rows.map(({ name }) => name))
        !== protocol.canonicalJson(expected)) throw storageError();
    if (rows.some(({ type, hidden }) => !['TEXT', 'INTEGER'].includes(String(type).toUpperCase())
        || Number(hidden || 0) !== 0)) throw storageError();
  }
  validateSqliteTableSql(tables);
  return digest({ objects, columns });
}

function validateSqliteAuditTrigger(trigger) {
  const sql = normalizedSql(trigger.sql);
  const operation = trigger.name.endsWith('_no_update') ? 'UPDATE' : 'DELETE';
  if (trigger.tbl_name !== 'customer_diagnostic_audit'
      || !sql.includes(`BEFORE ${operation} ON CUSTOMER_DIAGNOSTIC_AUDIT`)
      || !sql.includes('CUSTOMER DIAGNOSTIC AUDIT IS APPEND-ONLY')) throw storageError();
}

function validateSqliteTableSql(tables) {
  const byName = new Map(tables.map((row) => [row.name, normalizedSql(row.sql)]));
  if (!byName.get('customer_diagnostic_outbox')?.includes('PRIMARY KEY (CUSTOMER_ID, DEPLOYMENT_ID, MESSAGE_ID)')
      || !byName.get('customer_diagnostic_outbox')?.includes("'PENDING', 'LEASED', 'DELIVERED', 'EXPIRED', 'DEAD_LETTER'")
      || !byName.get('customer_diagnostic_time_high_water')?.includes('PRIMARY KEY (CUSTOMER_ID, DEPLOYMENT_ID)')
      || !byName.get('customer_diagnostic_audit')?.includes('EVENT_SEQ INTEGER PRIMARY KEY AUTOINCREMENT')
      || !byName.get('customer_diagnostic_checkpoint')?.includes('CHECKPOINT_REF TEXT NOT NULL UNIQUE')
      || !byName.get('customer_diagnostic_checkpoint')?.includes('PRIMARY KEY (CUSTOMER_ID, DEPLOYMENT_ID)')) {
    throw storageError();
  }
}

function postgresSchemaFingerprint(driver) {
  const tables = driver.prepare(`SELECT c.relname AS name,
      c.relrowsecurity AS row_security, c.relforcerowsecurity AS force_row_security
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
      AND c.relname IN ('customer_diagnostic_outbox',
        'customer_diagnostic_time_high_water', 'customer_diagnostic_audit',
        'customer_diagnostic_checkpoint')
    ORDER BY c.relname`).all();
  if (protocol.canonicalJson(tables.map(({ name }) => name))
      !== protocol.canonicalJson([...schemaTableNames()].sort())
      || tables.some((row) => row.row_security !== true || row.force_row_security !== true)) {
    throw storageError();
  }
  const columns = driver.prepare(`SELECT table_name, column_name, data_type, ordinal_position
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name IN ('customer_diagnostic_outbox',
      'customer_diagnostic_time_high_water', 'customer_diagnostic_audit',
      'customer_diagnostic_checkpoint')
    ORDER BY table_name, ordinal_position`).all();
  validatePostgresColumns(columns);
  const triggers = driver.prepare(`SELECT c.relname AS table_name, t.tgname AS name,
      pg_catalog.pg_get_triggerdef(t.oid) AS definition
    FROM pg_catalog.pg_trigger t
    JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND NOT t.tgisinternal
      AND c.relname IN ('customer_diagnostic_outbox',
        'customer_diagnostic_time_high_water', 'customer_diagnostic_audit',
        'customer_diagnostic_checkpoint')
    ORDER BY c.relname, t.tgname`).all();
  validatePostgresTriggers(triggers);
  const functions = driver.prepare(`SELECT p.proname AS name,
      pg_catalog.pg_get_functiondef(p.oid) AS definition
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname = 'reject_customer_diagnostic_audit_mutation'
    ORDER BY p.oid`).all();
  validatePostgresGuardFunction(functions);
  const policies = driver.prepare(`SELECT c.relname AS table_name, p.polname AS name,
      pg_catalog.pg_get_expr(p.polqual, p.polrelid) AS using_expression,
      pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) AS check_expression
    FROM pg_catalog.pg_policy p
    JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname IN ('customer_diagnostic_outbox',
      'customer_diagnostic_time_high_water', 'customer_diagnostic_audit',
      'customer_diagnostic_checkpoint')
    ORDER BY c.relname, p.polname`).all();
  validatePostgresPolicies(policies);
  return digest({ tables, columns, triggers, functions, policies });
}

function validatePostgresColumns(rows) {
  const grouped = new Map();
  for (const row of rows) {
    if (!grouped.has(row.table_name)) grouped.set(row.table_name, []);
    grouped.get(row.table_name).push(row.column_name);
  }
  for (const [table, expected] of Object.entries(schemaColumns())) {
    if (protocol.canonicalJson(grouped.get(table)) !== protocol.canonicalJson(expected)) {
      throw storageError();
    }
  }
}

function validatePostgresTriggers(rows) {
  if (rows.length !== 2) throw storageError();
  const names = rows.map(({ name }) => name).sort();
  if (protocol.canonicalJson(names) !== protocol.canonicalJson([
    'customer_diagnostic_audit_no_delete',
    'customer_diagnostic_audit_no_update',
  ])) throw storageError();
  for (const row of rows) {
    const operation = row.name.endsWith('_no_update') ? 'UPDATE' : 'DELETE';
    const definition = normalizedSql(row.definition);
    if (row.table_name !== 'customer_diagnostic_audit'
        || !definition.includes(`BEFORE ${operation} ON PUBLIC.CUSTOMER_DIAGNOSTIC_AUDIT`)
        || !definition.includes('PUBLIC.REJECT_CUSTOMER_DIAGNOSTIC_AUDIT_MUTATION')) {
      throw storageError();
    }
  }
}

function validatePostgresGuardFunction(rows) {
  if (rows.length !== 1 || rows[0].name !== 'reject_customer_diagnostic_audit_mutation') {
    throw storageError();
  }
  const definition = normalizedSql(rows[0].definition);
  if (!definition.includes('SET SEARCH_PATH TO \'PG_CATALOG\'')
      && !definition.includes('SET SEARCH_PATH TO PG_CATALOG')) throw storageError();
  if (!definition.includes("MESSAGE = 'CUSTOMER DIAGNOSTIC AUDIT IS APPEND-ONLY'")
      || !definition.includes("ERRCODE = '55000'")) throw storageError();
}

function validatePostgresPolicies(rows) {
  const expectedTables = [...schemaTableNames()].sort();
  if (rows.length !== expectedTables.length
      || protocol.canonicalJson(rows.map(({ table_name: table }) => table).sort())
        !== protocol.canonicalJson(expectedTables)) throw storageError();
  const expectedNames = {
    customer_diagnostic_outbox: 'customer_diagnostic_outbox_tenant_isolation',
    customer_diagnostic_time_high_water: 'customer_diagnostic_time_tenant_isolation',
    customer_diagnostic_audit: 'customer_diagnostic_audit_tenant_isolation',
    customer_diagnostic_checkpoint: 'customer_diagnostic_checkpoint_tenant_isolation',
  };
  for (const row of rows) {
    const using = normalizedSql(row.using_expression);
    const check = normalizedSql(row.check_expression);
    if (row.name !== expectedNames[row.table_name] || using !== check
        || !using.includes("COALESCE(CURRENT_SETTING('REDACTWALL.ORG_ID'::TEXT, TRUE)")
        || !using.includes("CUSTOMER_ID = CURRENT_SETTING('REDACTWALL.ORG_ID'::TEXT, TRUE)")
        || /\bOR\b/.test(using)) throw storageError();
  }
}

function schemaTableNames() {
  return [
    'customer_diagnostic_audit',
    'customer_diagnostic_checkpoint',
    'customer_diagnostic_outbox',
    'customer_diagnostic_time_high_water',
  ];
}

function schemaColumns() {
  return {
    customer_diagnostic_outbox: ROW_COLUMNS.map(([column]) => column),
    customer_diagnostic_time_high_water: TIME_COLUMNS.map(([column]) => column),
    customer_diagnostic_audit: AUDIT_COLUMNS,
    customer_diagnostic_checkpoint: CHECKPOINT_COLUMNS.map(([column]) => column),
  };
}

function normalizedSql(value) {
  return String(value || '').replace(/\s+/g, ' ').trim().toUpperCase();
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function plainSnapshot(value) {
  if (!plainRecord(value)) throw storageError();
  const record = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw storageError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || descriptor.get || descriptor.set) {
      throw storageError();
    }
    record[key] = descriptor.value;
  }
  return record;
}

function thenable(value) {
  return Boolean(value && (typeof value === 'object' || typeof value === 'function')
    && typeof value.then === 'function');
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function nonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function validDigest(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function validCheckpointReference(value) {
  return typeof value === 'string'
    && /^diagnostic_checkpoint_[A-Za-z0-9_-]{16,96}$/.test(value);
}

function validOpaqueId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{2,128}$/.test(value);
}

function validIso(value) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function checkedDriver(driver) {
  if (!driver || typeof driver.prepare !== 'function' || typeof driver.transaction !== 'function') {
    throw storageError();
  }
}

function checkedOptions(input) {
  const options = plainSnapshot(input);
  const allowed = new Set([
    'appendMainAudit', 'checkpointReference', 'driver', 'driverKind',
    'loadMainAuditCheckpoint', 'verifyMainAudit', 'verifyMainAuditEntry',
  ]);
  if (Object.keys(options).some((name) => !allowed.has(name)) || !options.driver
      || !['sqlite', 'postgres'].includes(options.driverKind)) throw storageError();
  const { driver } = options;
  checkedDriver(driver);
  const detectedKind = trustedDriverKind(driver);
  if (options.driverKind !== detectedKind) throw storageError();
  for (const name of [
    'appendMainAudit', 'checkpointReference', 'loadMainAuditCheckpoint',
    'verifyMainAudit', 'verifyMainAuditEntry',
  ]) {
    if (typeof options[name] !== 'function') throw storageError();
  }
  return Object.freeze({ ...options, driver, driverKind: detectedKind });
}

function trustedDriverKind(driver) {
  try {
    if (driver.kind === 'postgres') {
      const row = driver.prepare("SELECT pg_catalog.current_setting('server_version_num') AS version").get();
      if (!row || !/^\d{5,6}$/.test(String(row.version || ''))) throw storageError();
      return 'postgres';
    }
    if (driver.kind !== undefined && driver.kind !== 'sqlite') throw storageError();
    const row = driver.prepare('SELECT sqlite_version() AS version').get();
    const schema = driver.prepare('PRAGMA main.schema_version').get();
    if (!row || !/^\d+\.\d+\.\d+$/.test(String(row.version || ''))
        || !schema || !Number.isSafeInteger(schema.schema_version)) throw storageError();
    return 'sqlite';
  } catch (error) {
    if (error && error.code === 'CUSTOMER_DIAGNOSTIC_STORAGE_FAILED') throw error;
    throw storageError();
  }
}

function relationSet(driverKind) {
  if (driverKind === 'sqlite') {
    return Object.freeze({
      outbox: 'main.customer_diagnostic_outbox',
      time: 'main.customer_diagnostic_time_high_water',
      audit: 'main.customer_diagnostic_audit',
      checkpoint: 'main.customer_diagnostic_checkpoint',
    });
  }
  if (driverKind === 'postgres') {
    return Object.freeze({
      outbox: 'public.customer_diagnostic_outbox',
      time: 'public.customer_diagnostic_time_high_water',
      audit: 'public.customer_diagnostic_audit',
      checkpoint: 'public.customer_diagnostic_checkpoint',
    });
  }
  throw storageError();
}

function storageError() {
  const error = new Error('customer diagnostic storage operation failed');
  error.code = 'CUSTOMER_DIAGNOSTIC_STORAGE_FAILED';
  return error;
}

module.exports = { createCustomerDiagnosticStorage };
