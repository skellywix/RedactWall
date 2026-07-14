'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const fileMutationLock = require('../../server/file-mutation-lock');
const privatePaths = require('../../server/private-path');
const protocol = require('../../server/vendor-control-protocol');
const {
  STORAGE_CONTRACT_VERSION,
} = require('../../server/vendor-diagnostic-intelligence');

function canonical(value) {
  return protocol.canonicalJson(value);
}

function digest(value) {
  return crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex');
}

function hmacAuthority(label, options = {}) {
  const keyId = options.keyId || `${label}-key`;
  const key = options.key || crypto.createHash('sha256').update(`test authority:${label}`).digest();
  const fingerprint = options.fingerprint
    || crypto.createHash('sha256').update(key).digest('hex');
  return {
    keyId,
    fingerprint,
    sign(domain, message) {
      return {
        keyId,
        mac: crypto.createHmac('sha256', key)
          .update(domain, 'utf8').update('\0').update(message, 'utf8').digest('base64'),
      };
    },
    verify(domain, message, proof) {
      if (!proof || proof.keyId !== keyId || typeof proof.mac !== 'string') return false;
      const expected = crypto.createHmac('sha256', key)
        .update(domain, 'utf8').update('\0').update(message, 'utf8').digest();
      let actual;
      try { actual = Buffer.from(proof.mac, 'base64'); } catch { return false; }
      return actual.length === expected.length && crypto.timingSafeEqual(actual, expected)
        && actual.toString('base64') === proof.mac;
    },
  };
}

function authenticate(authority, domain, core) {
  return deepFreeze({
    ...structuredClone(core),
    recordDigest: digest(core),
    integrityProof: authority.sign(domain, canonical(core)),
  });
}

class ReferenceDiagnosticWitness {
  constructor(options = {}) {
    this.assurance = options.assurance || 'test_reference_only';
    this.records = new Map();
    this.hooks = options.hooks || {};
  }

  read(namespace) {
    if (this.hooks.read) return this.hooks.read(namespace, () => this.readRecord(namespace));
    return this.readRecord(namespace);
  }

  readRecord(namespace) {
    const value = this.records.get(namespace);
    return value ? structuredClone(value) : null;
  }

  compareAndSwap(command) {
    const run = () => {
      const current = this.records.get(command.namespace) || null;
      if ((current ? current.recordDigest : null) !== command.expectedRecordDigest) return null;
      this.records.set(command.namespace, structuredClone(command.nextRecord));
      return structuredClone(command.nextRecord);
    };
    return this.hooks.compareAndSwap ? this.hooks.compareAndSwap(command, run) : run();
  }
}

class FileDiagnosticWitness {
  constructor(directory) {
    this.assurance = 'test_reference_only';
    this.directory = path.resolve(directory);
    this.lockPath = path.join(this.directory, 'witness-cas');
    privatePaths.withPrivateDirectoryMutationLockSync(this.directory, () => {}, {
      label: 'test diagnostic witness directory',
      ownerLabel: 'test diagnostic witness authority',
      lockTimeoutMs: 60_000,
      lockTimeoutMaximumMs: 60_000,
    });
  }

  read(namespace) { return this.readRecord(namespace); }

  compareAndSwap(command) {
    return fileMutationLock.withFileMutationLockSync(this.lockPath, () => {
      const current = this.readRecord(command.namespace);
      if ((current ? current.recordDigest : null) !== command.expectedRecordDigest) return null;
      this.writeRecord(command.namespace, command.nextRecord);
      return structuredClone(command.nextRecord);
    }, { label: 'test diagnostic witness exact CAS', lockTimeoutMs: 60_000 });
  }

  readRecord(namespace) {
    const file = this.recordPath(namespace);
    if (!fs.existsSync(file)) return null;
    const bytes = privatePaths.readBoundedRegularFile(file, {
      maxBytes: 128 * 1024,
      label: 'test diagnostic witness record',
    });
    const value = JSON.parse(bytes.toString('utf8').trim());
    if (canonical(value) !== bytes.toString('utf8').trim() || value.namespace !== namespace) {
      throw new Error('test diagnostic witness record rejected');
    }
    return value;
  }

  writeRecord(namespace, record) {
    const file = this.recordPath(namespace);
    const staged = path.join(
      this.directory, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}`,
    );
    let descriptor;
    try {
      descriptor = fs.openSync(staged, 'wx', 0o600);
      fs.writeFileSync(descriptor, `${canonical(record)}\n`, 'utf8');
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      privatePaths.protectInheritedPrivateFile(staged, { label: 'test diagnostic witness staged record' });
      privatePaths.publishFileDurably(staged, file, { label: 'test diagnostic witness record' });
    } finally {
      if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} }
      try { fs.unlinkSync(staged); } catch {}
    }
  }

  recordPath(namespace) {
    const name = crypto.createHash('sha256').update(namespace, 'utf8').digest('hex');
    return path.join(this.directory, `${name}.json`);
  }
}

function auditDescriptor(eventId, action, fields) {
  return deepFreeze({
    schemaVersion: 1,
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
  });
}

function stateAudit(record, action, fields) {
  return auditDescriptor(record.auditEventId, action, {
    customerId: fields.customerId,
    deploymentId: fields.deploymentId,
    referenceId: fields.referenceId,
    operationDigest: record.recordDigest,
    resultDigest: record.recordDigest,
    resultCount: record.revision,
    stateRevision: record.revision,
    recordedAt: record.updatedAt || record.issuedAt || new Date(record.timeMs).toISOString(),
  });
}

function quotaReference(customerId, deploymentId, day) {
  return digest({ kind: 'vendor_diagnostic_quota', customerId, deploymentId, day });
}

function scopeKey(value) {
  return `${value.customerId}\0${value.deploymentId}`;
}

function claimKey(value) {
  return `${scopeKey(value)}\0${value.messageId}`;
}

function quotaKey(value) {
  return `${scopeKey(value)}\0${value.day}`;
}

class ReferenceDiagnosticStorage {
  constructor(options = {}) {
    this.contractVersion = STORAGE_CONTRACT_VERSION;
    this.data = emptyData();
    this.hooks = Object.create(null);
    this.transactionFault = 'normal';
    this.transactionCalls = 0;
    this.transactionTail = Promise.resolve();
    this.lastSearchQuery = null;
    this.lastCompactionQueries = [];
    this.databaseTimeMs = options.databaseTimeMs === undefined
      ? Date.parse('2026-07-12T12:00:00.000Z') : options.databaseTimeMs;
  }

  async transaction(work) {
    this.transactionCalls += 1;
    const run = () => this.runTransaction(work);
    const result = this.transactionTail.then(run, run);
    this.transactionTail = result.then(() => undefined, () => undefined);
    return result;
  }

  async runTransaction(work) {
    const staged = cloneData(this.data);
    const tx = new ReferenceDiagnosticTransaction(this, staged);
    if (this.transactionFault === 'omit') return Object.freeze({ omitted: true });
    if (this.transactionFault === 'substitute') {
      await work(tx);
      return Object.freeze({ substituted: true });
    }
    if (this.transactionFault === 'double') {
      await work(tx);
      await work(tx);
      throw new Error('unreachable double callback result');
    }
    if (this.transactionFault === 'swallowed-double') {
      const result = await work(tx);
      try { await work(tx); } catch {}
      return result;
    }
    if (this.transactionFault === 'raw') throw new Error('CANARY-RAW-STORAGE-123-45-6789');
    if (this.transactionFault !== 'normal') throw new Error('unknown reference transaction fault');
    const result = await work(tx);
    this.data = staged;
    return result;
  }

  setTransactionFault(value) {
    this.transactionFault = value;
  }

  snapshot() {
    return canonical(normalizeData(this.data));
  }

  seedAuthorization(record, audit) {
    this.data.authorizations.set(record.principalId, structuredClone(record));
    this.data.audits.push(structuredClone(audit));
  }

  seedConsent(record, audit) {
    this.data.consents.set(scopeKey(record), structuredClone(record));
    this.data.audits.push(structuredClone(audit));
  }

  seedCustomerGrant(record, audit) {
    this.data.customerGrants.set(scopeKey(record), structuredClone(record));
    this.data.audits.push(structuredClone(audit));
  }

  setDatabaseTime(value) {
    this.databaseTimeMs = value;
  }

  records() {
    return [...this.data.claims.values()].map((value) => structuredClone(value));
  }

  audits(action) {
    return this.data.audits
      .filter((value) => !action || value.action === action)
      .map((value) => structuredClone(value));
  }
}

class ReferenceDiagnosticTransaction {
  constructor(owner, data) {
    this.owner = owner;
    this.data = data;
  }

  invoke(name, args, operation) {
    const hook = this.owner.hooks[name];
    return hook ? hook({ args: structuredClone(args), data: this.data, run: operation }) : operation();
  }

  appendAudit(descriptor) {
    return this.invoke('appendAudit', [descriptor], () => {
      if (this.data.audits.some((value) => value.eventId === descriptor.eventId)) return null;
      const stored = structuredClone(descriptor);
      this.data.audits.push(stored);
      return structuredClone(stored);
    });
  }

  readAuditDescriptor(eventId) {
    return this.invoke('readAuditDescriptor', [eventId], () => {
      const found = this.data.audits.find((value) => value.eventId === eventId);
      return found ? structuredClone(found) : null;
    });
  }

  readLatestStateAudit(query) {
    return this.invoke('readLatestStateAudit', [query], () => {
      const found = this.data.audits.slice().reverse().find((value) => (
        value.action === query.action
        && value.customerId === query.customerId
        && value.deploymentId === query.deploymentId
        && value.referenceId === query.referenceId
      ));
      return found ? structuredClone(found) : null;
    });
  }

  readStateRevisionHighWater(query) {
    return this.invoke('readStateRevisionHighWater', [query], () => {
      const revisions = this.data.audits.filter((value) => (
        value.action === query.action
        && value.customerId === query.customerId
        && value.deploymentId === query.deploymentId
        && value.referenceId === query.referenceId
        && Number.isSafeInteger(value.stateRevision)
      )).map((value) => value.stateRevision);
      return revisions.length ? Math.max(...revisions) : null;
    });
  }

  readLatestClaimAudit(query) {
    return this.invoke('readLatestClaimAudit', [query], () => {
      const found = this.data.audits.slice().reverse().find((value) => (
        value.customerId === query.customerId
        && value.deploymentId === query.deploymentId
        && value.referenceId === query.messageId
      ));
      return found ? structuredClone(found) : null;
    });
  }

  readTimeHighWater() {
    return this.invoke('readTimeHighWater', [], () => cloneNullable(this.data.time));
  }

  readTrustedDatabaseTime() {
    return this.invoke('readTrustedDatabaseTime', [], () => ({
      source: 'database_transaction', timeMs: this.owner.databaseTimeMs,
    }));
  }

  compareAndSwapTimeHighWater(command) {
    return this.invoke('compareAndSwapTimeHighWater', [command], () => {
      if (!expectedDigest(this.data.time, command.expectedRecordDigest)) return null;
      this.data.time = structuredClone(command.nextRecord);
      return structuredClone(this.data.time);
    });
  }

  readDiagnosticAuthorizationState(principalId) {
    return this.invoke('readDiagnosticAuthorizationState', [principalId], () => (
      cloneNullable(this.data.authorizations.get(principalId) || null)
    ));
  }

  readDiagnosticCapabilityClaim(capabilityId) {
    return this.invoke('readDiagnosticCapabilityClaim', [capabilityId], () => (
      cloneNullable(this.data.capabilityClaims.get(capabilityId) || null)
    ));
  }

  readLatestCapabilityAudit(query) {
    return this.invoke('readLatestCapabilityAudit', [query], () => {
      const found = this.data.audits.slice().reverse().find((value) => (
        value.action === 'diagnostic_capability_used'
        && value.referenceId === query.capabilityId
      ));
      return found ? structuredClone(found) : null;
    });
  }

  readCustomerDiagnosticGrant(query) {
    return this.invoke('readCustomerDiagnosticGrant', [query], () => (
      cloneNullable(this.data.customerGrants.get(scopeKey(query)) || null)
    ));
  }

  readDiagnosticConsent(query) {
    return this.invoke('readDiagnosticConsent', [query], () => (
      cloneNullable(this.data.consents.get(scopeKey(query)) || null)
    ));
  }

  claimDiagnosticCapability(claim) {
    return this.invoke('claimDiagnosticCapability', [claim], () => {
      if (this.data.capabilityClaims.has(claim.capabilityId)) return null;
      this.data.capabilityClaims.set(claim.capabilityId, structuredClone(claim));
      return structuredClone(claim);
    });
  }

  readDiagnosticAccessEvidence(requestDigest) {
    return this.invoke('readDiagnosticAccessEvidence', [requestDigest], () => (
      cloneNullable(this.data.accessEvidence.get(requestDigest) || null)
    ));
  }

  readDiagnosticAccessRecord(query) {
    return this.invoke('readDiagnosticAccessRecord', [query], () => {
      const record = this.data.claims.get(claimKey(query)) || null;
      if (!record || record.recordType !== 'event'
          || record.recordDigest !== query.recordDigest) return null;
      return structuredClone(record);
    });
  }

  insertDiagnosticAccessEvidence(requestDigest, evidence) {
    return this.invoke('insertDiagnosticAccessEvidence', [requestDigest, evidence], () => {
      if (this.data.accessEvidence.has(requestDigest)) return null;
      this.data.accessEvidence.set(requestDigest, structuredClone(evidence));
      return structuredClone(evidence);
    });
  }

  readDiagnosticQuota(query) {
    return this.invoke('readDiagnosticQuota', [query], () => (
      cloneNullable(this.data.quotas.get(quotaKey(query)) || null)
    ));
  }

  compareAndSwapDiagnosticQuota(command) {
    return this.invoke('compareAndSwapDiagnosticQuota', [command], () => {
      const key = quotaKey(command);
      const current = this.data.quotas.get(key) || null;
      if (!expectedDigest(current, command.expectedRecordDigest)) return null;
      this.data.quotas.set(key, structuredClone(command.nextRecord));
      return structuredClone(command.nextRecord);
    });
  }

  findDiagnosticClaim(query) {
    return this.invoke('findDiagnosticClaim', [query], () => (
      cloneNullable(this.data.claims.get(claimKey(query)) || null)
    ));
  }

  insertDiagnostic(record) {
    return this.invoke('insertDiagnostic', [record], () => {
      const key = claimKey(record);
      if (this.data.claims.has(key)) return null;
      this.data.claims.set(key, structuredClone(record));
      return structuredClone(record);
    });
  }

  beginDiagnosticSearchSnapshot(query) {
    return this.invoke('beginDiagnosticSearchSnapshot', [query], () => {
      const records = this.filteredSearchRecords(query);
      if (!records.length) return null;
      const record = records.at(-1);
      return { receivedAt: record.receivedAt, messageId: record.messageId };
    });
  }

  filteredSearchRecords(query) {
    return [...this.data.claims.values()].filter((record) => (
      record.recordType === 'event'
      && customerAllowed(record.customerId, query.allowedCustomerIds)
      && Date.parse(record.expiresAt) > Date.parse(query.expiresAfter)
      && matchesFilters(record, query.filters)
    )).sort((left, right) => left.receivedAt.localeCompare(right.receivedAt)
      || left.messageId.localeCompare(right.messageId));
  }

  searchDiagnostics(query) {
    return this.invoke('searchDiagnostics', [query], () => {
      this.owner.lastSearchQuery = structuredClone(query);
      const records = this.filteredSearchRecords(query).filter((record) => {
        const point = { receivedAt: record.receivedAt, messageId: record.messageId };
        return (!query.after || compareHighWater(point, query.after) > 0)
          && (!query.snapshotHighWater
            || compareHighWater(point, query.snapshotHighWater) <= 0);
      });
      return { items: structuredClone(records.slice(0, query.limit)) };
    });
  }

  listExpiredDiagnostics(query) {
    return this.compactionList('listExpiredDiagnostics', query, 'event', 'expiresAt');
  }

  listExpiredDiagnosticTombstones(query) {
    return this.compactionList(
      'listExpiredDiagnosticTombstones', query, 'tombstone', 'deleteAfter',
    );
  }

  listExpiredDiagnosticReplayIndexes(query) {
    return this.compactionList(
      'listExpiredDiagnosticReplayIndexes', query, 'replay', 'idempotencyUntil',
    );
  }

  compactionList(name, query, recordType, timeField) {
    return this.invoke(name, [query], () => {
      this.owner.lastCompactionQueries.push({ name, query: structuredClone(query) });
      const records = [...this.data.claims.values()].filter((record) => (
        record.recordType === recordType
        && customerAllowed(record.customerId, query.allowedCustomerIds)
        && Date.parse(record[timeField]) <= query.nowMs
        && !activeDeletionReservation(this.data, record)
      ));
      records.sort((left, right) => left[timeField].localeCompare(right[timeField])
        || left.receivedAt.localeCompare(right.receivedAt)
        || left.messageId.localeCompare(right.messageId));
      return structuredClone(records.slice(0, query.limit));
    });
  }

  replaceDiagnosticWithTombstone(command) {
    return this.replaceClaim('replaceDiagnosticWithTombstone', command, 'event', 'tombstone');
  }

  replaceDiagnosticTombstoneWithReplay(command) {
    return this.replaceClaim(
      'replaceDiagnosticTombstoneWithReplay', command, 'tombstone', 'replay',
    );
  }

  replaceClaim(name, command, currentType, nextType) {
    return this.invoke(name, [command], () => {
      const key = claimKey(command.current);
      const current = this.data.claims.get(key);
      if (!current || current.recordType !== currentType || command.next.recordType !== nextType
          || canonical(current) !== canonical(command.current)
          || claimKey(command.next) !== key) return null;
      this.data.claims.set(key, structuredClone(command.next));
      return structuredClone(command.next);
    });
  }

  deleteDiagnosticReplayIndex(record) {
    return this.invoke('deleteDiagnosticReplayIndex', [record], () => {
      const key = claimKey(record);
      const current = this.data.claims.get(key);
      if (!current || current.recordType !== 'replay'
          || canonical(current) !== canonical(record)) return null;
      this.data.claims.delete(key);
      return structuredClone(record);
    });
  }

  readDiagnosticDeletionJob(jobId) {
    return this.invoke('readDiagnosticDeletionJob', [jobId], () => (
      cloneNullable(this.data.deletionJobs.get(jobId) || null)
    ));
  }

  readDiagnosticDeletionReservation(query) {
    return this.invoke('readDiagnosticDeletionReservation', [query], () => (
      cloneNullable(this.data.deletionReservations.get(scopeKey(query)) || null)
    ));
  }

  listExpiredDiagnosticDeletionReservations(query) {
    return this.invoke('listExpiredDiagnosticDeletionReservations', [query], () => (
      [...this.data.deletionReservations.values()]
        .filter((record) => record.active
          && Date.parse(record.leaseExpiresAt) <= query.nowMs
          && customerAllowed(record.customerId, query.allowedCustomerIds))
        .sort((left, right) => left.leaseExpiresAt.localeCompare(right.leaseExpiresAt)
          || left.customerId.localeCompare(right.customerId)
          || left.deploymentId.localeCompare(right.deploymentId))
        .slice(0, query.limit)
        .map((record) => structuredClone(record))
    ));
  }

  compareAndSwapDiagnosticDeletionReservation(command) {
    return this.invoke('compareAndSwapDiagnosticDeletionReservation', [command], () => {
      const key = scopeKey(command);
      const current = this.data.deletionReservations.get(key) || null;
      if (!expectedDigest(current, command.expectedRecordDigest)
          || command.nextRecord.customerId !== command.customerId
          || command.nextRecord.deploymentId !== command.deploymentId) return null;
      for (const [otherKey, other] of this.data.deletionReservations) {
        if (otherKey !== key && other.jobId === command.nextRecord.jobId) return null;
      }
      this.data.deletionReservations.set(key, structuredClone(command.nextRecord));
      return structuredClone(command.nextRecord);
    });
  }

  compareAndSwapDiagnosticDeletionJob(command) {
    return this.invoke('compareAndSwapDiagnosticDeletionJob', [command], () => {
      const current = this.data.deletionJobs.get(command.jobId) || null;
      if (!expectedDigest(current, command.expectedRecordDigest)) return null;
      this.data.deletionJobs.set(command.jobId, structuredClone(command.nextRecord));
      return structuredClone(command.nextRecord);
    });
  }

  previewDiagnosticDeletion(query) {
    return this.invoke('previewDiagnosticDeletion', [query], () => {
      const records = deletionRecords(this.data, query);
      if (!records.length) return { count: 0, snapshotHighWater: null };
      const record = records.at(-1);
      return {
        count: records.length,
        snapshotHighWater: { receivedAt: record.receivedAt, messageId: record.messageId },
      };
    });
  }

  listDiagnosticDeletionBatch(command) {
    return this.invoke('listDiagnosticDeletionBatch', [command], () => {
      const job = this.data.deletionJobs.get(command.jobId) || null;
      if (!job || job.recordDigest !== command.expectedJobDigest) return [];
      if (command.snapshotHighWater === null) return [];
      return structuredClone(deletionRecords(this.data, command).filter((record) => {
        const point = { receivedAt: record.receivedAt, messageId: record.messageId };
        return (!command.after || compareHighWater(point, command.after) > 0)
          && compareHighWater(point, command.snapshotHighWater) <= 0;
      }).slice(0, command.limit));
    });
  }

  deleteDiagnosticBatch(command) {
    return this.invoke('deleteDiagnosticBatch', [command], () => {
      const job = this.data.deletionJobs.get(command.jobId) || null;
      if (!job || job.recordDigest !== command.expectedJobDigest) return null;
      for (const record of command.records) {
        const current = this.data.claims.get(claimKey(record));
        if (!current || canonical(current) !== canonical(record)) return null;
      }
      for (const record of command.records) this.data.claims.delete(claimKey(record));
      return {
        deleted: command.records.map((record) => ({
          receivedAt: record.receivedAt, messageId: record.messageId,
        })),
        done: command.done,
      };
    });
  }
}

function emptyData() {
  return {
    time: null,
    authorizations: new Map(),
    customerGrants: new Map(),
    consents: new Map(),
    quotas: new Map(),
    capabilityClaims: new Map(),
    accessEvidence: new Map(),
    claims: new Map(),
    deletionJobs: new Map(),
    deletionReservations: new Map(),
    audits: [],
  };
}

function cloneData(data) {
  return structuredClone(data);
}

function normalizeData(data) {
  return {
    time: data.time,
    authorizations: orderedMap(data.authorizations),
    customerGrants: orderedMap(data.customerGrants),
    consents: orderedMap(data.consents),
    quotas: orderedMap(data.quotas),
    capabilityClaims: orderedMap(data.capabilityClaims),
    accessEvidence: orderedMap(data.accessEvidence),
    claims: orderedMap(data.claims),
    deletionJobs: orderedMap(data.deletionJobs),
    deletionReservations: orderedMap(data.deletionReservations),
    audits: data.audits,
  };
}

function orderedMap(value) {
  return [...value.entries()].sort(([left], [right]) => left.localeCompare(right));
}

function expectedDigest(record, expected) {
  return record === null ? expected === null : record.recordDigest === expected;
}

function cloneNullable(value) {
  return value === null ? null : structuredClone(value);
}

function customerAllowed(customerId, allowed) {
  return allowed === '*' || allowed.includes(customerId);
}

function matchesFilters(record, filters) {
  if (filters.customerId && record.customerId !== filters.customerId) return false;
  if (filters.deploymentId && record.deploymentId !== filters.deploymentId) return false;
  for (const field of ['component', 'code', 'severity', 'outcome']) {
    if (filters[field] && record.payload[field] !== filters[field]) return false;
  }
  if (filters.occurredAfter
      && Date.parse(record.payload.occurredAt) < Date.parse(filters.occurredAfter)) return false;
  if (filters.occurredBefore
      && Date.parse(record.payload.occurredAt) >= Date.parse(filters.occurredBefore)) return false;
  return true;
}

function compareHighWater(left, right) {
  return left.receivedAt.localeCompare(right.receivedAt)
    || left.messageId.localeCompare(right.messageId);
}

function deletionRecords(data, query) {
  return [...data.claims.values()].filter((record) => (
    record.customerId === query.customerId
    && record.deploymentId === query.deploymentId
  )).sort((left, right) => left.receivedAt.localeCompare(right.receivedAt)
    || left.messageId.localeCompare(right.messageId));
}

function activeDeletionReservation(data, record) {
  const reservation = data.deletionReservations.get(scopeKey(record));
  return Boolean(reservation && reservation.active);
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

module.exports = {
  FileDiagnosticWitness,
  ReferenceDiagnosticStorage,
  ReferenceDiagnosticWitness,
  authenticate,
  canonical,
  digest,
  hmacAuthority,
  quotaReference,
  scopeKey,
  stateAudit,
};
