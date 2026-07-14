'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');
const fileMutationLock = require('./file-mutation-lock');
const privatePaths = require('./private-path');
const protocol = require('./vendor-control-protocol');
const {
  AUDIT_DOMAIN,
  STORAGE_CONTRACT_VERSION,
} = require('./vendor-diagnostic-intelligence');
const {
  PRODUCTION_WITNESS_ASSURANCE,
  TEST_WITNESS_ASSURANCE,
  isProductionVendorDiagnosticWitnessAuthority,
} = require('./vendor-diagnostic-witness-factory');

const SCHEMA_VERSION = 2;
const DATABASE_SCHEMA_VERSION = 4;
const GENESIS_HEAD = '0'.repeat(64);
const CHECKPOINT_DOMAIN = 'redactwall.vendor-diagnostic-audit-checkpoint.v1';
const PENDING_DOMAIN = 'redactwall.vendor-diagnostic-audit-pending.v1';
const WITNESS_DOMAIN = 'redactwall.vendor-diagnostic-monotonic-witness.v1';
const RESTORE_CLAIM_DOMAIN = 'redactwall.vendor-diagnostic-restore-claim.v1';
const BACKUP_DOMAIN = 'redactwall.vendor-diagnostic-backup-manifest.v1';
const RESTORE_DOMAIN = 'redactwall.vendor-diagnostic-restore-authorization.v1';
const DATABASE_FILE = 'vendor-diagnostics.sqlite';
const CHECKPOINT_FILE = 'vendor-diagnostics.audit-checkpoint.json';
const PENDING_FILE = 'vendor-diagnostics.audit-pending.json';
const LOCK_FILE = 'vendor-diagnostics.transaction';
const MAX_SIDECAR_BYTES = 64 * 1024;
const SQLITE_BUSY_TIMEOUT_MS = 30_000;
const CONTROL_KINDS = new Set(['authorization', 'customer_grant', 'consent']);

class VendorDiagnosticSqliteStorage {
  constructor(options) {
    assertReferenceRuntime();
    const configuration = checkedOptions(options);
    this.contractVersion = STORAGE_CONTRACT_VERSION;
    this.directory = configuration.directory;
    this.databasePath = path.join(this.directory, DATABASE_FILE);
    this.checkpointPath = path.join(this.directory, CHECKPOINT_FILE);
    this.pendingPath = path.join(this.directory, PENDING_FILE);
    this.lockPath = path.join(this.directory, LOCK_FILE);
    this.auditAuthority = configuration.auditAuthority;
    this.witnessIntegrityAuthority = configuration.witnessIntegrityAuthority;
    this.witnessAuthority = configuration.witnessAuthority;
    this.security = configuration.security;
    this.restoreAuthorization = configuration.restoreAuthorization;
    this.backupManifest = configuration.backupManifest;
    this.tail = Promise.resolve();
    this.degraded = null;
    this.closed = false;
    this.db = openPrivateDatabase(
      this.directory, this.databasePath, this.security, this.auditAuthority,
      this.witnessAuthority, this.witnessIntegrityAuthority,
    );
    this.instanceBinding = databaseInstanceBinding(this.databasePath);
    this.dataVersion = databaseDataVersion(this.db);
    try {
      fileMutationLock.withFileMutationLockSync(
        this.lockPath,
        () => this.initializeAndReconcile(),
        {
          label: 'vendor diagnostic SQLite initialization',
          lockTimeoutMs: 60_000,
          lockTimeoutMaximumMs: 60_000,
        },
      );
    }
    catch (error) {
      try { this.db.close(); } catch {}
      throw error;
    }
  }

  transaction(work) {
    if (this.closed || typeof work !== 'function') {
      return Promise.reject(storageError('diagnostic_sqlite_closed'));
    }
    if (this.degraded !== null) return Promise.reject(this.degraded);
    const run = () => fileMutationLock.withFileMutationLock(
      this.lockPath,
      () => this.runTransaction(work),
      { label: 'vendor diagnostic SQLite transaction', lockTimeoutMs: SQLITE_BUSY_TIMEOUT_MS },
    );
    const result = this.tail.then(run, run);
    this.tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async runTransaction(work) {
    this.db.exec('BEGIN IMMEDIATE');
    let committed = false;
    let commitFault = null;
    let result;
    let finalState;
    let base;
    let identity;
    try {
      base = this.reconcileAndVerify(false);
      identity = this.readStoreIdentity();
      const tx = new VendorDiagnosticSqliteTransaction(this);
      result = await work(tx);
      const finalTail = this.verifyAuditTailFrom(base);
      if (finalTail.sequence <= base.sequence) {
        throw storageError('diagnostic_sqlite_audit_required');
      }
      finalState = verifiedStoreState(this.db, this.auditAuthority);
      if (!sameTail(finalState, finalTail)) {
        throw storageError('diagnostic_sqlite_audit_chain_invalid');
      }
      const pending = authenticate(this.auditAuthority, PENDING_DOMAIN, {
        schemaVersion: SCHEMA_VERSION,
        recordType: 'pending_commit',
        transactionId: crypto.randomUUID(),
        storeId: identity.storeId,
        scopeId: identity.scopeId,
        baseSequence: base.sequence,
        baseHead: base.head,
        baseStateDigest: base.stateDigest,
        finalSequence: finalState.sequence,
        finalHead: finalState.head,
        finalStateDigest: finalState.stateDigest,
        recordedAt: iso(tx.databaseTimeMs()),
      });
      writeSidecar(this.pendingPath, pending);
      try {
        this.db.exec('COMMIT');
        committed = true;
      } catch (commitError) {
        commitFault = commitError;
      }
    } catch (error) {
      if (!committed) {
        try { this.db.exec('ROLLBACK'); } catch {}
      }
      throw error;
    }
    if (commitFault !== null) {
      return this.resolveCommitFault({ base, finalState, result, commitFault });
    }
    try {
      this.publishWitness(identity, base, finalState);
      this.publishCheckpoint(finalState);
      removeSidecar(this.pendingPath);
      this.degraded = null;
    } catch (error) {
      this.degraded = storageError(
        String(error && error.code || '').includes('witness')
          ? 'diagnostic_sqlite_witness_uncertain'
          : 'diagnostic_sqlite_checkpoint_degraded',
        error,
      );
      throw this.degraded;
    }
    return result;
  }

  resolveCommitFault({ base, finalState, result, commitFault }) {
    this.degraded = storageError('diagnostic_sqlite_commit_uncertain', commitFault);
    const uncertainConnection = this.db;
    try {
      if (uncertainConnection.inTransaction) uncertainConnection.exec('ROLLBACK');
    } catch {}
    try { uncertainConnection.close(); }
    catch { throw this.degraded; }
    if (uncertainConnection.open !== false) throw this.degraded;
    this.db = openPrivateDatabase(
      this.directory, this.databasePath, this.security, this.auditAuthority,
      this.witnessAuthority, this.witnessIntegrityAuthority,
    );
    const observedDataVersion = databaseDataVersion(this.db);
    this.db.exec('BEGIN IMMEDIATE');
    let durableState;
    try {
      durableState = verifiedStoreState(this.db, this.auditAuthority);
      if (databaseDataVersion(this.db) !== observedDataVersion) {
        throw storageError('diagnostic_sqlite_state_unstable');
      }
      this.db.exec('COMMIT');
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
    if (sameState(durableState, finalState)) {
      const identity = this.readStoreIdentity();
      this.publishWitness(identity, base, finalState);
      return result;
    }
    if (sameState(durableState, base)) {
      throw storageError('diagnostic_sqlite_commit_rolled_back', commitFault);
    }
    throw storageError('diagnostic_sqlite_commit_uncertain', commitFault);
  }

  initializeAndReconcile() {
    const identityCreated = this.initializeStoreIdentity();
    if (identityCreated && this.restoreAuthorization === null && this.backupManifest === null) {
      this.publishInitialWitness(
        this.readStoreIdentity(), verifiedStoreState(this.db, this.auditAuthority),
      );
    }
    this.db.exec('BEGIN IMMEDIATE');
    let restored = null;
    try {
      if (this.restoreAuthorization !== null || this.backupManifest !== null) {
        restored = this.adoptFreshRestoreScope();
      } else {
        this.reconcileAndVerify(true);
      }
      this.db.exec('COMMIT');
      if (restored !== null) {
        this.publishCheckpoint(restored.state);
        removeSidecar(this.pendingPath);
      }
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
  }

  initializeStoreIdentity() {
    const present = this.readStoreIdentity(true);
    if (present) return false;
    const tail = auditTail(this.db);
    if (tail.sequence !== 0 || fs.existsSync(this.checkpointPath)
        || fs.existsSync(this.pendingPath)) {
      throw storageError('diagnostic_sqlite_store_identity_missing');
    }
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare(`
        INSERT INTO vd_store (singleton, store_id, scope_id) VALUES (1, ?, ?)
      `).run(crypto.randomUUID(), crypto.randomUUID());
      this.db.exec('COMMIT');
      return true;
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch {}
      throw error;
    }
  }

  adoptFreshRestoreScope() {
    if (this.restoreAuthorization === null || this.backupManifest === null
        || fs.existsSync(this.pendingPath)) {
      throw storageError('diagnostic_sqlite_restore_invalid');
    }
    const manifest = verifyBackupManifest(this.auditAuthority, this.backupManifest);
    const authorization = verifyRestoreAuthorization(
      this.auditAuthority, this.restoreAuthorization,
    );
    const sourceIdentity = this.readStoreIdentity();
    const sourceState = verifiedStoreState(this.db, this.auditAuthority);
    const checkpoint = this.readCheckpoint();
    if (authorization.backupManifestDigest !== manifest.recordDigest
        || authorization.sourceStoreId !== sourceIdentity.storeId
        || authorization.sourceScopeId !== sourceIdentity.scopeId
        || manifest.sourceStoreId !== sourceIdentity.storeId
        || manifest.sourceScopeId !== sourceIdentity.scopeId
        || authorization.sourceSequence !== manifest.sequence
        || authorization.sourceHead !== manifest.head
        || !sameState(sourceState, manifest) || !sameState(checkpoint, manifest)
        || Date.parse(authorization.expiresAt) <= databaseNow(this.db)) {
      throw storageError('diagnostic_sqlite_restore_invalid');
    }
    const identity = Object.freeze({
      storeId: authorization.destinationStoreId,
      scopeId: authorization.destinationScopeId,
    });
    const recordedAt = iso(databaseNow(this.db));
    const descriptorCore = {
      schemaVersion: 1,
      eventId: crypto.randomUUID(),
      action: 'diagnostic_store_scope_restored',
      customerId: null,
      deploymentId: null,
      referenceId: authorization.authorizationId,
      operationDigest: manifest.recordDigest,
      resultDigest: sha256(canonical(identity)),
      resultCount: 1,
      stateRevision: 1,
      recordedAt,
    };
    const audit = authenticate(this.auditAuthority, AUDIT_DOMAIN, descriptorCore);
    const auditJson = canonical(audit);
    const finalTail = Object.freeze({
      sequence: sourceState.sequence + 1,
      head: sha256(`${sourceState.head}\0${auditJson}`),
    });
    this.db.prepare(`
      UPDATE vd_store SET store_id = ?, scope_id = ? WHERE singleton = 1
    `).run(identity.storeId, identity.scopeId);
    const tx = new VendorDiagnosticSqliteTransaction(this);
    if (tx.appendAudit(audit) === null) throw storageError('diagnostic_sqlite_restore_invalid');
    const actualTail = this.verifyAuditTailFrom(sourceState);
    if (!sameTail(actualTail, finalTail)) throw storageError('diagnostic_sqlite_restore_invalid');
    const finalState = verifiedStoreState(this.db, this.auditAuthority);
    if (!sameTail(finalState, finalTail)) throw storageError('diagnostic_sqlite_restore_invalid');
    const witness = createWitnessRecord(
      this.witnessIntegrityAuthority, identity, finalState, 1, null,
      authorization.recordDigest, recordedAt, this.instanceBinding,
    );
    const claim = authenticate(this.witnessIntegrityAuthority, RESTORE_CLAIM_DOMAIN, {
      schemaVersion: SCHEMA_VERSION,
      recordType: 'diagnostic_restore_claim',
      namespace: restoreClaimNamespace(authorization.authorizationId),
      authorizationId: authorization.authorizationId,
      authorizationDigest: authorization.recordDigest,
      backupManifestDigest: manifest.recordDigest,
      sourceStoreId: sourceIdentity.storeId,
      sourceScopeId: sourceIdentity.scopeId,
      sourceSequence: sourceState.sequence,
      sourceHead: sourceState.head,
      destinationStoreId: identity.storeId,
      destinationScopeId: identity.scopeId,
      resultWitnessDigest: witness.recordDigest,
      claimedAt: recordedAt,
    });
    this.consumeRestoreClaim(claim);
    this.publishNewWitness(witness, 'diagnostic_sqlite_restore_witness_uncertain');
    const pending = authenticate(this.auditAuthority, PENDING_DOMAIN, {
      schemaVersion: SCHEMA_VERSION,
      recordType: 'pending_commit',
      transactionId: crypto.randomUUID(),
      storeId: identity.storeId,
      scopeId: identity.scopeId,
      baseSequence: sourceState.sequence,
      baseHead: sourceState.head,
      baseStateDigest: sourceState.stateDigest,
      finalSequence: finalState.sequence,
      finalHead: finalState.head,
      finalStateDigest: finalState.stateDigest,
      recordedAt: iso(databaseNow(this.db)),
    });
    writeSidecar(this.pendingPath, pending);
    return { identity, state: finalState, authorization, claim, witness };
  }

  reconcileAndVerify(_fullVerification = false) {
    const acceptedDataVersion = this.dataVersion;
    try {
      const observedDataVersion = databaseDataVersion(this.db);
      const checkpoint = this.readCheckpoint();
      const identity = this.readStoreIdentity();
      const witness = this.readStoreWitness(identity);
      const state = verifiedStoreState(this.db, this.auditAuthority);
      const pending = readAuthenticatedSidecar(
        this.pendingPath, this.auditAuthority, PENDING_DOMAIN, pendingCoreKeys(), true,
      );
      if (pending !== null) {
        validatePending(pending);
        if (pending.storeId !== identity.storeId || pending.scopeId !== identity.scopeId) {
          throw storageError('diagnostic_sqlite_pending_conflict');
        }
        const base = {
          sequence: pending.baseSequence,
          head: pending.baseHead,
          stateDigest: pending.baseStateDigest,
        };
        const final = {
          sequence: pending.finalSequence,
          head: pending.finalHead,
          stateDigest: pending.finalStateDigest,
        };
        if (sameState(state, final)) {
          if (!sameState(checkpoint, base) && !sameState(checkpoint, final)) {
            throw storageError('diagnostic_sqlite_pending_conflict');
          }
          if (!sameState(witness, base) && !sameState(witness, final)) {
            throw storageError('diagnostic_sqlite_pending_conflict');
          }
          if (!sameState(witness, final)) this.publishWitness(identity, base, final);
          if (!sameState(checkpoint, final)) this.publishCheckpoint(final);
        } else if (!sameState(state, base) || !sameState(checkpoint, base)
            || !sameState(witness, base)) {
          throw storageError('diagnostic_sqlite_pending_conflict');
        }
        removeSidecar(this.pendingPath);
      }
      const reconciled = this.readCheckpoint();
      const reconciledWitness = this.readStoreWitness(identity);
      if (!sameState(reconciled, state) && sameState(reconciledWitness, state)) {
        this.publishCheckpoint(state);
      }
      const finalCheckpoint = this.readCheckpoint();
      if ((sameTail(finalCheckpoint, state)
            && finalCheckpoint.stateDigest !== state.stateDigest)
          || (sameTail(reconciledWitness, state)
            && reconciledWitness.stateDigest !== state.stateDigest)) {
        throw storageError('diagnostic_sqlite_state_mismatch');
      }
      if (!sameState(finalCheckpoint, state) || !sameState(reconciledWitness, state)) {
        throw storageError('diagnostic_sqlite_checkpoint_mismatch');
      }
      if (databaseDataVersion(this.db) !== observedDataVersion) {
        throw storageError('diagnostic_sqlite_state_unstable');
      }
      this.degraded = null;
      this.dataVersion = observedDataVersion;
      return state;
    } catch (error) {
      const failure = diagnosticStateFailure(error);
      this.degraded = failure;
      this.dataVersion = acceptedDataVersion;
      throw failure;
    }
  }

  verifyAuditChainStreaming() {
    const rows = this.db.prepare(`
      SELECT sequence, event_id, action, customer_id, deployment_id,
        reference_id, state_revision, descriptor_json, previous_hash, entry_hash
      FROM vd_audit ORDER BY sequence ASC
    `).iterate();
    let sequence = 0;
    let head = GENESIS_HEAD;
    for (const row of rows) {
      sequence += 1;
      if (row.sequence !== sequence || row.previous_hash !== head) {
        throw storageError('diagnostic_sqlite_audit_chain_invalid');
      }
      verifyAuditRow(this.auditAuthority, row, head);
      head = row.entry_hash;
    }
    return Object.freeze({ sequence, head });
  }

  verifyAuditTailFrom(base) {
    if (!Number.isSafeInteger(base.sequence) || base.sequence < 0 || !hexDigest(base.head)) {
      throw storageError('diagnostic_sqlite_audit_chain_invalid');
    }
    let sequence = base.sequence;
    let head = base.head;
    const rows = this.db.prepare(`
      SELECT sequence, event_id, action, customer_id, deployment_id,
        reference_id, state_revision, descriptor_json, previous_hash, entry_hash
      FROM vd_audit WHERE sequence > ? ORDER BY sequence ASC
    `).iterate(base.sequence);
    for (const row of rows) {
      sequence += 1;
      if (row.sequence !== sequence || row.previous_hash !== head) {
        throw storageError('diagnostic_sqlite_audit_chain_invalid');
      }
      verifyAuditRow(this.auditAuthority, row, head);
      head = row.entry_hash;
    }
    const raw = auditTail(this.db);
    if (raw.sequence !== sequence || raw.head !== head) {
      throw storageError('diagnostic_sqlite_audit_chain_invalid');
    }
    return Object.freeze({ sequence, head });
  }

  readCheckpoint() {
    const value = readAuthenticatedSidecar(
      this.checkpointPath, this.auditAuthority, CHECKPOINT_DOMAIN,
      checkpointCoreKeys(), true,
    );
    if (value === null) {
      return Object.freeze({ sequence: 0, head: GENESIS_HEAD, stateDigest: null });
    }
    validateCheckpoint(value);
    return Object.freeze({
      sequence: value.sequence, head: value.head, stateDigest: value.stateDigest,
    });
  }

  readStoreIdentity(optional = false) {
    const row = this.db.prepare(`
      SELECT store_id, scope_id FROM vd_store WHERE singleton = 1
    `).get();
    if (!row) {
      if (optional) return null;
      throw storageError('diagnostic_sqlite_store_identity_missing');
    }
    if (!uuid(row.store_id) || !uuid(row.scope_id)) {
      throw storageError('diagnostic_sqlite_store_identity_invalid');
    }
    return Object.freeze({ storeId: row.store_id, scopeId: row.scope_id });
  }

  readStoreWitness(identity, optional = false) {
    const namespace = storeWitnessNamespace(identity.storeId, this.instanceBinding);
    const value = this.readWitnessRecord(
      namespace, WITNESS_DOMAIN, witnessCoreKeys(), 'diagnostic_sqlite_witness_invalid', optional,
    );
    if (value === null) return null;
    validateWitness(value);
    if (value.storeId !== identity.storeId || value.scopeId !== identity.scopeId
        || value.instanceBinding !== this.instanceBinding) {
      throw storageError('diagnostic_sqlite_witness_identity_mismatch');
    }
    return value;
  }

  readWitnessRecord(namespace, domain, coreKeys, code, optional = false) {
    let value;
    try { value = syncWitnessResult(this.witnessAuthority.read(namespace)); }
    catch (error) { throw storageError('diagnostic_sqlite_witness_uncertain', error); }
    if (value === null) {
      if (optional) return null;
      throw storageError('diagnostic_sqlite_witness_missing');
    }
    return verifyAuthenticated(
      this.witnessIntegrityAuthority, domain, clone(value), coreKeys, code,
    );
  }

  publishInitialWitness(identity, tail) {
    if (tail.sequence !== 0 || tail.head !== GENESIS_HEAD
        || this.readStoreWitness(identity, true) !== null) {
      throw storageError('diagnostic_sqlite_witness_conflict');
    }
    const witness = createWitnessRecord(
      this.witnessIntegrityAuthority, identity, tail, 1, null, null,
      iso(databaseNow(this.db)), this.instanceBinding,
    );
    return this.publishNewWitness(witness, 'diagnostic_sqlite_witness_uncertain');
  }

  publishNewWitness(witness, code) {
    let result;
    try {
      result = syncWitnessResult(this.witnessAuthority.compareAndSwap({
        namespace: witness.namespace,
        expectedRecordDigest: null,
        nextRecord: clone(witness),
      }));
    } catch (error) { throw storageError(code, error); }
    const observed = this.readWitnessRecord(
      witness.namespace,
      witness.recordType === 'diagnostic_restore_claim' ? RESTORE_CLAIM_DOMAIN : WITNESS_DOMAIN,
      witness.recordType === 'diagnostic_restore_claim' ? restoreClaimCoreKeys() : witnessCoreKeys(),
      code,
    );
    if (!sameAuthenticatedRecord(result, witness) || !sameAuthenticatedRecord(observed, witness)) {
      throw storageError(code);
    }
    return observed;
  }

  publishWitness(identity, expected, next) {
    const current = this.readStoreWitness(identity);
    if (sameState(current, next)) return current;
    if (!sameState(current, expected) || next.sequence <= expected.sequence) {
      throw storageError('diagnostic_sqlite_witness_conflict');
    }
    const witness = createWitnessRecord(
      this.witnessIntegrityAuthority, identity, next, current.generation + 1,
      current.recordDigest, null, iso(databaseNow(this.db)), this.instanceBinding,
    );
    let result;
    try {
      result = syncWitnessResult(this.witnessAuthority.compareAndSwap({
        namespace: witness.namespace,
        expectedRecordDigest: current.recordDigest,
        nextRecord: clone(witness),
      }));
    } catch (error) {
      const observed = this.readStoreWitness(identity);
      if (sameAuthenticatedRecord(observed, witness)) return observed;
      throw storageError('diagnostic_sqlite_witness_uncertain', error);
    }
    const observed = this.readStoreWitness(identity);
    if (!sameAuthenticatedRecord(result, witness) || !sameAuthenticatedRecord(observed, witness)) {
      throw storageError('diagnostic_sqlite_witness_conflict');
    }
    return observed;
  }

  consumeRestoreClaim(claim) {
    if (this.readWitnessRecord(
      claim.namespace, RESTORE_CLAIM_DOMAIN, restoreClaimCoreKeys(),
      'diagnostic_sqlite_restore_claim_invalid', true,
    ) !== null) throw storageError('diagnostic_sqlite_restore_authorization_consumed');
    this.publishNewWitness(claim, 'diagnostic_sqlite_restore_claim_uncertain');
  }

  publishCheckpoint(tail) {
    const checkpoint = authenticate(this.auditAuthority, CHECKPOINT_DOMAIN, {
      schemaVersion: SCHEMA_VERSION,
      recordType: 'audit_checkpoint',
      sequence: tail.sequence,
      head: tail.head,
      stateDigest: tail.stateDigest,
      recordedAt: iso(databaseNow(this.db)),
    });
    writeSidecar(this.checkpointPath, checkpoint);
  }

  createAuthenticatedBackupManifest(command) {
    const input = checkedBackupCommand(command);
    return this.withReadSnapshot(() => {
      const state = this.reconcileAndVerify(false);
      const identity = this.readStoreIdentity();
      return authenticate(this.auditAuthority, BACKUP_DOMAIN, {
        schemaVersion: SCHEMA_VERSION,
        recordType: 'diagnostic_backup_manifest',
        backupId: input.backupId,
        sourceStoreId: identity.storeId,
        sourceScopeId: identity.scopeId,
        sequence: state.sequence,
        head: state.head,
        stateDigest: state.stateDigest,
        createdAt: iso(databaseNow(this.db)),
      });
    });
  }

  createFreshRestoreAuthorization(command) {
    const input = checkedRestoreRequest(command);
    return this.withReadSnapshot(() => {
      const manifest = verifyBackupManifest(this.auditAuthority, input.backupManifest);
      const state = this.reconcileAndVerify(false);
      const identity = this.readStoreIdentity();
      if (manifest.sourceStoreId !== identity.storeId
          || manifest.sourceScopeId !== identity.scopeId
          || !sameState(manifest, state)) {
        throw storageError('diagnostic_sqlite_backup_manifest_stale');
      }
      const nowMs = databaseNow(this.db);
      return authenticate(this.auditAuthority, RESTORE_DOMAIN, {
        schemaVersion: SCHEMA_VERSION,
        recordType: 'diagnostic_restore_authorization',
        authorizationId: crypto.randomUUID(),
        backupManifestDigest: manifest.recordDigest,
        sourceStoreId: identity.storeId,
        sourceScopeId: identity.scopeId,
        sourceSequence: state.sequence,
        sourceHead: state.head,
        destinationStoreId: crypto.randomUUID(),
        destinationScopeId: crypto.randomUUID(),
        issuedAt: iso(nowMs),
        expiresAt: iso(nowMs + input.lifetimeMs),
      });
    });
  }

  withReadSnapshot(work) {
    if (this.closed) {
      return Promise.reject(storageError('diagnostic_sqlite_closed'));
    }
    if (this.degraded !== null) return Promise.reject(this.degraded);
    const run = () => fileMutationLock.withFileMutationLock(this.lockPath, () => {
        this.db.exec('BEGIN IMMEDIATE');
        try {
          const result = work();
          this.db.exec('COMMIT');
          return result;
        } catch (error) {
          try { this.db.exec('ROLLBACK'); } catch {}
          throw error;
        }
      }, { label: 'vendor diagnostic SQLite snapshot', lockTimeoutMs: SQLITE_BUSY_TIMEOUT_MS });
    const result = this.tail.then(run, run);
    this.tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async publishControlState(command) {
    const input = checkedControlState(command);
    return this.transaction((tx) => tx.publishControlState(input));
  }

  health() {
    let liveError = this.degraded;
    if (liveError === null && !this.closed) {
      const acceptedDataVersion = this.dataVersion;
      try {
        const observedDataVersion = databaseDataVersion(this.db);
        this.db.exec('BEGIN');
        const identity = this.readStoreIdentity();
        const witness = this.readStoreWitness(identity);
        const state = verifiedStoreState(this.db, this.auditAuthority);
        const checkpoint = this.readCheckpoint();
        if ((sameTail(witness, state) && witness.stateDigest !== state.stateDigest)
            || (sameTail(checkpoint, state)
              && checkpoint.stateDigest !== state.stateDigest)) {
          throw storageError('diagnostic_sqlite_state_mismatch');
        }
        if (!sameState(witness, state) || !sameState(checkpoint, state)) {
          throw storageError('diagnostic_sqlite_witness_mismatch');
        }
        if (databaseDataVersion(this.db) !== observedDataVersion) {
          throw storageError('diagnostic_sqlite_state_unstable');
        }
        this.db.exec('COMMIT');
        this.dataVersion = observedDataVersion;
      } catch (error) {
        try { if (this.db.inTransaction) this.db.exec('ROLLBACK'); } catch {}
        liveError = diagnosticStateFailure(error);
        this.degraded = liveError;
        this.dataVersion = acceptedDataVersion;
      }
    }
    return Object.freeze({
      ready: liveError === null && !fs.existsSync(this.pendingPath),
      productionReady: false,
      degradedCode: liveError ? liveError.code : null,
    });
  }

  async close() {
    await this.tail;
    if (!this.closed) this.db.close();
    this.closed = true;
  }
}

class VendorDiagnosticSqliteTransaction {
  constructor(owner) {
    this.owner = owner;
    this.db = owner.db;
  }

  databaseTimeMs() { return databaseNow(this.db); }

  readTrustedDatabaseTime() {
    return { source: 'database_transaction', timeMs: this.databaseTimeMs() };
  }

  appendAudit(descriptor) {
    verifyAuthenticated(
      this.owner.auditAuthority, AUDIT_DOMAIN, descriptor,
      auditCoreKeys(), 'diagnostic_sqlite_audit_invalid',
    );
    const json = canonical(descriptor);
    const tail = auditTail(this.db);
    const entryHash = sha256(`${tail.head}\0${json}`);
    try {
      this.db.prepare(`
        INSERT INTO vd_audit (
          descriptor_json, previous_hash, entry_hash
        ) VALUES (?, ?, ?)
      `).run(
        json, tail.head, entryHash,
      );
      return clone(descriptor);
    } catch (error) {
      if (error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') return null;
      throw error;
    }
  }

  readAuditDescriptor(eventId) {
    return readAudit(this.db.prepare(
      'SELECT descriptor_json FROM vd_audit WHERE event_id = ?',
    ).get(eventId));
  }

  readLatestStateAudit(query) { return this.readLatestAudit(query); }

  readStateRevisionHighWater(query) {
    const row = this.db.prepare(`
      SELECT MAX(state_revision) AS high_water FROM vd_audit
      WHERE action = ?
        AND customer_id IS ?
        AND deployment_id IS ?
        AND reference_id = ?
    `).get(query.action, query.customerId, query.deploymentId, query.referenceId);
    return row && Number.isSafeInteger(row.high_water) ? row.high_water : null;
  }

  readLatestClaimAudit(query) {
    return this.readLatestAudit({
      customerId: query.customerId,
      deploymentId: query.deploymentId,
      referenceId: query.messageId,
    });
  }

  readLatestCapabilityAudit(query) {
    return this.readLatestAudit({
      action: 'diagnostic_capability_used', referenceId: query.capabilityId,
    });
  }

  readLatestAudit(query) {
    const clauses = [];
    const parameters = [];
    for (const [field, column] of [
      ['action', 'action'], ['customerId', 'customer_id'],
      ['deploymentId', 'deployment_id'], ['referenceId', 'reference_id'],
    ]) {
      if (!Object.hasOwn(query, field)) continue;
      if (query[field] === null) clauses.push(`${column} IS NULL`);
      else { clauses.push(`${column} = ?`); parameters.push(query[field]); }
    }
    const row = this.db.prepare(`
      SELECT descriptor_json FROM vd_audit
      WHERE ${clauses.join(' AND ')} ORDER BY sequence DESC LIMIT 1
    `).get(...parameters);
    return readAudit(row);
  }

  readTimeHighWater() { return this.readDocument('time', 'singleton'); }

  compareAndSwapTimeHighWater(command) {
    return this.compareAndSwapDocument(
      'time', 'singleton', command.expectedRecordDigest, command.nextRecord,
    );
  }

  readDiagnosticAuthorizationState(principalId) {
    return this.readDocument('authorization', principalId);
  }

  readCustomerDiagnosticGrant(query) {
    return this.readDocument('customer_grant', scopeKey(query));
  }

  readDiagnosticConsent(query) { return this.readDocument('consent', scopeKey(query)); }

  readDiagnosticCapabilityClaim(capabilityId) {
    return this.readDocument('capability_claim', capabilityId);
  }

  claimDiagnosticCapability(claim) {
    return this.insertDocument('capability_claim', claim.capabilityId, claim);
  }

  readDiagnosticAccessEvidence(requestDigest) {
    return this.readDocument('access_evidence', requestDigest);
  }

  readDiagnosticAccessRecord(query) {
    const record = this.readDocument('record', claimKey(query));
    if (!record || record.recordType !== 'event'
        || record.customerId !== query.customerId
        || record.deploymentId !== query.deploymentId
        || record.messageId !== query.messageId
        || record.recordDigest !== query.recordDigest) return null;
    return record;
  }

  insertDiagnosticAccessEvidence(requestDigest, evidence) {
    return this.insertDocument('access_evidence', requestDigest, evidence);
  }

  readDiagnosticQuota(query) { return this.readDocument('quota', quotaKey(query)); }

  compareAndSwapDiagnosticQuota(command) {
    return this.compareAndSwapDocument(
      'quota', quotaKey(command), command.expectedRecordDigest, command.nextRecord,
    );
  }

  findDiagnosticClaim(query) { return this.readDocument('record', claimKey(query)); }

  insertDiagnostic(record) { return this.insertDocument('record', claimKey(record), record); }

  readDiagnosticDeletionJob(jobId) { return this.readDocument('deletion_job', jobId); }

  readDiagnosticDeletionReservation(query) {
    const row = this.db.prepare(`
      SELECT document_json FROM vd_deletion_scope
      WHERE customer_id = ? AND deployment_id = ?
    `).get(query.customerId, query.deploymentId);
    return row ? parseCanonical(
      row.document_json, 'diagnostic_sqlite_document_invalid',
    ) : null;
  }

  compareAndSwapDiagnosticDeletionReservation(command) {
    const current = this.db.prepare(`
      SELECT record_digest FROM vd_deletion_scope
      WHERE customer_id = ? AND deployment_id = ?
    `).get(command.customerId, command.deploymentId);
    if ((current ? current.record_digest : null) !== command.expectedRecordDigest
        || command.nextRecord.customerId !== command.customerId
        || command.nextRecord.deploymentId !== command.deploymentId) return null;
    try {
      this.db.prepare(`
        INSERT INTO vd_deletion_scope (
          customer_id, deployment_id, job_id, record_digest, active,
          lease_expires_at, document_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(customer_id, deployment_id) DO UPDATE SET
          job_id = excluded.job_id,
          record_digest = excluded.record_digest,
          active = excluded.active,
          lease_expires_at = excluded.lease_expires_at,
          document_json = excluded.document_json
      `).run(
        command.customerId,
        command.deploymentId,
        command.nextRecord.jobId,
        command.nextRecord.recordDigest,
        command.nextRecord.active ? 1 : 0,
        command.nextRecord.leaseExpiresAt,
        canonical(command.nextRecord),
      );
      return clone(command.nextRecord);
    } catch (error) {
      if (error && String(error.code || '').startsWith('SQLITE_CONSTRAINT')) return null;
      throw error;
    }
  }

  compareAndSwapDiagnosticDeletionJob(command) {
    return this.compareAndSwapDocument(
      'deletion_job', command.jobId, command.expectedRecordDigest, command.nextRecord,
    );
  }

  publishControlState(command) {
    const current = this.readDocument(command.kind, command.key);
    const currentDigest = current ? current.recordDigest : null;
    if (currentDigest !== command.expectedRecordDigest
        || !Number.isSafeInteger(command.record.revision)
        || command.record.revision !== (current ? current.revision + 1 : 1)
        || command.audit.stateRevision !== command.record.revision) {
      throw storageError('diagnostic_sqlite_control_state_conflict');
    }
    const storedAudit = this.appendAudit(command.audit);
    if (storedAudit === null) throw storageError('diagnostic_sqlite_control_state_conflict');
    const stored = this.compareAndSwapDocument(
      command.kind, command.key, command.expectedRecordDigest, command.record,
    );
    if (stored === null) throw storageError('diagnostic_sqlite_control_state_conflict');
    return stored;
  }

  readDocument(kind, key) {
    const row = this.db.prepare(
      'SELECT document_json FROM vd_document WHERE kind = ? AND document_key = ?',
    ).get(kind, key);
    return row ? parseCanonical(row.document_json, 'diagnostic_sqlite_document_invalid') : null;
  }

  insertDocument(kind, key, record) {
    const columns = normalizedDocumentColumns(kind, record);
    try {
      this.db.prepare(`
        INSERT INTO vd_document (
          kind, document_key, record_digest, document_json,
          customer_id, deployment_id, record_type, received_at, message_id,
          expires_at, delete_after, idempotency_until, component,
          diagnostic_code, severity, outcome, occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(kind, key, record.recordDigest, canonical(record), ...columns);
      return clone(record);
    } catch (error) {
      if (error && error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') return null;
      throw error;
    }
  }

  compareAndSwapDocument(kind, key, expectedDigest, record) {
    const current = this.db.prepare(`
      SELECT record_digest FROM vd_document WHERE kind = ? AND document_key = ?
    `).get(kind, key);
    if ((current ? current.record_digest : null) !== expectedDigest) return null;
    const columns = normalizedDocumentColumns(kind, record);
    this.db.prepare(`
      INSERT INTO vd_document (kind, document_key, record_digest, document_json)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(kind, document_key) DO UPDATE SET
        record_digest = excluded.record_digest,
        document_json = excluded.document_json
    `).run(kind, key, record.recordDigest, canonical(record));
    if (kind === 'record') {
      this.db.prepare(`
        UPDATE vd_document SET
          customer_id = ?, deployment_id = ?, record_type = ?, received_at = ?, message_id = ?,
          expires_at = ?, delete_after = ?, idempotency_until = ?, component = ?,
          diagnostic_code = ?, severity = ?, outcome = ?, occurred_at = ?
        WHERE kind = ? AND document_key = ?
      `).run(...columns, kind, key);
    }
    return clone(record);
  }
}

function createVendorDiagnosticSqliteStorage(options) {
  return new VendorDiagnosticSqliteStorage(options);
}

Object.assign(VendorDiagnosticSqliteTransaction.prototype, {
  beginDiagnosticSearchSnapshot(query) {
    const rows = searchRecordRows(this.db, query, true, 1);
    return rows.length ? normalizedPoint(rows[0]) : null;
  },

  searchDiagnostics(query) {
    const rows = searchRecordRows(this.db, query, false, query.limit);
    return { items: rows.map(parseRecordRow) };
  },

  listExpiredDiagnostics(query) {
    return expiredRecords(this, query, 'event', 'expiresAt');
  },

  listExpiredDiagnosticTombstones(query) {
    return expiredRecords(this, query, 'tombstone', 'deleteAfter');
  },

  listExpiredDiagnosticReplayIndexes(query) {
    return expiredRecords(this, query, 'replay', 'idempotencyUntil');
  },

  replaceDiagnosticWithTombstone(command) {
    return replaceRecord(this, command, 'event', 'tombstone');
  },

  replaceDiagnosticTombstoneWithReplay(command) {
    return replaceRecord(this, command, 'tombstone', 'replay');
  },

  deleteDiagnosticReplayIndex(record) {
    const key = claimKey(record);
    const current = this.readDocument('record', key);
    if (!current || current.recordType !== 'replay'
        || canonical(current) !== canonical(record)) return null;
    const result = this.db.prepare(`
      DELETE FROM vd_document
      WHERE kind = 'record' AND document_key = ? AND record_digest = ?
        AND customer_id = ? AND deployment_id = ? AND message_id = ?
    `).run(
      key, record.recordDigest, record.customerId, record.deploymentId, record.messageId,
    );
    return result.changes === 1 ? clone(record) : null;
  },

  previewDiagnosticDeletion(query) {
    const count = this.db.prepare(`
      SELECT COUNT(*) AS count FROM vd_document
      WHERE kind = 'record' AND customer_id = ? AND deployment_id = ?
    `).get(query.customerId, query.deploymentId).count;
    const high = this.db.prepare(`
      SELECT received_at, message_id FROM vd_document
      WHERE kind = 'record' AND customer_id = ? AND deployment_id = ?
      ORDER BY received_at DESC, message_id DESC LIMIT 1
    `).get(query.customerId, query.deploymentId);
    return {
      count,
      snapshotHighWater: high ? normalizedPoint(high) : null,
    };
  },

  listDiagnosticDeletionBatch(command) {
    const job = this.readDocument('deletion_job', command.jobId);
    if (!job || job.recordDigest !== command.expectedJobDigest
        || command.snapshotHighWater === null) return [];
    return deletionRecordRows(this.db, command).map(parseRecordRow);
  },

  listExpiredDiagnosticDeletionReservations(query) {
    const allowed = allowedCustomerSql(query.allowedCustomerIds, 'customer_id');
    return this.db.prepare(`
      SELECT document_json FROM vd_deletion_scope
        INDEXED BY vd_deletion_scope_expired_lease
      WHERE active = 1 AND lease_expires_at <= ? ${allowed.clause}
      ORDER BY lease_expires_at ASC, customer_id ASC, deployment_id ASC
      LIMIT ?
    `).all(iso(query.nowMs), ...allowed.parameters, query.limit).map((row) => (
      parseCanonical(row.document_json, 'diagnostic_sqlite_document_invalid')
    ));
  },

  deleteDiagnosticBatch(command) {
    const job = this.readDocument('deletion_job', command.jobId);
    if (!job || job.recordDigest !== command.expectedJobDigest) return null;
    const remove = this.db.prepare(`
      DELETE FROM vd_document
      WHERE kind = 'record' AND document_key = ? AND record_digest = ?
        AND customer_id = ? AND deployment_id = ? AND message_id = ?
    `);
    for (const record of command.records) {
      const current = this.readDocument('record', claimKey(record));
      if (!current || canonical(current) !== canonical(record)) return null;
    }
    for (const record of command.records) {
      const result = remove.run(
        claimKey(record), record.recordDigest, command.customerId,
        command.deploymentId, record.messageId,
      );
      if (result.changes !== 1) throw storageError('diagnostic_sqlite_delete_conflict');
    }
    return {
      deleted: command.records.map(recordPoint),
      done: command.done,
    };
  },
});

function expiredRecords(tx, query, type, timeField) {
  const plan = {
    expiresAt: { column: 'expires_at', index: 'vd_record_expiry' },
    deleteAfter: { column: 'delete_after', index: 'vd_record_tombstone_expiry' },
    idempotencyUntil: { column: 'idempotency_until', index: 'vd_record_replay_expiry' },
  }[timeField];
  if (!plan) throw storageError('diagnostic_sqlite_query_invalid');
  const allowed = allowedCustomerSql(query.allowedCustomerIds, 'r.customer_id');
  const sql = `
    SELECT r.document_json FROM vd_document r INDEXED BY ${plan.index}
    WHERE r.kind = 'record' AND r.record_type = ?
      AND r.${plan.column} <= ? ${allowed.clause}
      AND NOT EXISTS (
        SELECT 1 FROM vd_deletion_scope d
        WHERE d.active = 1 AND d.customer_id = r.customer_id
          AND d.deployment_id = r.deployment_id
      )
    ORDER BY r.${plan.column} ASC, r.received_at ASC, r.message_id ASC
    LIMIT ?
  `;
  return tx.db.prepare(sql).all(
    type, iso(query.nowMs), ...allowed.parameters, query.limit,
  ).map(parseRecordRow);
}

function searchRecordRows(db, query, descending, limit) {
  const clauses = ["r.kind = 'record'", "r.record_type = 'event'", 'r.expires_at > ?'];
  const parameters = [query.expiresAfter];
  const allowed = allowedCustomerSql(query.allowedCustomerIds, 'r.customer_id');
  if (allowed.clause) {
    clauses.push(allowed.clause.replace(/^\s*AND\s+/, ''));
    parameters.push(...allowed.parameters);
  }
  for (const [field, column] of [
    ['customerId', 'r.customer_id'], ['deploymentId', 'r.deployment_id'],
    ['component', 'r.component'], ['code', 'r.diagnostic_code'],
    ['severity', 'r.severity'], ['outcome', 'r.outcome'],
  ]) {
    if (query.filters[field]) {
      clauses.push(`${column} = ?`);
      parameters.push(query.filters[field]);
    }
  }
  if (query.filters.occurredAfter) {
    clauses.push('r.occurred_at >= ?');
    parameters.push(query.filters.occurredAfter);
  }
  if (query.filters.occurredBefore) {
    clauses.push('r.occurred_at < ?');
    parameters.push(query.filters.occurredBefore);
  }
  if (!descending && query.after) {
    clauses.push('(r.received_at > ? OR (r.received_at = ? AND r.message_id > ?))');
    parameters.push(query.after.receivedAt, query.after.receivedAt, query.after.messageId);
  }
  if (!descending && query.snapshotHighWater) {
    clauses.push('(r.received_at < ? OR (r.received_at = ? AND r.message_id <= ?))');
    parameters.push(
      query.snapshotHighWater.receivedAt,
      query.snapshotHighWater.receivedAt,
      query.snapshotHighWater.messageId,
    );
  }
  const direction = descending ? 'DESC' : 'ASC';
  const searchIndex = query.filters.customerId
    ? (query.filters.deploymentId
      ? 'vd_record_search_deployment' : 'vd_record_search_customer')
    : 'vd_record_search_global';
  return db.prepare(`
    SELECT r.document_json, r.received_at, r.message_id
    FROM vd_document r INDEXED BY ${searchIndex}
    WHERE ${clauses.join(' AND ')}
    ORDER BY r.received_at ${direction}, r.message_id ${direction}
    LIMIT ?
  `).all(...parameters, limit);
}

function deletionRecordRows(db, query) {
  const clauses = [
    "kind = 'record'", 'customer_id = ?', 'deployment_id = ?',
    '(received_at < ? OR (received_at = ? AND message_id <= ?))',
  ];
  const parameters = [
    query.customerId, query.deploymentId,
    query.snapshotHighWater.receivedAt,
    query.snapshotHighWater.receivedAt,
    query.snapshotHighWater.messageId,
  ];
  if (query.after) {
    clauses.push('(received_at > ? OR (received_at = ? AND message_id > ?))');
    parameters.push(query.after.receivedAt, query.after.receivedAt, query.after.messageId);
  }
  return db.prepare(`
    SELECT document_json, received_at, message_id FROM vd_document
    WHERE ${clauses.join(' AND ')}
    ORDER BY received_at ASC, message_id ASC
    LIMIT ?
  `).all(...parameters, query.limit);
}

function allowedCustomerSql(allowed, column) {
  if (allowed === '*') return { clause: '', parameters: [] };
  if (!Array.isArray(allowed) || !allowed.length || allowed.length > 1_000) {
    throw storageError('diagnostic_sqlite_query_invalid');
  }
  return {
    clause: `AND ${column} IN (${allowed.map(() => '?').join(', ')})`,
    parameters: allowed,
  };
}

function parseRecordRow(row) {
  return parseCanonical(row.document_json, 'diagnostic_sqlite_document_invalid');
}

function normalizedPoint(row) {
  return { receivedAt: row.received_at, messageId: row.message_id };
}

function replaceRecord(tx, command, currentType, nextType) {
  const key = claimKey(command.current);
  const current = tx.readDocument('record', key);
  if (!current || current.recordType !== currentType || command.next.recordType !== nextType
      || canonical(current) !== canonical(command.current)
      || claimKey(command.next) !== key) return null;
  return tx.compareAndSwapDocument(
    'record', key, current.recordDigest, command.next,
  );
}

function recordPoint(record) {
  return { receivedAt: record.receivedAt, messageId: record.messageId };
}

function normalizedDocumentColumns(kind, record) {
  if (kind !== 'record') return Array(13).fill(null);
  const payload = record.recordType === 'event' && record.payload ? record.payload : {};
  return [
    record.customerId,
    record.deploymentId,
    record.recordType,
    record.receivedAt,
    record.messageId,
    record.expiresAt || null,
    record.deleteAfter || null,
    record.idempotencyUntil || null,
    payload.component || null,
    payload.code || null,
    payload.severity || null,
    payload.outcome || null,
    payload.occurredAt || null,
  ];
}

function checkedOptions(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw storageError('diagnostic_sqlite_configuration_invalid');
  }
  const allowed = new Set([
    'allowTestWitness', 'auditAuthority', 'backupManifest', 'directory',
    'restoreAuthorization', 'security', 'witnessAuthority', 'witnessIntegrityAuthority',
  ]);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).some((key) => !allowed.has(key))
      || Object.values(descriptors).some((descriptor) => !Object.hasOwn(descriptor, 'value')
        || descriptor.get || descriptor.set || descriptor.enumerable !== true)) {
    throw storageError('diagnostic_sqlite_configuration_invalid');
  }
  const input = Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
  if (typeof input.directory !== 'string' || !path.isAbsolute(input.directory)
      || !input.auditAuthority || typeof input.auditAuthority.sign !== 'function'
      || typeof input.auditAuthority.verify !== 'function'
      || typeof input.auditAuthority.keyId !== 'string'
      || !input.witnessIntegrityAuthority
      || typeof input.witnessIntegrityAuthority.sign !== 'function'
      || typeof input.witnessIntegrityAuthority.verify !== 'function'
      || typeof input.witnessIntegrityAuthority.keyId !== 'string') {
    throw storageError('diagnostic_sqlite_configuration_invalid');
  }
  const directory = path.resolve(input.directory);
  const witnessAuthority = checkedWitnessAuthority(
    input.witnessAuthority, input.allowTestWitness === true,
  );
  if ((input.restoreAuthorization === undefined) !== (input.backupManifest === undefined)) {
    throw storageError('diagnostic_sqlite_configuration_invalid');
  }
  return {
    directory,
    witnessAuthority,
    sourceWitnessAuthority: input.witnessAuthority,
    auditAuthority: Object.freeze({
      keyId: input.auditAuthority.keyId,
      sign: input.auditAuthority.sign.bind(input.auditAuthority),
      verify: input.auditAuthority.verify.bind(input.auditAuthority),
    }),
    witnessIntegrityAuthority: Object.freeze({
      keyId: input.witnessIntegrityAuthority.keyId,
      sign: input.witnessIntegrityAuthority.sign.bind(input.witnessIntegrityAuthority),
      verify: input.witnessIntegrityAuthority.verify.bind(input.witnessIntegrityAuthority),
    }),
    backupManifest: input.backupManifest === undefined ? null : clone(input.backupManifest),
    restoreAuthorization: input.restoreAuthorization === undefined
      ? null : clone(input.restoreAuthorization),
    security: input.security || {},
  };
}

function checkedWitnessAuthority(value, allowTestWitness) {
  const production = isProductionVendorDiagnosticWitnessAuthority(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || typeof value.read !== 'function' || typeof value.compareAndSwap !== 'function'
      || ![PRODUCTION_WITNESS_ASSURANCE, TEST_WITNESS_ASSURANCE].includes(value.assurance)
      || (value.assurance === PRODUCTION_WITNESS_ASSURANCE && !production)
      || (value.assurance === TEST_WITNESS_ASSURANCE && !allowTestWitness)) {
    throw storageError('diagnostic_sqlite_witness_authority_invalid');
  }
  return Object.freeze({
    assurance: value.assurance,
    read: value.read.bind(value),
    compareAndSwap: value.compareAndSwap.bind(value),
  });
}

function openPrivateDatabase(
  directory, databasePath, security, auditAuthority,
  witnessAuthority, witnessIntegrityAuthority,
) {
  let database;
  const previousUmask = process.umask(0o077);
  try {
    privatePaths.withPrivateDirectoryMutationLockSync(directory, () => {
      database = new Database(databasePath);
      database.pragma(`busy_timeout = ${SQLITE_BUSY_TIMEOUT_MS}`);
      database.pragma('journal_mode = DELETE');
      database.pragma('synchronous = FULL');
      database.pragma('foreign_keys = ON');
      migrate(
        database, auditAuthority, witnessAuthority, witnessIntegrityAuthority, databasePath,
      );
      privatePaths.protectInheritedPrivateFile(databasePath, {
        ...security, label: 'vendor diagnostic SQLite database',
      });
    }, {
      ...security,
      label: 'vendor diagnostic SQLite directory',
      ownerLabel: 'vendor diagnostic SQLite store',
      lockTimeoutMs: 60_000,
      lockTimeoutMaximumMs: 60_000,
    });
    return database;
  } catch (error) {
    try { database?.close(); } catch {}
    throw storageError('diagnostic_sqlite_open_failed', error);
  } finally {
    process.umask(previousUmask);
  }
}

function migrate(
  db, auditAuthority, witnessAuthority, witnessIntegrityAuthority, databasePath,
) {
  const version = db.pragma('user_version', { simple: true });
  if (![0, 2, 3, DATABASE_SCHEMA_VERSION].includes(version)) {
    throw storageError('diagnostic_sqlite_schema_unsupported');
  }
  if (version === DATABASE_SCHEMA_VERSION) return;
  if (version === 2 || version === 3) {
    migrateLegacyToV4(
      db, version, auditAuthority, witnessAuthority, witnessIntegrityAuthority, databasePath,
    );
    return;
  }
  db.exec(`
    BEGIN IMMEDIATE;
    CREATE TABLE vd_store (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      store_id TEXT NOT NULL UNIQUE,
      scope_id TEXT NOT NULL UNIQUE
    );
    CREATE TABLE vd_document (
      kind TEXT NOT NULL,
      document_key TEXT NOT NULL,
      record_digest TEXT NOT NULL,
      document_json TEXT NOT NULL,
      customer_id TEXT,
      deployment_id TEXT,
      record_type TEXT,
      received_at TEXT,
      message_id TEXT,
      expires_at TEXT,
      delete_after TEXT,
      idempotency_until TEXT,
      component TEXT,
      diagnostic_code TEXT,
      severity TEXT,
      outcome TEXT,
      occurred_at TEXT,
      PRIMARY KEY (kind, document_key)
    ) WITHOUT ROWID;
    CREATE INDEX vd_document_digest ON vd_document(kind, record_digest);
    CREATE UNIQUE INDEX vd_record_scope_message ON vd_document(
      customer_id, deployment_id, message_id
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_search_global ON vd_document(
      record_type, received_at, message_id, expires_at
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_search_customer ON vd_document(
      customer_id, received_at, message_id, expires_at, deployment_id
    ) WHERE kind = 'record' AND record_type = 'event';
    CREATE INDEX vd_record_search_deployment ON vd_document(
      customer_id, deployment_id, received_at, message_id, expires_at
    ) WHERE kind = 'record' AND record_type = 'event';
    CREATE INDEX vd_record_expiry ON vd_document(
      record_type, expires_at, received_at, message_id, customer_id, deployment_id
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_tombstone_expiry ON vd_document(
      record_type, delete_after, received_at, message_id, customer_id, deployment_id
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_replay_expiry ON vd_document(
      record_type, idempotency_until, received_at, message_id, customer_id, deployment_id
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_filters ON vd_document(
      customer_id, deployment_id, component, diagnostic_code, severity, outcome,
      occurred_at, received_at, message_id
    ) WHERE kind = 'record' AND record_type = 'event';
    CREATE INDEX vd_record_tenant_deletion ON vd_document(
      customer_id, deployment_id, received_at, message_id
    ) WHERE kind = 'record';
    CREATE TABLE vd_deletion_scope (
      customer_id TEXT NOT NULL,
      deployment_id TEXT NOT NULL,
      job_id TEXT NOT NULL UNIQUE,
      record_digest TEXT NOT NULL,
      active INTEGER NOT NULL CHECK (active IN (0, 1)),
      lease_expires_at TEXT,
      document_json TEXT NOT NULL,
      PRIMARY KEY (customer_id, deployment_id)
    ) WITHOUT ROWID;
    CREATE INDEX vd_deletion_scope_active ON vd_deletion_scope(
      active, customer_id, deployment_id
    );
    CREATE INDEX vd_deletion_scope_active_tenant ON vd_deletion_scope(
      customer_id, deployment_id
    ) WHERE active = 1;
    CREATE INDEX vd_deletion_scope_expired_lease ON vd_deletion_scope(
      lease_expires_at, customer_id, deployment_id
    ) WHERE active = 1;
    CREATE TABLE vd_audit (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      descriptor_json TEXT NOT NULL,
      event_id TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.eventId')) STORED
        NOT NULL UNIQUE,
      action TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.action')) STORED NOT NULL,
      customer_id TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.customerId')) STORED,
      deployment_id TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.deploymentId')) STORED,
      reference_id TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.referenceId')) STORED
        NOT NULL,
      state_revision INTEGER GENERATED ALWAYS AS (
        json_extract(descriptor_json, '$.stateRevision')
      ) STORED,
      previous_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL UNIQUE
    );
    CREATE INDEX vd_audit_state_lookup ON vd_audit(
      action, customer_id, deployment_id, reference_id, sequence DESC
    );
    CREATE INDEX vd_audit_claim_lookup ON vd_audit(
      customer_id, deployment_id, reference_id, sequence DESC
    ) WHERE customer_id IS NOT NULL AND deployment_id IS NOT NULL;
    CREATE TRIGGER vd_audit_immutable_update BEFORE UPDATE ON vd_audit
      BEGIN SELECT RAISE(ABORT, 'vendor diagnostic audit is immutable'); END;
    CREATE TRIGGER vd_audit_immutable_delete BEFORE DELETE ON vd_audit
      BEGIN SELECT RAISE(ABORT, 'vendor diagnostic audit is immutable'); END;
    PRAGMA user_version = ${DATABASE_SCHEMA_VERSION};
    COMMIT;
  `);
}

function migrateLegacyToV4(
  db, version, auditAuthority, witnessAuthority, witnessIntegrityAuthority, databasePath,
) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const authenticatedState = verifyLegacyAuthenticatedState(
      db, auditAuthority, witnessAuthority, witnessIntegrityAuthority, databasePath,
    );
    if (version === 2) {
      db.exec(`
        ALTER TABLE vd_deletion_scope ADD COLUMN lease_expires_at TEXT;
        UPDATE vd_deletion_scope
          SET lease_expires_at = json_extract(document_json, '$.leaseExpiresAt');
      `);
    }
    verifyLegacyStateProjections(db);
    verifyLegacyAuditProjections(db, auditAuthority);
    rebuildLegacyAuditAndQueryIndexes(db);
    if (!sameState(
      verifiedStoreState(db, auditAuthority), authenticatedState,
    )) throw storageError('diagnostic_sqlite_state_mismatch');
    db.exec(`PRAGMA user_version = ${DATABASE_SCHEMA_VERSION};`);
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

function verifyLegacyAuthenticatedState(
  db, auditAuthority, witnessAuthority, witnessIntegrityAuthority, databasePath,
) {
  const identity = db.prepare(`
    SELECT store_id AS storeId, scope_id AS scopeId
    FROM vd_store WHERE singleton = 1
  `).get();
  if (!identity || !uuid(identity.storeId) || !uuid(identity.scopeId)) {
    throw storageError('diagnostic_sqlite_store_identity_invalid');
  }
  const instanceBinding = databaseInstanceBinding(databasePath);
  const namespace = storeWitnessNamespace(identity.storeId, instanceBinding);
  let candidate;
  try { candidate = syncWitnessResult(witnessAuthority.read(namespace)); }
  catch (error) { throw storageError('diagnostic_sqlite_witness_uncertain', error); }
  if (candidate === null) throw storageError('diagnostic_sqlite_witness_missing');
  const witness = verifyAuthenticated(
    witnessIntegrityAuthority, WITNESS_DOMAIN, candidate, witnessCoreKeys(),
    'diagnostic_sqlite_witness_invalid',
  );
  validateWitness(witness);
  if (witness.namespace !== namespace || witness.storeId !== identity.storeId
      || witness.scopeId !== identity.scopeId || witness.instanceBinding !== instanceBinding) {
    throw storageError('diagnostic_sqlite_witness_identity_mismatch');
  }
  const state = verifiedStoreState(db, auditAuthority);
  if (sameTail(witness, state) && witness.stateDigest !== state.stateDigest) {
    throw storageError('diagnostic_sqlite_state_mismatch');
  }
  if (!sameState(witness, state)) {
    throw storageError('diagnostic_sqlite_witness_mismatch');
  }
  return state;
}

function verifyLegacyStateProjections(db) {
  for (const row of db.prepare(`
    SELECT kind, document_key, record_digest, document_json,
      customer_id, deployment_id, record_type, received_at, message_id,
      expires_at, delete_after, idempotency_until, component,
      diagnostic_code, severity, outcome, occurred_at
    FROM vd_document
    ORDER BY kind ASC, document_key ASC
  `).iterate()) verifyDocumentProjection(row);
  for (const row of db.prepare(`
    SELECT customer_id, deployment_id, job_id, record_digest, active,
      lease_expires_at, document_json
    FROM vd_deletion_scope ORDER BY customer_id ASC, deployment_id ASC
  `).iterate()) verifyDeletionProjection(row);
}

function verifyLegacyAuditProjections(db, auditAuthority) {
  let sequence = 0;
  let previous = GENESIS_HEAD;
  for (const row of db.prepare(`
    SELECT sequence, event_id, action, customer_id, deployment_id,
      reference_id, state_revision, descriptor_json, previous_hash, entry_hash
    FROM vd_audit ORDER BY sequence ASC
  `).iterate()) {
    sequence += 1;
    if (row.sequence !== sequence) {
      throw storageError('diagnostic_sqlite_audit_chain_invalid');
    }
    verifyAuditRow(auditAuthority, row, previous);
    previous = row.entry_hash;
  }
  verifyAuditSequenceState(db, sequence);
}

function rebuildLegacyAuditAndQueryIndexes(db) {
  db.exec(`
    CREATE TABLE vd_audit_v4 (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      descriptor_json TEXT NOT NULL,
      event_id TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.eventId')) STORED
        NOT NULL UNIQUE,
      action TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.action')) STORED NOT NULL,
      customer_id TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.customerId')) STORED,
      deployment_id TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.deploymentId')) STORED,
      reference_id TEXT GENERATED ALWAYS AS (json_extract(descriptor_json, '$.referenceId')) STORED
        NOT NULL,
      state_revision INTEGER GENERATED ALWAYS AS (
        json_extract(descriptor_json, '$.stateRevision')
      ) STORED,
      previous_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL UNIQUE
    );
    INSERT INTO vd_audit_v4 (sequence, descriptor_json, previous_hash, entry_hash)
      SELECT sequence, descriptor_json, previous_hash, entry_hash
      FROM vd_audit ORDER BY sequence ASC;
    DROP TABLE vd_audit;
    ALTER TABLE vd_audit_v4 RENAME TO vd_audit;
    CREATE INDEX vd_audit_state_lookup ON vd_audit(
      action, customer_id, deployment_id, reference_id, sequence DESC
    );
    CREATE INDEX vd_audit_claim_lookup ON vd_audit(
      customer_id, deployment_id, reference_id, sequence DESC
    ) WHERE customer_id IS NOT NULL AND deployment_id IS NOT NULL;
    CREATE TRIGGER vd_audit_immutable_update BEFORE UPDATE ON vd_audit
      BEGIN SELECT RAISE(ABORT, 'vendor diagnostic audit is immutable'); END;
    CREATE TRIGGER vd_audit_immutable_delete BEFORE DELETE ON vd_audit
      BEGIN SELECT RAISE(ABORT, 'vendor diagnostic audit is immutable'); END;
    DROP INDEX IF EXISTS vd_record_search;
    DROP INDEX IF EXISTS vd_record_search_global;
    DROP INDEX IF EXISTS vd_record_search_customer;
    DROP INDEX IF EXISTS vd_record_search_deployment;
    DROP INDEX IF EXISTS vd_record_expiry;
    DROP INDEX IF EXISTS vd_record_tombstone_expiry;
    DROP INDEX IF EXISTS vd_record_replay_expiry;
    DROP INDEX IF EXISTS vd_record_tenant_deletion;
    DROP INDEX IF EXISTS vd_deletion_scope_active_tenant;
    DROP INDEX IF EXISTS vd_deletion_scope_expired_lease;
    CREATE INDEX vd_record_search_global ON vd_document(
      record_type, received_at, message_id, expires_at
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_search_customer ON vd_document(
      customer_id, received_at, message_id, expires_at, deployment_id
    ) WHERE kind = 'record' AND record_type = 'event';
    CREATE INDEX vd_record_search_deployment ON vd_document(
      customer_id, deployment_id, received_at, message_id, expires_at
    ) WHERE kind = 'record' AND record_type = 'event';
    CREATE INDEX vd_record_expiry ON vd_document(
      record_type, expires_at, received_at, message_id, customer_id, deployment_id
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_tombstone_expiry ON vd_document(
      record_type, delete_after, received_at, message_id, customer_id, deployment_id
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_replay_expiry ON vd_document(
      record_type, idempotency_until, received_at, message_id, customer_id, deployment_id
    ) WHERE kind = 'record';
    CREATE INDEX vd_record_tenant_deletion ON vd_document(
      customer_id, deployment_id, received_at, message_id
    ) WHERE kind = 'record';
    CREATE INDEX vd_deletion_scope_active_tenant ON vd_deletion_scope(
      customer_id, deployment_id
    ) WHERE active = 1;
    CREATE INDEX vd_deletion_scope_expired_lease ON vd_deletion_scope(
      lease_expires_at, customer_id, deployment_id
    ) WHERE active = 1;
  `);
}

function checkedControlState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',')
        !== ['audit', 'expectedRecordDigest', 'key', 'kind', 'record'].sort().join(',')) {
    throw storageError('diagnostic_sqlite_control_state_invalid');
  }
  const action = {
    authorization: 'diagnostic_authorization_state',
    customer_grant: 'diagnostic_customer_grant_state',
    consent: 'diagnostic_consent_state',
  }[value.kind];
  if (!CONTROL_KINDS.has(value.kind) || typeof value.key !== 'string' || !value.key
      || (value.expectedRecordDigest !== null && !hexDigest(value.expectedRecordDigest))
      || !value.record || !hexDigest(value.record.recordDigest)
      || !value.audit || value.audit.operationDigest !== value.record.recordDigest
      || value.audit.resultDigest !== value.record.recordDigest
      || value.audit.eventId !== value.record.auditEventId
      || value.audit.action !== action
      || value.key !== controlStateKey(value.kind, value.record)) {
    throw storageError('diagnostic_sqlite_control_state_invalid');
  }
  return clone(value);
}

function checkedBackupCommand(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).join(',') !== 'backupId' || !uuid(value.backupId)) {
    throw storageError('diagnostic_sqlite_backup_manifest_invalid');
  }
  return { backupId: value.backupId };
}

function checkedRestoreRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'backupManifest,lifetimeMs'
      || !Number.isSafeInteger(value.lifetimeMs) || value.lifetimeMs < 60_000
      || value.lifetimeMs > 24 * 60 * 60 * 1000) {
    throw storageError('diagnostic_sqlite_restore_invalid');
  }
  return { backupManifest: clone(value.backupManifest), lifetimeMs: value.lifetimeMs };
}

function verifiedStoreState(db, auditAuthority) {
  const hash = crypto.createHash('sha256');
  const identity = db.prepare(`
    SELECT singleton, store_id, scope_id FROM vd_store ORDER BY singleton ASC
  `).all();
  hash.update('vd_store\n', 'utf8');
  for (const row of identity) hash.update(canonical(row), 'utf8').update('\n', 'utf8');
  hash.update('vd_document\n', 'utf8');
  for (const row of db.prepare(`
    SELECT kind, document_key, record_digest, document_json,
      customer_id, deployment_id, record_type, received_at, message_id,
      expires_at, delete_after, idempotency_until, component,
      diagnostic_code, severity, outcome, occurred_at
    FROM vd_document
    ORDER BY kind ASC, document_key ASC
  `).iterate()) {
    verifyDocumentProjection(row);
    hash.update(canonical(row), 'utf8').update('\n', 'utf8');
  }
  hash.update('vd_deletion_scope\n', 'utf8');
  const hasLeaseColumn = db.pragma('table_xinfo(vd_deletion_scope)')
    .some((column) => column.name === 'lease_expires_at');
  const leaseProjection = hasLeaseColumn
    ? 'lease_expires_at'
    : "json_extract(document_json, '$.leaseExpiresAt') AS lease_expires_at";
  for (const row of db.prepare(`
    SELECT customer_id, deployment_id, job_id, record_digest, active,
      ${leaseProjection}, document_json
    FROM vd_deletion_scope ORDER BY customer_id ASC, deployment_id ASC
  `).iterate()) {
    verifyDeletionProjection(row);
    hash.update(canonical(row), 'utf8').update('\n', 'utf8');
  }
  hash.update('vd_audit\n', 'utf8');
  let previous = GENESIS_HEAD;
  let sequence = 0;
  for (const row of db.prepare(`
    SELECT sequence, event_id, action, customer_id, deployment_id,
      reference_id, state_revision, descriptor_json, previous_hash, entry_hash
    FROM vd_audit ORDER BY sequence ASC
  `).iterate()) {
    sequence += 1;
    if (row.sequence !== sequence) throw storageError('diagnostic_sqlite_audit_chain_invalid');
    verifyAuditRow(auditAuthority, row, previous);
    previous = row.entry_hash;
    hash.update(canonical(row), 'utf8').update('\n', 'utf8');
  }
  const sequenceState = verifyAuditSequenceState(db, sequence);
  hash.update('sqlite_sequence\n', 'utf8')
    .update(canonical(sequenceState), 'utf8').update('\n', 'utf8');
  return Object.freeze({ sequence, head: previous, stateDigest: hash.digest('hex') });
}

function verifyAuditSequenceState(db, sequence) {
  const state = db.prepare(`
    SELECT name, seq FROM sqlite_sequence WHERE name = 'vd_audit'
  `).get() || null;
  if ((sequence === 0 && state !== null && state.seq !== 0)
      || (sequence > 0 && (!state || state.seq !== sequence))) {
    throw storageError('diagnostic_sqlite_audit_chain_invalid');
  }
  return state;
}

function verifyDocumentProjection(row) {
  const document = parseCanonical(row.document_json, 'diagnostic_sqlite_projection_invalid');
  if (!document || document.recordDigest !== row.record_digest) {
    throw storageError('diagnostic_sqlite_projection_invalid');
  }
  const expected = normalizedDocumentColumns(row.kind, document);
  const actual = [
    row.customer_id, row.deployment_id, row.record_type, row.received_at, row.message_id,
    row.expires_at, row.delete_after, row.idempotency_until, row.component,
    row.diagnostic_code, row.severity, row.outcome, row.occurred_at,
  ];
  if (canonical(actual) !== canonical(expected)) {
    throw storageError('diagnostic_sqlite_projection_invalid');
  }
}

function verifyDeletionProjection(row) {
  const document = parseCanonical(row.document_json, 'diagnostic_sqlite_projection_invalid');
  if (!document || document.recordDigest !== row.record_digest
      || document.customerId !== row.customer_id || document.deploymentId !== row.deployment_id
      || document.jobId !== row.job_id || typeof document.active !== 'boolean'
      || (document.active ? 1 : 0) !== row.active
      || document.leaseExpiresAt !== row.lease_expires_at) {
    throw storageError('diagnostic_sqlite_projection_invalid');
  }
}

function auditTail(db) {
  const row = db.prepare(`
    SELECT sequence, entry_hash FROM vd_audit ORDER BY sequence DESC LIMIT 1
  `).get();
  return row
    ? { sequence: row.sequence, head: row.entry_hash }
    : { sequence: 0, head: GENESIS_HEAD };
}

function verifyAuditRow(authority, row, expectedPrevious) {
  const descriptor = parseCanonical(
    row.descriptor_json, 'diagnostic_sqlite_audit_chain_invalid',
  );
  verifyAuthenticated(
    authority, AUDIT_DOMAIN, descriptor,
    auditCoreKeys(), 'diagnostic_sqlite_audit_chain_invalid',
  );
  if (row.previous_hash !== expectedPrevious
      || row.event_id !== descriptor.eventId || row.action !== descriptor.action
      || row.customer_id !== descriptor.customerId
      || row.deployment_id !== descriptor.deploymentId
      || row.reference_id !== descriptor.referenceId
      || row.state_revision !== descriptor.stateRevision
      || row.entry_hash !== sha256(`${expectedPrevious}\0${row.descriptor_json}`)) {
    throw storageError('diagnostic_sqlite_audit_chain_invalid');
  }
}

function databaseNow(db) {
  const row = db.prepare(`
    SELECT CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) AS time_ms
  `).get();
  if (!row || !Number.isSafeInteger(row.time_ms) || row.time_ms < 0) {
    throw storageError('diagnostic_sqlite_time_invalid');
  }
  return row.time_ms;
}

function databaseDataVersion(db) {
  const value = db.pragma('data_version', { simple: true });
  if (!Number.isSafeInteger(value) || value < 1) {
    throw storageError('diagnostic_sqlite_data_version_invalid');
  }
  return value;
}

function databaseInstanceBinding(databasePath) {
  let stat;
  try { stat = fs.statSync(databasePath, { bigint: true }); }
  catch (error) { throw storageError('diagnostic_sqlite_instance_identity_invalid', error); }
  if (!stat.isFile() || stat.nlink !== 1n || stat.dev <= 0n || stat.ino <= 0n
      || stat.birthtimeNs <= 0n) {
    throw storageError('diagnostic_sqlite_instance_identity_invalid');
  }
  return sha256(canonical({
    deviceId: stat.dev.toString(),
    fileId: stat.ino.toString(),
    createdAtNs: stat.birthtimeNs.toString(),
  }));
}

function readAudit(row) {
  return row
    ? parseCanonical(row.descriptor_json, 'diagnostic_sqlite_audit_invalid')
    : null;
}

function authenticate(authority, domain, core) {
  const recordDigest = sha256(canonical(core));
  const proof = authority.sign(domain, canonical(core));
  const result = { ...clone(core), recordDigest, integrityProof: clone(proof) };
  verifyAuthenticated(authority, domain, result, Object.keys(core), 'diagnostic_sqlite_sign_failed');
  return Object.freeze(result);
}

function verifyAuthenticated(authority, domain, value, coreKeys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw storageError(code);
  const keys = [...coreKeys, 'recordDigest', 'integrityProof'].sort();
  if (Object.keys(value).sort().join(',') !== keys.join(',')) throw storageError(code);
  const core = {};
  for (const key of coreKeys) core[key] = value[key];
  if (!hexDigest(value.recordDigest) || value.recordDigest !== sha256(canonical(core))
      || !value.integrityProof || typeof value.integrityProof.keyId !== 'string'
      || typeof value.integrityProof.mac !== 'string'
      || authority.verify(
        domain, canonical(core), clone(value.integrityProof),
      ) !== true) throw storageError(code);
  return value;
}

function readAuthenticatedSidecar(file, authority, domain, coreKeys, optional) {
  if (!fs.existsSync(file)) {
    if (optional) return null;
    throw storageError('diagnostic_sqlite_sidecar_missing');
  }
  let bytes;
  try {
    bytes = privatePaths.readBoundedRegularFile(file, {
      maxBytes: MAX_SIDECAR_BYTES,
      label: 'vendor diagnostic audit sidecar',
    });
  } catch (error) { throw storageError('diagnostic_sqlite_sidecar_invalid', error); }
  const value = parseCanonical(
    bytes.toString('utf8').trim(), 'diagnostic_sqlite_sidecar_invalid',
  );
  return verifyAuthenticated(
    authority, domain, value, coreKeys, 'diagnostic_sqlite_sidecar_invalid',
  );
}

function writeSidecar(file, value) {
  const directory = path.dirname(file);
  const staged = path.join(
    directory, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.staged`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(staged, 'wx', 0o600);
    fs.writeFileSync(descriptor, `${canonical(value)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    privatePaths.protectInheritedPrivateFile(staged, {
      label: 'vendor diagnostic audit sidecar staging file',
    });
    privatePaths.publishFileDurably(staged, file, {
      label: 'vendor diagnostic audit sidecar',
    });
  } catch (error) {
    if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} }
    try { fs.unlinkSync(staged); } catch {}
    throw storageError('diagnostic_sqlite_sidecar_write_failed', error);
  }
}

function removeSidecar(file) {
  let stat;
  try { stat = fs.lstatSync(file, { bigint: true }); }
  catch (error) {
    if (error && error.code === 'ENOENT') return;
    throw error;
  }
  privatePaths.removeExactPublicationFile(file, stat, {
    label: 'vendor diagnostic audit pending sidecar',
  });
}

function validateCheckpoint(value) {
  if (value.schemaVersion !== SCHEMA_VERSION || value.recordType !== 'audit_checkpoint'
      || !Number.isSafeInteger(value.sequence) || value.sequence < 0
      || !hexDigest(value.head) || !hexDigest(value.stateDigest)
      || !canonicalIso(value.recordedAt)) {
    throw storageError('diagnostic_sqlite_checkpoint_invalid');
  }
}

function validatePending(value) {
  if (value.schemaVersion !== SCHEMA_VERSION || value.recordType !== 'pending_commit'
      || !uuid(value.transactionId) || !uuid(value.storeId) || !uuid(value.scopeId)
      || !Number.isSafeInteger(value.baseSequence)
      || !Number.isSafeInteger(value.finalSequence) || value.baseSequence < 0
      || value.finalSequence < value.baseSequence || !hexDigest(value.baseHead)
      || !hexDigest(value.baseStateDigest) || !hexDigest(value.finalHead)
      || !hexDigest(value.finalStateDigest) || !canonicalIso(value.recordedAt)) {
    throw storageError('diagnostic_sqlite_pending_invalid');
  }
}

function validateWitness(value) {
  if (value.schemaVersion !== SCHEMA_VERSION
      || value.recordType !== 'diagnostic_monotonic_witness'
      || value.namespace !== storeWitnessNamespace(value.storeId, value.instanceBinding)
      || !uuid(value.storeId) || !uuid(value.scopeId)
      || !hexDigest(value.instanceBinding)
      || !Number.isSafeInteger(value.generation) || value.generation < 1
      || !Number.isSafeInteger(value.sequence) || value.sequence < 0
      || !hexDigest(value.head) || !hexDigest(value.stateDigest)
      || (value.previousWitnessDigest !== null && !hexDigest(value.previousWitnessDigest))
      || (value.restoreAuthorizationDigest !== null
        && !hexDigest(value.restoreAuthorizationDigest))
      || !canonicalIso(value.recordedAt)) {
    throw storageError('diagnostic_sqlite_witness_invalid');
  }
}

function verifyBackupManifest(authority, value) {
  const record = verifyAuthenticated(
    authority, BACKUP_DOMAIN, value, backupCoreKeys(),
    'diagnostic_sqlite_backup_manifest_invalid',
  );
  if (record.schemaVersion !== SCHEMA_VERSION
      || record.recordType !== 'diagnostic_backup_manifest'
      || !uuid(record.backupId) || !uuid(record.sourceStoreId)
      || !uuid(record.sourceScopeId) || !Number.isSafeInteger(record.sequence)
      || record.sequence < 0 || !hexDigest(record.head) || !hexDigest(record.stateDigest)
      || !canonicalIso(record.createdAt)) {
    throw storageError('diagnostic_sqlite_backup_manifest_invalid');
  }
  return record;
}

function verifyRestoreAuthorization(authority, value) {
  const record = verifyAuthenticated(
    authority, RESTORE_DOMAIN, value, restoreCoreKeys(),
    'diagnostic_sqlite_restore_invalid',
  );
  if (record.schemaVersion !== SCHEMA_VERSION
      || record.recordType !== 'diagnostic_restore_authorization'
      || !uuid(record.authorizationId) || !hexDigest(record.backupManifestDigest)
      || !uuid(record.sourceStoreId) || !uuid(record.sourceScopeId)
      || !Number.isSafeInteger(record.sourceSequence) || record.sourceSequence < 0
      || !hexDigest(record.sourceHead) || !uuid(record.destinationStoreId)
      || !uuid(record.destinationScopeId)
      || record.destinationStoreId === record.sourceStoreId
      || record.destinationScopeId === record.sourceScopeId
      || !canonicalIso(record.issuedAt) || !canonicalIso(record.expiresAt)
      || Date.parse(record.expiresAt) <= Date.parse(record.issuedAt)) {
    throw storageError('diagnostic_sqlite_restore_invalid');
  }
  return record;
}

function checkpointCoreKeys() {
  return ['schemaVersion', 'recordType', 'sequence', 'head', 'stateDigest', 'recordedAt'];
}

function pendingCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'transactionId', 'storeId', 'scopeId',
    'baseSequence', 'baseHead', 'baseStateDigest',
    'finalSequence', 'finalHead', 'finalStateDigest', 'recordedAt',
  ];
}

function witnessCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'namespace', 'storeId', 'scopeId', 'generation',
    'instanceBinding',
    'sequence', 'head', 'stateDigest', 'previousWitnessDigest',
    'restoreAuthorizationDigest', 'recordedAt',
  ];
}

function restoreClaimCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'namespace', 'authorizationId',
    'authorizationDigest', 'backupManifestDigest', 'sourceStoreId', 'sourceScopeId',
    'sourceSequence', 'sourceHead', 'destinationStoreId', 'destinationScopeId',
    'resultWitnessDigest', 'claimedAt',
  ];
}

function backupCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'backupId', 'sourceStoreId', 'sourceScopeId',
    'sequence', 'head', 'stateDigest', 'createdAt',
  ];
}

function restoreCoreKeys() {
  return [
    'schemaVersion', 'recordType', 'authorizationId', 'backupManifestDigest',
    'sourceStoreId', 'sourceScopeId', 'sourceSequence', 'sourceHead',
    'destinationStoreId', 'destinationScopeId', 'issuedAt', 'expiresAt',
  ];
}

function auditCoreKeys() {
  return [
    'schemaVersion', 'eventId', 'action', 'customerId', 'deploymentId',
    'referenceId', 'operationDigest', 'resultDigest', 'resultCount',
    'stateRevision', 'recordedAt',
  ];
}

function sameTail(left, right) {
  return left.sequence === right.sequence && left.head === right.head;
}

function sameState(left, right) {
  return Boolean(left && right && sameTail(left, right)
    && hexDigest(left.stateDigest) && left.stateDigest === right.stateDigest);
}

function createWitnessRecord(
  authority, identity, tail, generation, previousWitnessDigest,
  restoreAuthorizationDigest, recordedAt, instanceBinding,
) {
  return authenticate(authority, WITNESS_DOMAIN, {
    schemaVersion: SCHEMA_VERSION,
    recordType: 'diagnostic_monotonic_witness',
    namespace: storeWitnessNamespace(identity.storeId, instanceBinding),
    storeId: identity.storeId,
    scopeId: identity.scopeId,
    instanceBinding,
    generation,
    sequence: tail.sequence,
    head: tail.head,
    stateDigest: tail.stateDigest,
    previousWitnessDigest,
    restoreAuthorizationDigest,
    recordedAt,
  });
}

function syncWitnessResult(value) {
  if (value && typeof value.then === 'function') {
    throw storageError('diagnostic_sqlite_witness_async_unsupported');
  }
  return value === null ? null : clone(value);
}

function sameAuthenticatedRecord(left, right) {
  return Boolean(left && right && left.recordDigest === right.recordDigest
    && canonical(left) === canonical(right));
}

function storeWitnessNamespace(storeId, instanceBinding) {
  return `vendor-diagnostics:store:${storeId}:instance:${instanceBinding}`;
}
function restoreClaimNamespace(authorizationId) {
  return `vendor-diagnostics:restore-authorization:${authorizationId}`;
}

function parseCanonical(value, code) {
  try {
    const parsed = JSON.parse(value);
    if (canonical(parsed) !== value) throw new Error('noncanonical JSON');
    return parsed;
  } catch (error) { throw storageError(code, error); }
}

function canonical(value) { return protocol.canonicalJson(value); }
function clone(value) { return JSON.parse(canonical(value)); }
function sha256(value) { return crypto.createHash('sha256').update(value, 'utf8').digest('hex'); }
function hexDigest(value) { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
function uuid(value) {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
function canonicalIso(value) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}
function iso(value) { return new Date(value).toISOString(); }
function opaqueKey(value) { return sha256(canonical(value)); }
function scopeKey(value) { return opaqueKey([value.customerId, value.deploymentId]); }
function claimKey(value) { return opaqueKey([value.customerId, value.deploymentId, value.messageId]); }
function quotaKey(value) { return opaqueKey([value.customerId, value.deploymentId, value.day]); }
function controlStateKey(kind, record) {
  if (kind === 'authorization') return record.principalId;
  if (kind === 'customer_grant' || kind === 'consent') return scopeKey(record);
  throw storageError('diagnostic_sqlite_control_state_invalid');
}

function diagnosticStateFailure(error) {
  return error && typeof error.code === 'string'
    && error.code.startsWith('diagnostic_sqlite_')
    ? error
    : storageError('diagnostic_sqlite_state_validation_failed', error);
}

function storageError(code, cause) {
  const error = new Error('vendor diagnostic SQLite storage rejected');
  error.code = code;
  if (cause) error.cause = cause;
  return error;
}

function assertReferenceRuntime() {
  if (String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production') {
    throw storageError('vendor_diagnostic_reference_runtime_forbidden');
  }
}

module.exports = {
  BACKUP_DOMAIN,
  CHECKPOINT_DOMAIN,
  PENDING_DOMAIN,
  DATABASE_FILE,
  CHECKPOINT_FILE,
  PENDING_FILE,
  RESTORE_DOMAIN,
  RESTORE_CLAIM_DOMAIN,
  PRODUCTION_WITNESS_ASSURANCE,
  TEST_WITNESS_ASSURANCE,
  WITNESS_DOMAIN,
  controlStateKey,
  createVendorDiagnosticSqliteStorage,
};
