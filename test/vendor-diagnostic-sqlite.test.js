'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const Database = require('better-sqlite3');
const privatePaths = require('../server/private-path');
const protocol = require('../server/vendor-control-protocol');
const {
  AUTHORITY_DEFINITIONS,
} = require('../server/vendor-signed-artifact');
const {
  AUDIT_DOMAIN,
  AUTHORIZATION_DOMAIN,
  CAPABILITY_DOMAIN,
  CONSENT_DOMAIN,
  CUSTOMER_GRANT_DOMAIN,
  DELETION_INTENT_DOMAIN,
  OWNER_AUTH_ASSERTION_DOMAIN,
} = require('../server/vendor-diagnostic-intelligence');
const {
  createVendorDiagnosticKeyFactory,
  PURPOSES,
  RESERVED_PURPOSES,
} = require('../server/vendor-diagnostic-key-factory');
const {
  createCustomerDeletionIntentKeyRegistry,
  deletionIntentSigningInput,
} = require('../server/vendor-diagnostic-customer-key-registry');
const {
  createVendorDiagnosticRuntime,
} = require('../server/vendor-diagnostic-runtime');
const {
  CHECKPOINT_FILE,
  DATABASE_FILE,
  PENDING_DOMAIN,
  PENDING_FILE,
  WITNESS_DOMAIN,
  createVendorDiagnosticSqliteStorage,
} = require('../server/vendor-diagnostic-sqlite');
const {
  FileDiagnosticWitness,
  ReferenceDiagnosticWitness,
  authenticate,
  canonical,
  digest,
  stateAudit,
} = require('./support/vendor-diagnostic-reference-adapter');

const WORKER = path.join(__dirname, 'support', 'vendor-diagnostic-sqlite-worker.js');
const CUSTOMER = 'cu-sqlite-diagnostic';
const DEPLOYMENT = 'dep_33333333333333333333333333333333';
const PRINCIPAL = Object.freeze({
  principalId: '70000000-0000-4000-8000-000000000001',
  principalType: 'connector',
  sessionId: '71000000-0000-4000-8000-000000000001',
});
const VENDOR = Object.freeze({
  principalId: '72000000-0000-4000-8000-000000000001',
  principalType: 'vendor',
  sessionId: '73000000-0000-4000-8000-000000000001',
});
const LEGACY_V2_SCHEMA = `
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
  CREATE INDEX vd_record_search ON vd_document(
    record_type, customer_id, deployment_id, received_at, message_id
  ) WHERE kind = 'record';
  CREATE INDEX vd_record_expiry ON vd_document(
    record_type, expires_at, customer_id, deployment_id, received_at, message_id
  ) WHERE kind = 'record';
  CREATE INDEX vd_record_tombstone_expiry ON vd_document(
    record_type, delete_after, customer_id, deployment_id, received_at, message_id
  ) WHERE kind = 'record';
  CREATE INDEX vd_record_replay_expiry ON vd_document(
    record_type, idempotency_until, customer_id, deployment_id, received_at, message_id
  ) WHERE kind = 'record';
  CREATE INDEX vd_record_filters ON vd_document(
    customer_id, deployment_id, component, diagnostic_code, severity, outcome,
    occurred_at, received_at, message_id
  ) WHERE kind = 'record' AND record_type = 'event';
  CREATE TABLE vd_deletion_scope (
    customer_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    job_id TEXT NOT NULL UNIQUE,
    record_digest TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    document_json TEXT NOT NULL,
    PRIMARY KEY (customer_id, deployment_id)
  ) WITHOUT ROWID;
  CREATE INDEX vd_deletion_scope_active ON vd_deletion_scope(
    active, customer_id, deployment_id
  );
  CREATE TABLE vd_audit (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL,
    customer_id TEXT,
    deployment_id TEXT,
    reference_id TEXT NOT NULL,
    state_revision INTEGER,
    descriptor_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE
  );
  CREATE INDEX vd_audit_state_lookup ON vd_audit(
    action, customer_id, deployment_id, reference_id, sequence DESC
  );
  PRAGMA user_version = 2;
`;
const LEGACY_V3_SCHEMA = `
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
  CREATE INDEX vd_record_search ON vd_document(
    record_type, customer_id, deployment_id, received_at, message_id
  ) WHERE kind = 'record';
  CREATE INDEX vd_record_expiry ON vd_document(
    record_type, expires_at, customer_id, deployment_id, received_at, message_id
  ) WHERE kind = 'record';
  CREATE INDEX vd_record_tombstone_expiry ON vd_document(
    record_type, delete_after, customer_id, deployment_id, received_at, message_id
  ) WHERE kind = 'record';
  CREATE INDEX vd_record_replay_expiry ON vd_document(
    record_type, idempotency_until, customer_id, deployment_id, received_at, message_id
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
    event_id TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL,
    customer_id TEXT,
    deployment_id TEXT,
    reference_id TEXT NOT NULL,
    state_revision INTEGER,
    descriptor_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE
  );
  CREATE INDEX vd_audit_state_lookup ON vd_audit(
    action, customer_id, deployment_id, reference_id, sequence DESC
  );
  CREATE INDEX vd_audit_claim_lookup ON vd_audit(
    customer_id, deployment_id, reference_id, sequence DESC
  ) WHERE customer_id IS NOT NULL AND deployment_id IS NOT NULL;
  PRAGMA user_version = 3;
`;

function keyBytes(label) {
  return crypto.createHash('sha256').update(`sqlite diagnostic:${label}`).digest();
}

function keyFactoryConfiguration() {
  const ownerAuthorityManifest = Object.fromEntries(RESERVED_PURPOSES.map((purpose) => [
    purpose,
    sqliteOwnerRecord(purpose),
  ]));
  const keys = Object.fromEntries(PURPOSES.map((purpose) => [purpose, {
      current: {
        keyId: purpose === 'integrity'
          ? `rw-diagnostic-integrity-${crypto.createHash('sha256')
            .update(keyBytes('integrity.current')).digest('hex')}`
          : `${purpose.toLowerCase()}.sqlite-current`,
        key: keyBytes(`${purpose}.current`).toString('base64'),
      },
      verifyOnly: [],
    }]));
  ownerAuthorityManifest.diagnostic_integrity = {
    keyId: keys.integrity.current.keyId,
    identity: crypto.createHash('sha256').update(keyBytes('integrity.current')).digest('hex'),
  };
  return {
    keys,
    ownerAuthorityManifest,
    requiredVerifyHorizonMs: 120 * 24 * 60 * 60 * 1000,
  };
}

function sqliteOwnerRecord(purpose) {
  const identity = crypto.createHash('sha256')
    .update(keyBytes(`owner.${purpose}`)).digest('hex');
  const prefix = AUTHORITY_DEFINITIONS[purpose].keyPrefix;
  return {
    keyId: ['entitlement', 'online_verdict'].includes(purpose)
      ? `${prefix}${identity}` : `${prefix}sqlite-current`,
    identity,
  };
}

function signedAudit(authority, descriptor) {
  return authenticate(authority, AUDIT_DOMAIN, descriptor);
}

function deletionKeyConfiguration(nowMs) {
  const pair = crypto.generateKeyPairSync('ed25519');
  const keyId = 'customer-delete.sqlite-current';
  const entries = [{
    customerId: CUSTOMER,
    deploymentId: DEPLOYMENT,
    current: {
      keyId,
      publicKey: pair.publicKey.export({ format: 'pem', type: 'spki' }),
      validFrom: new Date(nowMs - 24 * 60 * 60 * 1000).toISOString(),
    },
    verifyOnly: [],
  }];
  return {
    entries,
    keyId,
    privateKey: pair.privateKey,
    registry: createCustomerDeletionIntentKeyRegistry({ entries, now: Date.now }),
  };
}

function signedDeletionIntent(configuration, core) {
  const message = canonical(core);
  return {
    ...core,
    keyId: configuration.keyId,
    recordDigest: digest(core),
    signature: crypto.sign(
      null,
      deletionIntentSigningInput(DELETION_INTENT_DOMAIN, configuration.keyId, message),
      configuration.privateKey,
    ).toString('base64'),
  };
}

function stableConsentReference() {
  return digest({
    kind: 'vendor_diagnostic_consent',
    customerId: CUSTOMER,
    deploymentId: DEPLOYMENT,
    channel: 'diagnostics',
  });
}

async function publishControlStates(runtime, factory, nowMs) {
  const access = factory.authority('access');
  const audit = factory.authority('audit');
  const customerGrant = factory.authority('customerGrant');
  const integrity = factory.authority('integrity');
  const authorization = authenticate(access, AUTHORIZATION_DOMAIN, {
    schemaVersion: 1,
    recordType: 'authorization_state',
    principalId: PRINCIPAL.principalId,
    principalType: PRINCIPAL.principalType,
    revision: 1,
    ownerAuthEventId: crypto.randomUUID(),
    issuer: 'owner-platform',
    credentialPurpose: 'connector_credential',
    credentialVersion: 1,
    revocationRevision: 0,
    status: 'active',
    updatedAt: new Date(nowMs - 1_000).toISOString(),
    expiresAt: new Date(nowMs + 24 * 60 * 60 * 1000).toISOString(),
    auditEventId: crypto.randomUUID(),
  });
  await runtime.publishControlState({
    kind: 'authorization', expectedRecordDigest: null, record: authorization,
    audit: signedAudit(audit, stateAudit(authorization, 'diagnostic_authorization_state', {
      customerId: null, deploymentId: null, referenceId: PRINCIPAL.principalId,
    })),
  });
  const grant = authenticate(customerGrant, CUSTOMER_GRANT_DOMAIN, {
    schemaVersion: 1,
    recordType: 'customer_grant',
    channel: 'diagnostics',
    grantId: crypto.randomUUID(),
    customerId: CUSTOMER,
    deploymentId: DEPLOYMENT,
    enabled: true,
    revision: 1,
    revocationRevision: 0,
    issuedAt: new Date(nowMs - 1_000).toISOString(),
    expiresAt: new Date(nowMs + 24 * 60 * 60 * 1000).toISOString(),
    auditEventId: crypto.randomUUID(),
  });
  await runtime.publishControlState({
    kind: 'customer_grant', expectedRecordDigest: null, record: grant,
    audit: signedAudit(audit, stateAudit(grant, 'diagnostic_customer_grant_state', {
      customerId: CUSTOMER,
      deploymentId: DEPLOYMENT,
      referenceId: stableConsentReference(),
    })),
  });
  const consent = authenticate(integrity, CONSENT_DOMAIN, {
    schemaVersion: 1,
    recordType: 'consent_state',
    channel: 'diagnostics',
    consentId: crypto.randomUUID(),
    customerId: CUSTOMER,
    deploymentId: DEPLOYMENT,
    enabled: true,
    expiresAt: new Date(nowMs + 24 * 60 * 60 * 1000).toISOString(),
    retentionDays: 30,
    revision: 1,
    revocationRevision: 0,
    updatedAt: new Date(nowMs - 1_000).toISOString(),
    usePolicy: 'support_security_only',
    customerGrantId: grant.grantId,
    customerGrantDigest: grant.recordDigest,
    customerGrantRevision: grant.revision,
    customerGrantRevocationRevision: grant.revocationRevision,
    auditEventId: crypto.randomUUID(),
  });
  await runtime.publishControlState({
    kind: 'consent', expectedRecordDigest: null, record: consent,
    audit: signedAudit(audit, stateAudit(consent, 'diagnostic_consent_state', {
      customerId: CUSTOMER,
      deploymentId: DEPLOYMENT,
      referenceId: stableConsentReference(),
    })),
  });
  return { authorization, grant, consent };
}

function capability(factory, authorization, nowMs) {
  return authenticate(factory.authority('access'), CAPABILITY_DOMAIN, {
    schemaVersion: 1,
    recordType: 'capability',
    capabilityId: crypto.randomUUID(),
    principalId: PRINCIPAL.principalId,
    sessionId: PRINCIPAL.sessionId,
    principalType: PRINCIPAL.principalType,
    purpose: 'diagnostic:ingest',
    customerIds: [CUSTOMER],
    deploymentId: DEPLOYMENT,
    ownerAuthEventId: authorization.ownerAuthEventId,
    ownerAuthAssertion: null,
    issuer: authorization.issuer,
    credentialPurpose: authorization.credentialPurpose,
    credentialVersion: authorization.credentialVersion,
    authorizationRevision: authorization.revision,
    issuedAt: new Date(nowMs - 1_000).toISOString(),
    expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
    stepUpAt: null,
    supportCaseId: null,
    approvalId: null,
  });
}

function vendorCapability(factory, authorization, purpose, nowMs, overrides = {}) {
  const ownerAuthAssertion = authenticate(
    factory.authority('ownerAuth'), OWNER_AUTH_ASSERTION_DOMAIN, {
      schemaVersion: 1,
      recordType: 'owner_auth_assertion',
      assertionId: crypto.randomUUID(),
      principalId: VENDOR.principalId,
      sessionId: VENDOR.sessionId,
      ownerAuthEventId: authorization.ownerAuthEventId,
      mfaEventId: crypto.randomUUID(),
      issuer: authorization.issuer,
      credentialVersion: authorization.credentialVersion,
      authenticatedAt: new Date(nowMs - 1_000).toISOString(),
      mfaAt: new Date(nowMs - 1_000).toISOString(),
      expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
    },
  );
  return authenticate(factory.authority('access'), CAPABILITY_DOMAIN, {
    schemaVersion: 1,
    recordType: 'capability',
    capabilityId: crypto.randomUUID(),
    principalId: VENDOR.principalId,
    sessionId: VENDOR.sessionId,
    principalType: VENDOR.principalType,
    purpose,
    customerIds: [CUSTOMER],
    deploymentId: null,
    ownerAuthEventId: authorization.ownerAuthEventId,
    ownerAuthAssertion,
    issuer: authorization.issuer,
    credentialPurpose: authorization.credentialPurpose,
    credentialVersion: authorization.credentialVersion,
    authorizationRevision: authorization.revision,
    issuedAt: new Date(nowMs - 1_000).toISOString(),
    expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
    stepUpAt: new Date(nowMs - 1_000).toISOString(),
    supportCaseId: null,
    approvalId: null,
    ...overrides,
  });
}

function payload(nowMs) {
  return {
    schemaVersion: 1,
    messageId: crypto.randomUUID(),
    customerId: CUSTOMER,
    deploymentId: DEPLOYMENT,
    kind: protocol.CHANNEL_KINDS.DIAGNOSTIC,
    correlationId: crypto.randomUUID(),
    component: 'connector',
    code: 'CONNECTOR_TIMEOUT',
    severity: 'warning',
    outcome: 'retrying',
    countBucket: '2-5',
    sizeBucket: 'none',
    durationBucket: '1-5s',
    retryState: 'scheduled',
    componentVersion: '2.0.0',
    occurredAt: new Date(nowMs - 1_000).toISOString(),
  };
}

function storageAudit(factory, label) {
  return signedAudit(factory.authority('audit'), {
    schemaVersion: 1,
    eventId: crypto.randomUUID(),
    action: 'diagnostics_viewed',
    customerId: CUSTOMER,
    deploymentId: DEPLOYMENT,
    referenceId: crypto.randomUUID(),
    operationDigest: digest({ label, operation: 'test' }),
    resultDigest: digest({ label, result: 'prompt-free' }),
    resultCount: 0,
    stateRevision: null,
    recordedAt: new Date().toISOString(),
  });
}

function openStorage(root, factory, overrides = {}) {
  const witnessAuthority = overrides.witnessAuthority
    || new FileDiagnosticWitness(overrides.witnessDirectory || path.join(root, 'witness'));
  const storageOverrides = { ...overrides };
  delete storageOverrides.witnessDirectory;
  delete storageOverrides.witnessAuthority;
  return createVendorDiagnosticSqliteStorage({
    directory: path.join(root, 'private'),
    allowTestWitness: true,
    auditAuthority: factory.authority('audit'),
    witnessAuthority,
    witnessIntegrityAuthority: factory.authority('diagnosticWitness'),
    ...storageOverrides,
  });
}

async function appendStorageAudit(storage, factory, label) {
  const audit = storageAudit(factory, label);
  const result = await storage.transaction((tx) => tx.appendAudit(audit));
  assert.deepEqual(result, audit);
  return audit;
}

function createLegacyEventRecord(nowMs) {
  const receivedAt = new Date(nowMs - 60_000).toISOString();
  const core = {
    schemaVersion: 1, recordType: 'event', customerId: CUSTOMER, deploymentId: DEPLOYMENT,
    receivedAt, messageId: crypto.randomUUID(),
    expiresAt: new Date(nowMs + 24 * 60 * 60 * 1000).toISOString(),
    deleteAfter: new Date(nowMs + 48 * 60 * 60 * 1000).toISOString(),
    idempotencyUntil: new Date(nowMs + 60 * 60 * 1000).toISOString(),
    payload: {
      component: 'connector', code: 'LEGACY_MIGRATION_FIXTURE', severity: 'warning',
      outcome: 'retrying', occurredAt: receivedAt,
    },
  };
  return { ...core, recordDigest: digest(core) };
}

function createLegacyDeletionReservation(nowMs) {
  const core = {
    schemaVersion: 1,
    recordType: 'deletion_reservation',
    customerId: CUSTOMER,
    deploymentId: DEPLOYMENT,
    jobId: crypto.randomUUID(),
    active: true,
    leaseExpiresAt: new Date(nowMs + 60 * 60 * 1000).toISOString(),
  };
  return { ...core, recordDigest: digest(core) };
}

function createLegacyMigrationFixture(root, factory, version, mutate = null) {
  assert.equal(version === 2 || version === 3, true);
  const nowMs = Date.now();
  const documentKey = digest({ root, kind: 'legacy-migration-document' });
  const evidenceCore = {
    schemaVersion: 1,
    recordType: 'access_evidence',
    fixtureId: crypto.randomUUID(),
  };
  const evidence = { ...evidenceCore, recordDigest: digest(evidenceCore) };
  const record = createLegacyEventRecord(nowMs);
  const reservation = createLegacyDeletionReservation(nowMs);
  const audit = storageAudit(factory, `legacy-v${version}`);
  const auditJson = canonical(audit);
  const entryHash = crypto.createHash('sha256')
    .update(`${'0'.repeat(64)}\0${auditJson}`, 'utf8').digest('hex');
  const identity = { storeId: crypto.randomUUID(), scopeId: crypto.randomUUID() };
  const databasePath = path.join(root, 'private', DATABASE_FILE);
  const fixture = {
    audit, auditJson, databasePath, documentKey, entryHash, evidence,
    identity, record, reservation, version,
  };
  createFrozenLegacyDatabase(fixture, mutate);
  fixture.witnessAuthority = createLegacyFixtureWitness(factory, fixture);
  return fixture;
}

function createFrozenLegacyDatabase(fixture, mutate) {
  const directory = path.dirname(fixture.databasePath);
  privatePaths.withPrivateDirectoryMutationLockSync(directory, () => {
    writeFrozenLegacyDatabase(fixture, mutate);
    privatePaths.protectInheritedPrivateFile(fixture.databasePath, {
      label: `vendor diagnostic frozen v${fixture.version} fixture`,
    });
  }, {
    label: `vendor diagnostic frozen v${fixture.version} fixture directory`,
    ownerLabel: 'vendor diagnostic frozen migration fixture',
    lockTimeoutMs: 60_000,
    lockTimeoutMaximumMs: 60_000,
  });
}

function writeFrozenLegacyDatabase(fixture, mutate) {
  const db = new Database(fixture.databasePath);
  db.exec('BEGIN IMMEDIATE');
  try {
    db.exec(fixture.version === 2 ? LEGACY_V2_SCHEMA : LEGACY_V3_SCHEMA);
    insertFrozenLegacyRows(db, fixture);
    fixture.stateDigest = frozenLegacyStateDigest(db);
    if (typeof mutate === 'function') mutate(db);
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    throw error;
  } finally {
    db.close();
  }
}

function insertFrozenLegacyRows(db, fixture) {
  db.prepare(`
    INSERT INTO vd_store (singleton, store_id, scope_id) VALUES (1, ?, ?)
  `).run(fixture.identity.storeId, fixture.identity.scopeId);
  const insertDocument = db.prepare(`
    INSERT INTO vd_document (
      kind, document_key, record_digest, document_json,
      customer_id, deployment_id, record_type, received_at, message_id,
      expires_at, delete_after, idempotency_until, component,
      diagnostic_code, severity, outcome, occurred_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertDocument.run(
    'access_evidence', fixture.documentKey, fixture.evidence.recordDigest,
    canonical(fixture.evidence), ...Array(13).fill(null),
  );
  const record = fixture.record;
  insertDocument.run(
    'record', digest([record.customerId, record.deploymentId, record.messageId]),
    record.recordDigest, canonical(record), record.customerId, record.deploymentId,
    record.recordType, record.receivedAt, record.messageId, record.expiresAt,
    record.deleteAfter, record.idempotencyUntil, record.payload.component,
    record.payload.code, record.payload.severity, record.payload.outcome,
    record.payload.occurredAt,
  );
  insertFrozenDeletionRow(db, fixture);
  insertFrozenAuditRow(db, fixture);
}

function insertFrozenDeletionRow(db, fixture) {
  const columns = fixture.version === 2
    ? 'customer_id, deployment_id, job_id, record_digest, active, document_json'
    : `customer_id, deployment_id, job_id, record_digest, active,
      lease_expires_at, document_json`;
  const values = fixture.version === 2 ? '?, ?, ?, ?, ?, ?' : '?, ?, ?, ?, ?, ?, ?';
  const parameters = [
    CUSTOMER, DEPLOYMENT, fixture.reservation.jobId,
    fixture.reservation.recordDigest, 1,
  ];
  if (fixture.version === 3) parameters.push(fixture.reservation.leaseExpiresAt);
  parameters.push(canonical(fixture.reservation));
  db.prepare(`INSERT INTO vd_deletion_scope (${columns}) VALUES (${values})`).run(...parameters);
}

function insertFrozenAuditRow(db, fixture) {
  db.prepare(`
    INSERT INTO vd_audit (
      sequence, event_id, action, customer_id, deployment_id, reference_id,
      state_revision, descriptor_json, previous_hash, entry_hash
    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    fixture.audit.eventId, fixture.audit.action, fixture.audit.customerId,
    fixture.audit.deploymentId, fixture.audit.referenceId, fixture.audit.stateRevision,
    fixture.auditJson, '0'.repeat(64), fixture.entryHash,
  );
}

function frozenLegacyStateDigest(db) {
  const hash = crypto.createHash('sha256');
  const appendRows = (label, rows) => {
    hash.update(`${label}\n`, 'utf8');
    for (const row of rows) hash.update(canonical(row), 'utf8').update('\n', 'utf8');
  };
  appendRows('vd_store', db.prepare(`
    SELECT singleton, store_id, scope_id FROM vd_store ORDER BY singleton ASC
  `).all());
  appendRows('vd_document', db.prepare(`
    SELECT kind, document_key, record_digest, document_json,
      customer_id, deployment_id, record_type, received_at, message_id,
      expires_at, delete_after, idempotency_until, component,
      diagnostic_code, severity, outcome, occurred_at
    FROM vd_document ORDER BY kind ASC, document_key ASC
  `).all());
  const hasLeaseColumn = db.pragma('table_xinfo(vd_deletion_scope)')
    .some((column) => column.name === 'lease_expires_at');
  const leaseProjection = hasLeaseColumn
    ? 'lease_expires_at'
    : "json_extract(document_json, '$.leaseExpiresAt') AS lease_expires_at";
  appendRows('vd_deletion_scope', db.prepare(`
    SELECT customer_id, deployment_id, job_id, record_digest, active,
      ${leaseProjection}, document_json
    FROM vd_deletion_scope ORDER BY customer_id ASC, deployment_id ASC
  `).all());
  appendRows('vd_audit', db.prepare(`
    SELECT sequence, event_id, action, customer_id, deployment_id,
      reference_id, state_revision, descriptor_json, previous_hash, entry_hash
    FROM vd_audit ORDER BY sequence ASC
  `).all());
  const sequenceState = db.prepare(`
    SELECT name, seq FROM sqlite_sequence WHERE name = 'vd_audit'
  `).get() || null;
  hash.update('sqlite_sequence\n', 'utf8')
    .update(canonical(sequenceState), 'utf8').update('\n', 'utf8');
  return hash.digest('hex');
}

function createLegacyFixtureWitness(factory, fixture) {
  const stat = fs.statSync(fixture.databasePath, { bigint: true });
  const instanceBinding = digest({
    deviceId: stat.dev.toString(),
    fileId: stat.ino.toString(),
    createdAtNs: stat.birthtimeNs.toString(),
  });
  const namespace = `vendor-diagnostics:store:${fixture.identity.storeId}:instance:${instanceBinding}`;
  const witness = authenticate(factory.authority('diagnosticWitness'), WITNESS_DOMAIN, {
    schemaVersion: 2,
    recordType: 'diagnostic_monotonic_witness',
    namespace,
    storeId: fixture.identity.storeId,
    scopeId: fixture.identity.scopeId,
    instanceBinding,
    generation: 1,
    sequence: 1,
    head: fixture.entryHash,
    stateDigest: fixture.stateDigest,
    previousWitnessDigest: null,
    restoreAuthorizationDigest: null,
    recordedAt: fixture.audit.recordedAt,
  });
  const authority = new ReferenceDiagnosticWitness();
  authority.records.set(namespace, structuredClone(witness));
  return authority;
}

function legacyDatabaseSnapshot(databasePath) {
  const db = new Database(databasePath, { readonly: true });
  try {
    return {
      userVersion: db.pragma('user_version', { simple: true }),
      objects: db.prepare(`
        SELECT type, name, tbl_name, sql FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name
      `).all(),
      deletionColumns: db.pragma('table_xinfo(vd_deletion_scope)'),
      storeRows: db.prepare(`
        SELECT singleton, store_id, scope_id FROM vd_store ORDER BY singleton
      `).all(),
      documents: db.prepare(`
        SELECT * FROM vd_document ORDER BY kind, document_key
      `).all(),
      deletionScopes: db.prepare(`
        SELECT * FROM vd_deletion_scope ORDER BY customer_id, deployment_id
      `).all(),
      auditRows: db.prepare(`
        SELECT sequence, event_id, action, customer_id, deployment_id, reference_id,
          state_revision, descriptor_json, previous_hash, entry_hash
        FROM vd_audit ORDER BY sequence
      `).all(),
      sqliteSequence: db.prepare(`
        SELECT name, seq FROM sqlite_sequence ORDER BY name
      `).all(),
    };
  } finally {
    db.close();
  }
}

function hasErrorCode(error, code) {
  for (let current = error; current; current = current.cause) {
    if (current.code === code) return true;
  }
  return false;
}

function hasErrorMessage(error, message) {
  for (let current = error; current; current = current.cause) {
    if (current.message === message) return true;
  }
  return false;
}

async function expectLegacyOpenFailure(root, factory, fixture, code) {
  let storage;
  try {
    storage = openStorage(root, factory, { witnessAuthority: fixture.witnessAuthority });
  } catch (error) {
    assert.equal(hasErrorCode(error, code), true);
    return;
  }
  await storage.close();
  assert.fail(`legacy v${fixture.version} store unexpectedly opened`);
}

function mutateDeletionActive(db, active) {
  const row = db.prepare(`
    SELECT document_json FROM vd_deletion_scope
    WHERE customer_id = ? AND deployment_id = ?
  `).get(CUSTOMER, DEPLOYMENT);
  const document = JSON.parse(row.document_json);
  document.active = active;
  db.prepare(`
    UPDATE vd_deletion_scope SET active = ?, document_json = ?
    WHERE customer_id = ? AND deployment_id = ?
  `).run(active === null ? 0 : 1, canonical(document), CUSTOMER, DEPLOYMENT);
}

function tamperDeletionSemanticState(db) {
  const before = db.prepare(`
    SELECT record_digest, active, document_json FROM vd_deletion_scope
    WHERE customer_id = ? AND deployment_id = ?
  `).get(CUSTOMER, DEPLOYMENT);
  const document = JSON.parse(before.document_json);
  assert.equal(document.active, true);
  assert.equal(before.active, 1);
  document.active = false;
  db.prepare(`
    UPDATE vd_deletion_scope SET active = 0, document_json = ?
    WHERE customer_id = ? AND deployment_id = ?
  `).run(canonical(document), CUSTOMER, DEPLOYMENT);
  const after = db.prepare(`
    SELECT record_digest, active, document_json FROM vd_deletion_scope
    WHERE customer_id = ? AND deployment_id = ?
  `).get(CUSTOMER, DEPLOYMENT);
  assert.equal(after.record_digest, before.record_digest);
  assert.equal(after.active, 0);
  assert.equal(JSON.parse(after.document_json).active, false);
}

function rewriteLegacyAudit(db, update) {
  const row = db.prepare(`
    SELECT descriptor_json FROM vd_audit WHERE sequence = (
      SELECT MIN(sequence) FROM vd_audit
    )
  `).get();
  const descriptorJson = update(row.descriptor_json);
  const entryHash = crypto.createHash('sha256')
    .update(`${'0'.repeat(64)}\0${descriptorJson}`, 'utf8').digest('hex');
  db.prepare(`
    UPDATE vd_audit SET descriptor_json = ?, entry_hash = ?
  `).run(descriptorJson, entryHash);
}

function withLateMigrationFailure(work) {
  const original = Database.prototype.exec;
  let injected = false;
  Database.prototype.exec = function injectedExec(sql) {
    const result = original.call(this, sql);
    if (!injected && String(sql).includes('CREATE TABLE vd_audit_v4')) {
      injected = true;
      throw new Error('simulated late legacy migration failure');
    }
    return result;
  };
  try {
    return work();
  } finally {
    Database.prototype.exec = original;
    assert.equal(injected, true, 'late migration failure hook must run');
  }
}

async function assertMigratedLegacyFixture(storage, fixture) {
  assert.deepEqual(storage.health(), {
    ready: true, productionReady: false, degradedCode: null,
  });
  assert.equal(storage.db.pragma('user_version', { simple: true }), 4);
  const document = storage.db.prepare(`
    SELECT record_digest, document_json, customer_id, deployment_id, record_type,
      received_at, message_id, expires_at, delete_after, idempotency_until,
      component, diagnostic_code, severity, outcome, occurred_at
    FROM vd_document WHERE kind = 'access_evidence' AND document_key = ?
  `).get(fixture.documentKey);
  assert.equal(document.record_digest, fixture.evidence.recordDigest);
  assert.equal(document.document_json, canonical(fixture.evidence));
  assert.deepEqual(Object.values(document).slice(2), Array(13).fill(null));
  assert.deepEqual(storage.db.prepare(`
    SELECT record_digest, document_json, customer_id, deployment_id, record_type,
      received_at, message_id, expires_at, delete_after, idempotency_until,
      component, diagnostic_code, severity, outcome, occurred_at
    FROM vd_document WHERE kind = 'record' AND message_id = ?
  `).get(fixture.record.messageId), {
    record_digest: fixture.record.recordDigest,
    document_json: canonical(fixture.record),
    customer_id: CUSTOMER,
    deployment_id: DEPLOYMENT,
    record_type: 'event',
    received_at: fixture.record.receivedAt,
    message_id: fixture.record.messageId,
    expires_at: fixture.record.expiresAt,
    delete_after: fixture.record.deleteAfter,
    idempotency_until: fixture.record.idempotencyUntil,
    component: fixture.record.payload.component,
    diagnostic_code: fixture.record.payload.code,
    severity: fixture.record.payload.severity,
    outcome: fixture.record.payload.outcome,
    occurred_at: fixture.record.payload.occurredAt,
  });
  assert.deepEqual(storage.db.prepare(`
    SELECT customer_id, deployment_id, job_id, record_digest, active,
      lease_expires_at, document_json FROM vd_deletion_scope
    WHERE customer_id = ? AND deployment_id = ?
  `).get(CUSTOMER, DEPLOYMENT), {
    customer_id: CUSTOMER,
    deployment_id: DEPLOYMENT,
    job_id: fixture.reservation.jobId,
    record_digest: fixture.reservation.recordDigest,
    active: 1,
    lease_expires_at: fixture.reservation.leaseExpiresAt,
    document_json: canonical(fixture.reservation),
  });
  const audit = storage.db.prepare(`
    SELECT event_id, action, customer_id, deployment_id, reference_id,
      state_revision, descriptor_json FROM vd_audit WHERE sequence = 1
  `).get();
  assert.equal(audit.descriptor_json, canonical(fixture.audit));
  assert.deepEqual({
    eventId: audit.event_id,
    action: audit.action,
    customerId: audit.customer_id,
    deploymentId: audit.deployment_id,
    referenceId: audit.reference_id,
    stateRevision: audit.state_revision,
  }, {
    eventId: fixture.audit.eventId,
    action: fixture.audit.action,
    customerId: fixture.audit.customerId,
    deploymentId: fixture.audit.deploymentId,
    referenceId: fixture.audit.referenceId,
    stateRevision: fixture.audit.stateRevision,
  });
  const indexes = new Set(storage.db.prepare(`
    SELECT name FROM sqlite_master WHERE type = 'index'
  `).all().map((row) => row.name));
  for (const name of [
    'vd_audit_claim_lookup', 'vd_record_search_global', 'vd_record_search_customer',
    'vd_record_search_deployment', 'vd_record_tenant_deletion',
    'vd_deletion_scope_active_tenant', 'vd_deletion_scope_expired_lease',
  ]) assert.equal(indexes.has(name), true, `${name} must exist after migration`);
  const manifest = await storage.createAuthenticatedBackupManifest({
    backupId: crypto.randomUUID(),
  });
  assert.equal(manifest.recordType, 'diagnostic_backup_manifest');
  assert.match(manifest.stateDigest, /^[a-f0-9]{64}$/);
}

function preparePrivateRestoreDirectory(directory, sourceDirectory) {
  privatePaths.withPrivateDirectoryMutationLockSync(directory, () => {
    for (const file of [DATABASE_FILE, CHECKPOINT_FILE]) {
      const destination = path.join(directory, file);
      fs.copyFileSync(path.join(sourceDirectory, file), destination);
      privatePaths.protectInheritedPrivateFile(destination, {
        label: `vendor diagnostic restore fixture ${file}`,
      });
    }
  }, {
    label: 'vendor diagnostic restore fixture directory',
    ownerLabel: 'vendor diagnostic restore fixture',
    lockTimeoutMs: 60_000,
    lockTimeoutMaximumMs: 60_000,
  });
}

function runWorker(request) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [WORKER], {
      cwd: path.join(__dirname, '..'),
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0 || stderr) {
        reject(new Error(`diagnostic SQLite worker failed (${code}): ${stderr}`));
        return;
      }
      try { resolve(JSON.parse(stdout.trim())); }
      catch (error) { reject(error); }
    });
    child.stdin.end(JSON.stringify(request));
  });
}

test('clean v2 and v3 stores migrate atomically to fully projected v4 stores', {
  timeout: 180_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-migrate-clean-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  for (const version of [2, 3]) {
    const caseRoot = path.join(root, `v${version}`);
    const fixture = await createLegacyMigrationFixture(caseRoot, factory, version);
    assert.equal(legacyDatabaseSnapshot(fixture.databasePath).userVersion, version);
    const storage = openStorage(caseRoot, factory, {
      witnessAuthority: fixture.witnessAuthority,
    });
    try {
      await assertMigratedLegacyFixture(storage, fixture);
    } finally {
      await storage.close();
    }
  }
});

test('legacy projection rejection rolls back every migration effect and keeps its version', {
  timeout: 240_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-migrate-reject-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  const cases = [
    {
      name: 'v2-noncanonical-document',
      version: 2,
      mutate(db) {
        const row = db.prepare(`
          SELECT document_json FROM vd_document WHERE kind = 'access_evidence'
        `).get();
        const noncanonical = JSON.stringify(JSON.parse(row.document_json), null, 2);
        assert.deepEqual(JSON.parse(noncanonical), JSON.parse(row.document_json));
        assert.notEqual(noncanonical, canonical(JSON.parse(noncanonical)));
        db.prepare(`
          UPDATE vd_document SET document_json = ? WHERE kind = 'access_evidence'
        `).run(noncanonical);
      },
    },
    {
      name: 'v2-deletion-projection-mismatch',
      version: 2,
      mutate(db) {
        db.prepare(`
          UPDATE vd_deletion_scope SET active = 0
          WHERE customer_id = ? AND deployment_id = ?
        `).run(CUSTOMER, DEPLOYMENT);
      },
    },
    {
      name: 'v3-document-projection-mismatch',
      version: 3,
      mutate(db) {
        db.prepare(`
          UPDATE vd_document SET customer_id = ? WHERE kind = 'access_evidence'
        `).run('cu-invalid-normalized-projection');
      },
    },
  ];
  for (const migrationCase of cases) {
    const caseRoot = path.join(root, migrationCase.name);
    const fixture = await createLegacyMigrationFixture(
      caseRoot, factory, migrationCase.version, migrationCase.mutate,
    );
    const before = legacyDatabaseSnapshot(fixture.databasePath);
    assert.equal(before.userVersion, migrationCase.version);
    await expectLegacyOpenFailure(
      caseRoot, factory, fixture, 'diagnostic_sqlite_projection_invalid',
    );
    const after = legacyDatabaseSnapshot(fixture.databasePath);
    assert.deepEqual(after, before, `${migrationCase.name} must roll back exactly`);
    assert.equal(after.userVersion, migrationCase.version);
    assert.equal(after.objects.some((object) => object.name === 'vd_audit_v4'), false);
    if (migrationCase.version === 2) {
      assert.equal(after.deletionColumns.some((column) => (
        column.name === 'lease_expires_at'
      )), false);
    }
  }
});

test('legacy v2 and v3 reject every coercible non-boolean deletion active value atomically', {
  timeout: 300_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-active-migrate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  for (const version of [2, 3]) {
    for (const [label, active] of [['number', 1], ['string', '1'], ['null', null]]) {
      const caseRoot = path.join(root, `v${version}-${label}`);
      const fixture = createLegacyMigrationFixture(
        caseRoot, factory, version, (db) => mutateDeletionActive(db, active),
      );
      const before = legacyDatabaseSnapshot(fixture.databasePath);
      await expectLegacyOpenFailure(
        caseRoot, factory, fixture, 'diagnostic_sqlite_projection_invalid',
      );
      assert.deepEqual(
        legacyDatabaseSnapshot(fixture.databasePath), before,
        `v${version} ${label} active rejection must roll back exactly`,
      );
    }
  }
});

test('legacy v2 and v3 reject authenticated-root semantic tamper atomically', {
  timeout: 180_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-root-migrate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  for (const version of [2, 3]) {
    const caseRoot = path.join(root, `v${version}`);
    const fixture = createLegacyMigrationFixture(
      caseRoot, factory, version, tamperDeletionSemanticState,
    );
    const before = legacyDatabaseSnapshot(fixture.databasePath);
    await expectLegacyOpenFailure(
      caseRoot, factory, fixture, 'diagnostic_sqlite_state_mismatch',
    );
    assert.deepEqual(
      legacyDatabaseSnapshot(fixture.databasePath), before,
      `semantic-tampered v${version} migration must roll back store, schema, and rows`,
    );
  }
});

test('legacy audit canonical, authentication, hash, and sequence failures roll back exactly', {
  timeout: 300_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-audit-migrate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  const cases = [
    {
      name: 'noncanonical', versions: [2, 3],
      mutate(db) {
        rewriteLegacyAudit(db, (json) => {
          const noncanonical = JSON.stringify(JSON.parse(json), null, 2);
          assert.notEqual(noncanonical, canonical(JSON.parse(noncanonical)));
          return noncanonical;
        });
      },
    },
    {
      name: 'authentication', versions: [2, 3],
      mutate(db) {
        rewriteLegacyAudit(db, (json) => {
          const descriptor = JSON.parse(json);
          descriptor.resultCount += 1;
          return canonical(descriptor);
        });
      },
    },
    {
      name: 'entry-hash', versions: [2, 3],
      mutate(db) { db.prepare('UPDATE vd_audit SET entry_hash = ?').run('f'.repeat(64)); },
    },
    {
      name: 'sequence-gap', versions: [2],
      mutate(db) { db.exec('UPDATE vd_audit SET sequence = 2'); },
    },
    {
      name: 'sqlite-sequence-ahead', versions: [3],
      mutate(db) { db.exec("UPDATE sqlite_sequence SET seq = 9 WHERE name = 'vd_audit'"); },
    },
  ];
  for (const auditCase of cases) {
    for (const version of auditCase.versions) {
      const caseRoot = path.join(root, `${auditCase.name}-v${version}`);
      const fixture = createLegacyMigrationFixture(
        caseRoot, factory, version, auditCase.mutate,
      );
      const before = legacyDatabaseSnapshot(fixture.databasePath);
      await expectLegacyOpenFailure(
        caseRoot, factory, fixture, 'diagnostic_sqlite_audit_chain_invalid',
      );
      assert.deepEqual(
        legacyDatabaseSnapshot(fixture.databasePath), before,
        `${auditCase.name} v${version} must roll back schema, audit, and sequence state`,
      );
    }
  }
});

test('non-boolean deletion active tamper fails readiness and authenticated backup', {
  timeout: 240_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-active-runtime-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  for (const [label, active] of [['number', 1], ['string', '1'], ['null', null]]) {
    const caseRoot = path.join(root, label);
    const fixture = createLegacyMigrationFixture(caseRoot, factory, 3);
    const storage = openStorage(caseRoot, factory, {
      witnessAuthority: fixture.witnessAuthority,
    });
    try {
      await storage.createAuthenticatedBackupManifest({ backupId: crypto.randomUUID() });
      const raw = new Database(fixture.databasePath);
      try { mutateDeletionActive(raw, active); } finally { raw.close(); }
      assert.deepEqual(storage.health(), {
        ready: false,
        productionReady: false,
        degradedCode: 'diagnostic_sqlite_projection_invalid',
      });
      await assert.rejects(
        storage.createAuthenticatedBackupManifest({ backupId: crypto.randomUUID() }),
        (error) => error.code === 'diagnostic_sqlite_projection_invalid',
      );
    } finally {
      await storage.close();
    }
  }
});

test('semantic deletion tamper fails backup before latching degraded readiness', {
  timeout: 180_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-root-backup-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  const fixture = createLegacyMigrationFixture(root, factory, 3);
  const storage = openStorage(root, factory, {
    witnessAuthority: fixture.witnessAuthority,
  });
  try {
    await storage.createAuthenticatedBackupManifest({ backupId: crypto.randomUUID() });
    const raw = new Database(fixture.databasePath);
    try { tamperDeletionSemanticState(raw); } finally { raw.close(); }
    await assert.rejects(
      storage.createAuthenticatedBackupManifest({ backupId: crypto.randomUUID() }),
      (error) => error.code === 'diagnostic_sqlite_state_mismatch',
    );
    assert.deepEqual(storage.health(), {
      ready: false,
      productionReady: false,
      degradedCode: 'diagnostic_sqlite_state_mismatch',
    });
  } finally {
    await storage.close();
  }
});

test('semantic deletion tamper rejects a transaction before work and retains old data version', {
  timeout: 180_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-root-transaction-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  const fixture = createLegacyMigrationFixture(root, factory, 3);
  const storage = openStorage(root, factory, {
    witnessAuthority: fixture.witnessAuthority,
  });
  try {
    const acceptedDataVersion = storage.dataVersion;
    const raw = new Database(fixture.databasePath);
    try { tamperDeletionSemanticState(raw); } finally { raw.close(); }
    let workCalled = false;
    await assert.rejects(
      storage.transaction((tx) => {
        workCalled = true;
        return tx.appendAudit(storageAudit(factory, 'semantic-tamper-transaction'));
      }),
      (error) => error.code === 'diagnostic_sqlite_state_mismatch',
    );
    assert.equal(workCalled, false);
    assert.equal(storage.dataVersion, acceptedDataVersion);
    assert.deepEqual(storage.health(), {
      ready: false,
      productionReady: false,
      degradedCode: 'diagnostic_sqlite_state_mismatch',
    });
  } finally {
    await storage.close();
  }
});

test('late legacy audit and index rebuild failure rolls back all migration state', {
  timeout: 180_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-late-migrate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  for (const version of [2, 3]) {
    const caseRoot = path.join(root, `v${version}`);
    const fixture = createLegacyMigrationFixture(caseRoot, factory, version);
    const before = legacyDatabaseSnapshot(fixture.databasePath);
    assert.throws(
      () => withLateMigrationFailure(() => openStorage(caseRoot, factory, {
        witnessAuthority: fixture.witnessAuthority,
      })),
      (error) => hasErrorMessage(error, 'simulated late legacy migration failure'),
    );
    assert.deepEqual(
      legacyDatabaseSnapshot(fixture.databasePath), before,
      `late v${version} migration failure must roll back exactly`,
    );
  }
});

test('SQLite adapter reconciles committed pending state and serializes independent processes', {
  timeout: 240_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-vendor-diagnostic-sqlite-'));
  const directory = path.join(root, 'private');
  const witnessDirectory = path.join(root, 'witness');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const keyFactoryOptions = keyFactoryConfiguration();
  const nowMs = Date.now();
  const deletionKeys = deletionKeyConfiguration(nowMs);
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryOptions,
    now: Date.now,
  });
  let runtime = createVendorDiagnosticRuntime({
    allowTestWitness: true,
    directory,
    deletionIntentKeyRegistry: deletionKeys.registry,
    keyFactory: factory,
    witnessAuthority: new FileDiagnosticWitness(witnessDirectory),
    currentPrincipal: () => PRINCIPAL,
  });
  const states = await publishControlStates(runtime, factory, nowMs);
  assert.deepEqual(runtime.health(), { ready: true, productionReady: false, degradedCode: null });
  await runtime.close();
  runtime = null;

  const checkpointPath = path.join(directory, CHECKPOINT_FILE);
  const pendingPath = path.join(directory, PENDING_FILE);
  const checkpointBeforeBytes = fs.readFileSync(checkpointPath, 'utf8');
  const checkpointBefore = JSON.parse(checkpointBeforeBytes);
  const firstCapability = capability(factory, states.authorization, nowMs);
  const firstPayload = payload(nowMs);
  const firstRequest = {
    witnessDirectory,
    directory,
    deletionRegistryEntries: deletionKeys.entries,
    keyFactory: keyFactoryOptions,
    principal: PRINCIPAL,
    operation: 'ingest',
    command: { capability: firstCapability, payload: firstPayload },
  };
  const first = await runWorker(firstRequest);
  assert.equal(first.ok, true);
  assert.equal(first.result.messageId, firstPayload.messageId);
  const checkpointAfterBytes = fs.readFileSync(checkpointPath, 'utf8');
  const checkpointAfter = JSON.parse(checkpointAfterBytes);
  assert(checkpointAfter.sequence > checkpointBefore.sequence);
  const identityDatabase = new Database(path.join(directory, DATABASE_FILE), { readonly: true });
  const identity = identityDatabase.prepare(`
    SELECT store_id AS storeId, scope_id AS scopeId FROM vd_store WHERE singleton = 1
  `).get();
  identityDatabase.close();

  const pending = authenticate(factory.authority('audit'), PENDING_DOMAIN, {
    schemaVersion: 2,
    recordType: 'pending_commit',
    transactionId: crypto.randomUUID(),
    storeId: identity.storeId,
    scopeId: identity.scopeId,
    baseSequence: checkpointBefore.sequence,
    baseHead: checkpointBefore.head,
    baseStateDigest: checkpointBefore.stateDigest,
    finalSequence: checkpointAfter.sequence,
    finalHead: checkpointAfter.head,
    finalStateDigest: checkpointAfter.stateDigest,
    recordedAt: new Date().toISOString(),
  });
  fs.writeFileSync(checkpointPath, checkpointBeforeBytes, 'utf8');
  fs.writeFileSync(pendingPath, `${canonical(pending)}\n`, { mode: 0o600 });
  privatePaths.protectInheritedPrivateFile(pendingPath, {
    label: 'vendor diagnostic pending recovery fixture',
  });

  runtime = createVendorDiagnosticRuntime({
    allowTestWitness: true,
    directory,
    deletionIntentKeyRegistry: deletionKeys.registry,
    keyFactory: factory,
    witnessAuthority: new FileDiagnosticWitness(witnessDirectory),
    currentPrincipal: () => PRINCIPAL,
  });
  assert.equal(fs.existsSync(pendingPath), false);
  const reconciled = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
  assert.equal(reconciled.sequence, checkpointAfter.sequence);
  assert.equal(reconciled.head, checkpointAfter.head);
  await runtime.close();
  runtime = null;

  const replay = await runWorker(firstRequest);
  assert.equal(replay.ok, false);
  assert.equal(replay.code, 'capability_replayed');

  const raw = new Database(path.join(directory, DATABASE_FILE));
  const removedClaims = raw.prepare(`
    SELECT * FROM vd_document WHERE kind = 'capability_claim'
    ORDER BY document_key
  `).all();
  assert.equal(removedClaims.length, 1);
  raw.prepare(`
    DELETE FROM vd_document WHERE kind = 'capability_claim'
  `).run();
  raw.close();
  const missingClaim = await runWorker(firstRequest);
  assert.equal(missingClaim.ok, false);
  assert.equal(missingClaim.code, 'diagnostic_sqlite_state_mismatch');
  const restoredClaims = new Database(path.join(directory, DATABASE_FILE));
  const claimColumns = Object.keys(removedClaims[0]);
  const restoreClaim = restoredClaims.prepare(`
    INSERT INTO vd_document (${claimColumns.join(', ')})
    VALUES (${claimColumns.map(() => '?').join(', ')})
  `);
  for (const claim of removedClaims) restoreClaim.run(...claimColumns.map((key) => claim[key]));
  restoredClaims.close();

  const concurrentRequests = [0, 1].map(() => ({
    witnessDirectory,
    directory,
    deletionRegistryEntries: deletionKeys.entries,
    keyFactory: keyFactoryOptions,
    principal: PRINCIPAL,
    operation: 'ingest',
    command: {
      capability: capability(factory, states.authorization, Date.now()),
      payload: payload(Date.now()),
    },
  }));
  const concurrent = await Promise.all(concurrentRequests.map(runWorker));
  assert.deepEqual(concurrent.map((item) => item.ok), [true, true]);

  const health = await runWorker({
    witnessDirectory,
    directory,
    deletionRegistryEntries: deletionKeys.entries,
    keyFactory: keyFactoryOptions,
    principal: PRINCIPAL,
    operation: 'health',
  });
  assert.deepEqual(health, {
    ok: true,
    result: { ready: true, productionReady: false, degradedCode: null },
  });

  const deletionNow = Date.now();
  runtime = createVendorDiagnosticRuntime({
    allowTestWitness: true,
    directory,
    deletionIntentKeyRegistry: deletionKeys.registry,
    keyFactory: factory,
    witnessAuthority: new FileDiagnosticWitness(witnessDirectory),
    currentPrincipal: () => VENDOR,
  });
  const indexPlans = [
    {
      name: 'vd_record_search_global',
      rows: runtime.storage.db.prepare(`
        EXPLAIN QUERY PLAN SELECT r.document_json, r.received_at, r.message_id
        FROM vd_document r INDEXED BY vd_record_search_global
        WHERE r.kind = 'record' AND r.record_type = 'event' AND r.expires_at > ?
        ORDER BY r.received_at ASC, r.message_id ASC LIMIT 100
      `).all(new Date().toISOString()),
    },
    {
      name: 'vd_record_search_deployment',
      rows: runtime.storage.db.prepare(`
        EXPLAIN QUERY PLAN SELECT r.document_json, r.received_at, r.message_id
        FROM vd_document r INDEXED BY vd_record_search_deployment
        WHERE r.kind = 'record' AND r.record_type = 'event' AND r.expires_at > ?
          AND r.customer_id = ? AND r.deployment_id = ?
        ORDER BY r.received_at ASC, r.message_id ASC LIMIT 100
      `).all(new Date().toISOString(), CUSTOMER, DEPLOYMENT),
    },
    {
      name: 'vd_record_expiry',
      rows: runtime.storage.db.prepare(`
        EXPLAIN QUERY PLAN SELECT r.document_json
        FROM vd_document r INDEXED BY vd_record_expiry
        WHERE r.kind = 'record' AND r.record_type = 'event' AND r.expires_at <= ?
          AND NOT EXISTS (
            SELECT 1 FROM vd_deletion_scope d
            WHERE d.active = 1 AND d.customer_id = r.customer_id
              AND d.deployment_id = r.deployment_id
          )
        ORDER BY r.expires_at ASC, r.received_at ASC, r.message_id ASC LIMIT 100
      `).all(new Date().toISOString()),
    },
    {
      name: 'vd_audit_claim_lookup',
      rows: runtime.storage.db.prepare(`
        EXPLAIN QUERY PLAN SELECT descriptor_json FROM vd_audit
        WHERE customer_id = ? AND deployment_id = ? AND reference_id = ?
        ORDER BY sequence DESC LIMIT 1
      `).all(CUSTOMER, DEPLOYMENT, crypto.randomUUID()),
    },
    {
      name: 'vd_record_tenant_deletion',
      rows: runtime.storage.db.prepare(`
        EXPLAIN QUERY PLAN SELECT document_json FROM vd_document
        WHERE kind = 'record' AND customer_id = ? AND deployment_id = ?
        ORDER BY received_at ASC, message_id ASC LIMIT 100
      `).all(CUSTOMER, DEPLOYMENT),
    },
    {
      name: 'vd_deletion_scope_expired_lease',
      rows: runtime.storage.db.prepare(`
        EXPLAIN QUERY PLAN SELECT document_json FROM vd_deletion_scope
          INDEXED BY vd_deletion_scope_expired_lease
        WHERE active = 1 AND lease_expires_at <= ?
        ORDER BY lease_expires_at ASC, customer_id ASC, deployment_id ASC LIMIT 100
      `).all(new Date().toISOString()),
    },
  ];
  for (const plan of indexPlans) {
    const details = plan.rows.map((row) => row.detail).join('\n');
    assert.match(details, new RegExp(`USING INDEX ${plan.name}`));
    assert.doesNotMatch(details, /(?:^|\n)SCAN |USE TEMP B-TREE/);
  }
  const vendorAuthorization = authenticate(factory.authority('access'), AUTHORIZATION_DOMAIN, {
    schemaVersion: 1,
    recordType: 'authorization_state',
    principalId: VENDOR.principalId,
    principalType: VENDOR.principalType,
    revision: 1,
    ownerAuthEventId: crypto.randomUUID(),
    issuer: 'owner-platform',
    credentialPurpose: 'owner_session',
    credentialVersion: 1,
    revocationRevision: 0,
    status: 'active',
    updatedAt: new Date(deletionNow - 1_000).toISOString(),
    expiresAt: new Date(deletionNow + 24 * 60 * 60 * 1000).toISOString(),
    auditEventId: crypto.randomUUID(),
  });
  await runtime.publishControlState({
    kind: 'authorization',
    expectedRecordDigest: null,
    record: vendorAuthorization,
    audit: signedAudit(
      factory.authority('audit'),
      stateAudit(vendorAuthorization, 'diagnostic_authorization_state', {
        customerId: null, deploymentId: null, referenceId: VENDOR.principalId,
      }),
    ),
  });
  const intent = signedDeletionIntent(deletionKeys, {
    schemaVersion: 1,
    recordType: 'deletion_intent',
    intentId: crypto.randomUUID(),
    customerId: CUSTOMER,
    deploymentId: DEPLOYMENT,
    channel: 'diagnostics',
    customerGrantId: states.grant.grantId,
    customerGrantDigest: states.grant.recordDigest,
    customerGrantRevision: states.grant.revision,
    scopeRevision: states.grant.revision,
    subjectDigest: digest({ subject: 'sqlite-privacy-officer' }),
    reasonCode: 'privacy_request',
    issuedAt: new Date(deletionNow - 1_000).toISOString(),
    expiresAt: new Date(deletionNow + 60 * 60 * 1000).toISOString(),
  });
  await runtime.intelligence.submitDeletionIntent({ intent });
  const supportCaseId = crypto.randomUUID();
  const approvalId = crypto.randomUUID();
  const preview = await runtime.intelligence.previewDeletion({
    capability: vendorCapability(
      factory, vendorAuthorization, 'diagnostics:delete:preview', deletionNow,
      { supportCaseId },
    ),
    jobId: intent.intentId,
  });
  assert.equal(preview.count, 3);
  await runtime.intelligence.approveDeletion({
    capability: vendorCapability(
      factory, vendorAuthorization, 'diagnostics:delete:approve', deletionNow,
      { supportCaseId, approvalId },
    ),
    jobId: intent.intentId,
  });
  let progress;
  do {
    progress = await runtime.intelligence.executeDeletion({
      capability: vendorCapability(
        factory, vendorAuthorization, 'diagnostics:delete:execute', deletionNow,
        { supportCaseId, approvalId },
      ),
      jobId: intent.intentId,
      limit: 2,
    });
  } while (progress.nextBatchRequired);
  assert.equal(progress.status, 'completed');
  assert.equal(progress.deletedCount, 3);
  assert.equal(progress.completion.recordType, 'deletion_completion');
  await runtime.close();
  runtime = null;

  const validCheckpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
  validCheckpoint.recordDigest = `${validCheckpoint.recordDigest.slice(0, -1)}${
    validCheckpoint.recordDigest.endsWith('0') ? '1' : '0'
  }`;
  fs.writeFileSync(checkpointPath, `${canonical(validCheckpoint)}\n`, 'utf8');
  assert.throws(
    () => createVendorDiagnosticRuntime({
      allowTestWitness: true,
      directory,
      deletionIntentKeyRegistry: deletionKeys.registry,
      keyFactory: factory,
      witnessAuthority: new FileDiagnosticWitness(witnessDirectory),
      currentPrincipal: () => PRINCIPAL,
    }),
    (error) => error.code === 'diagnostic_sqlite_sidecar_invalid',
  );
});

test('COMMIT faults use a fresh connection and leave readiness latched until restart', {
  timeout: 240_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-commit-faults-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  for (const phase of ['before', 'during', 'after']) {
    const phaseRoot = path.join(root, phase);
    let storage = openStorage(phaseRoot, factory);
    const oldConnection = storage.db;
    const realExec = oldConnection.exec.bind(oldConnection);
    let injected = false;
    Object.defineProperty(oldConnection, 'exec', {
      configurable: true,
      value(sql) {
        if (!injected && String(sql).trim().toUpperCase() === 'COMMIT') {
          injected = true;
          if (phase === 'during') realExec('ROLLBACK');
          if (phase === 'after') realExec(sql);
          throw new Error(`simulated ${phase} COMMIT fault`);
        }
        return realExec(sql);
      },
    });
    const operation = appendStorageAudit(storage, factory, `commit-${phase}`);
    if (phase === 'after') await operation;
    else await assert.rejects(operation, (error) => (
      error.code === 'diagnostic_sqlite_commit_rolled_back'
    ));
    assert.notEqual(storage.db, oldConnection);
    assert.deepEqual(storage.health(), {
      ready: false,
      productionReady: false,
      degradedCode: 'diagnostic_sqlite_commit_uncertain',
    });
    assert.equal(fs.existsSync(path.join(phaseRoot, 'private', PENDING_FILE)), true);
    await storage.close();
    storage = openStorage(phaseRoot, factory);
    assert.deepEqual(storage.health(), {
      ready: true, productionReady: false, degradedCode: null,
    });
    assert.equal(fs.existsSync(path.join(phaseRoot, 'private', PENDING_FILE)), false);
    const count = storage.db.prepare(`
      SELECT COUNT(*) AS count FROM vd_audit WHERE action = 'diagnostics_viewed'
    `).get().count;
    assert.equal(count, phase === 'after' ? 1 : 0);
    await storage.close();
  }
});

test('audit projections are immutable and every audit byte is backup-bound and live-verified', {
  timeout: 120_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-audit-projection-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  const storage = openStorage(root, factory);
  const emptyManifest = await storage.createAuthenticatedBackupManifest({
    backupId: crypto.randomUUID(),
  });
  await appendStorageAudit(storage, factory, 'audit-projection');
  const populatedManifest = await storage.createAuthenticatedBackupManifest({
    backupId: crypto.randomUUID(),
  });
  assert.notEqual(populatedManifest.stateDigest, emptyManifest.stateDigest);
  assert.throws(() => storage.db.prepare(`
    UPDATE vd_audit SET action = 'diagnostic_ingested' WHERE sequence = 1
  `).run());

  const raw = new Database(path.join(root, 'private', DATABASE_FILE));
  raw.exec('DROP TRIGGER vd_audit_immutable_update');
  const row = raw.prepare('SELECT descriptor_json FROM vd_audit WHERE sequence = 1').get();
  const changed = JSON.parse(row.descriptor_json);
  changed.resultCount += 1;
  raw.prepare('UPDATE vd_audit SET descriptor_json = ? WHERE sequence = 1')
    .run(canonical(changed));
  raw.close();

  assert.deepEqual(storage.health(), {
    ready: false,
    productionReady: false,
    degradedCode: 'diagnostic_sqlite_audit_chain_invalid',
  });
  await assert.rejects(
    storage.createAuthenticatedBackupManifest({ backupId: crypto.randomUUID() }),
    (error) => error.code === 'diagnostic_sqlite_audit_chain_invalid',
  );
  await storage.close();
});

test('witness branding rejects assurance spoofing and CAS fails closed', {
  timeout: 240_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-witness-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });

  assert.throws(
    () => openStorage(path.join(root, 'spoofed-production'), factory, {
      witnessAuthority: new ReferenceDiagnosticWitness({
        assurance: 'independent_monotonic_exact_cas_v1',
      }),
    }),
    (error) => error.code === 'diagnostic_sqlite_witness_authority_invalid',
  );

  for (const mode of ['missing', 'stale', 'forked']) {
    const witness = new ReferenceDiagnosticWitness();
    const caseRoot = path.join(root, mode);
    let storage = openStorage(caseRoot, factory, { witnessAuthority: witness });
    const [namespace] = witness.records.keys();
    const genesis = structuredClone(witness.records.get(namespace));
    await appendStorageAudit(storage, factory, `witness-${mode}`);
    const current = structuredClone(witness.records.get(namespace));
    await storage.close();

    if (mode === 'missing') witness.records.delete(namespace);
    if (mode === 'stale') witness.records.set(namespace, genesis);
    if (mode === 'forked') {
      const { recordDigest, integrityProof, ...core } = current;
      void recordDigest;
      void integrityProof;
      witness.records.set(namespace, authenticate(
        factory.authority('diagnosticWitness'), WITNESS_DOMAIN, {
          ...core, head: digest({ forkedFrom: current.head }),
        },
      ));
    }
    assert.throws(
      () => openStorage(caseRoot, factory, { witnessAuthority: witness }),
      (error) => error.code === (mode === 'missing'
        ? 'diagnostic_sqlite_witness_missing'
        : 'diagnostic_sqlite_checkpoint_mismatch'),
    );
  }

  let failCas = false;
  const witness = new ReferenceDiagnosticWitness({
    hooks: {
      compareAndSwap(command, run) {
        if (failCas) throw new Error('simulated independent witness outage');
        return run();
      },
    },
  });
  const uncertainRoot = path.join(root, 'uncertain');
  let storage = openStorage(uncertainRoot, factory, { witnessAuthority: witness });
  failCas = true;
  await assert.rejects(
    appendStorageAudit(storage, factory, 'witness-uncertain'),
    (error) => error.code === 'diagnostic_sqlite_witness_uncertain',
  );
  assert.deepEqual(storage.health(), {
    ready: false,
    productionReady: false,
    degradedCode: 'diagnostic_sqlite_witness_uncertain',
  });
  assert.equal(fs.existsSync(path.join(uncertainRoot, 'private', PENDING_FILE)), true);
  await storage.close();

  failCas = false;
  storage = openStorage(uncertainRoot, factory, { witnessAuthority: witness });
  assert.deepEqual(storage.health(), {
    ready: true, productionReady: false, degradedCode: null,
  });
  assert.equal(fs.existsSync(path.join(uncertainRoot, 'private', PENDING_FILE)), false);
  await storage.close();
});

test('independent witness rejects rollback and consumes each fresh-scope restore once', {
  timeout: 240_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-anchor-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const factory = createVendorDiagnosticKeyFactory({
    ...keyFactoryConfiguration(), now: Date.now,
  });
  const rollbackRoot = path.join(root, 'rollback');
  let storage = openStorage(rollbackRoot, factory);
  await appendStorageAudit(storage, factory, 'rollback-base');
  await storage.close();
  const databaseSnapshot = fs.readFileSync(path.join(rollbackRoot, 'private', DATABASE_FILE));
  const checkpointSnapshot = fs.readFileSync(path.join(rollbackRoot, 'private', CHECKPOINT_FILE));
  storage = openStorage(rollbackRoot, factory);
  await appendStorageAudit(storage, factory, 'rollback-later');
  await storage.close();
  fs.writeFileSync(path.join(rollbackRoot, 'private', DATABASE_FILE), databaseSnapshot);
  fs.writeFileSync(path.join(rollbackRoot, 'private', CHECKPOINT_FILE), checkpointSnapshot);
  assert.throws(() => openStorage(rollbackRoot, factory), (error) => (
    error.code === 'diagnostic_sqlite_checkpoint_mismatch'
  ));

  const sourceRoot = path.join(root, 'source');
  const witnessDirectory = path.join(root, 'shared-witness');
  const sourceNow = Date.now();
  const sourceDeletionKeys = deletionKeyConfiguration(sourceNow);
  const sourceRuntime = createVendorDiagnosticRuntime({
    allowTestWitness: true,
    directory: path.join(sourceRoot, 'private'),
    deletionIntentKeyRegistry: sourceDeletionKeys.registry,
    keyFactory: factory,
    witnessAuthority: new FileDiagnosticWitness(witnessDirectory),
    currentPrincipal: () => PRINCIPAL,
  });
  const sourceStates = await publishControlStates(sourceRuntime, factory, sourceNow);
  await sourceRuntime.intelligence.ingest({
    capability: capability(factory, sourceStates.authorization, sourceNow),
    payload: payload(sourceNow),
  });
  const sourceIdentity = sourceRuntime.storage.db.prepare(`
    SELECT store_id AS storeId, scope_id AS scopeId FROM vd_store WHERE singleton = 1
  `).get();
  const backupManifest = await sourceRuntime.createAuthenticatedBackupManifest({
    backupId: crypto.randomUUID(),
  });
  const restoreAuthorization = await sourceRuntime.createFreshRestoreAuthorization({
    backupManifest,
    lifetimeMs: 60 * 60 * 1000,
  });
  await sourceRuntime.close();

  const unauthorizedCloneRoot = path.join(root, 'unauthorized-clone');
  preparePrivateRestoreDirectory(
    path.join(unauthorizedCloneRoot, 'private'), path.join(sourceRoot, 'private'),
  );
  assert.throws(
    () => openStorage(unauthorizedCloneRoot, factory, { witnessDirectory }),
    (error) => error.code === 'diagnostic_sqlite_witness_missing',
  );

  for (const mutation of [
    {
      name: 'document-json',
      apply(db) {
        db.prepare(`
          UPDATE vd_document SET document_json = '{}'
          WHERE kind = (SELECT kind FROM vd_document ORDER BY kind, document_key LIMIT 1)
            AND document_key = (
              SELECT document_key FROM vd_document ORDER BY kind, document_key LIMIT 1
            )
        `).run();
      },
    },
    {
      name: 'normalized-projection',
      apply(db) {
        db.prepare(`
          UPDATE vd_document SET customer_id = 'cu-projection-tamper'
          WHERE kind = 'record' AND document_key = (
            SELECT document_key FROM vd_document WHERE kind = 'record' LIMIT 1
          )
        `).run();
      },
    },
  ]) {
    const tamperedRoot = path.join(root, `restore-${mutation.name}`);
    preparePrivateRestoreDirectory(
      path.join(tamperedRoot, 'private'), path.join(sourceRoot, 'private'),
    );
    const raw = new Database(path.join(tamperedRoot, 'private', DATABASE_FILE));
    mutation.apply(raw);
    raw.close();
    assert.throws(
      () => openStorage(tamperedRoot, factory, {
        backupManifest, restoreAuthorization, witnessDirectory,
      }),
      (error) => error.code === 'diagnostic_sqlite_projection_invalid',
    );
  }
  const restoredRoot = path.join(root, 'restored');
  preparePrivateRestoreDirectory(
    path.join(restoredRoot, 'private'), path.join(sourceRoot, 'private'),
  );
  storage = openStorage(restoredRoot, factory, {
    backupManifest, restoreAuthorization, witnessDirectory,
  });
  const restoredIdentity = storage.db.prepare(`
    SELECT store_id AS storeId, scope_id AS scopeId FROM vd_store WHERE singleton = 1
  `).get();
  assert.notEqual(restoredIdentity.storeId, sourceIdentity.storeId);
  assert.notEqual(restoredIdentity.scopeId, sourceIdentity.scopeId);
  assert.deepEqual(storage.health(), { ready: true, productionReady: false, degradedCode: null });
  assert.equal(storage.db.prepare(`
    SELECT COUNT(*) AS count FROM vd_audit
    WHERE action = 'diagnostic_store_scope_restored'
  `).get().count, 1);
  await storage.close();

  const replayRoot = path.join(root, 'restore-replay');
  preparePrivateRestoreDirectory(
    path.join(replayRoot, 'private'), path.join(sourceRoot, 'private'),
  );
  assert.throws(
    () => openStorage(replayRoot, factory, {
      backupManifest, restoreAuthorization, witnessDirectory,
    }),
    (error) => error.code === 'diagnostic_sqlite_restore_authorization_consumed',
  );
});

test('audit verification keys survive rotation beyond the diagnostic replay horizon', {
  timeout: 180_000,
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-diagnostic-audit-rotation-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const initialOptions = keyFactoryConfiguration();
  const initialFactory = createVendorDiagnosticKeyFactory({
    ...initialOptions, now: () => Date.parse('2026-01-01T00:00:00.000Z'),
  });
  let storage = openStorage(root, initialFactory);
  await appendStorageAudit(storage, initialFactory, 'pre-rotation');
  await storage.close();
  const rotatedOptions = keyFactoryConfiguration();
  rotatedOptions.keys.audit.current = {
    keyId: 'audit.sqlite-next',
    key: keyBytes('audit.next').toString('base64'),
  };
  rotatedOptions.keys.audit.verifyOnly = [{
    keyId: initialOptions.keys.audit.current.keyId,
    key: initialOptions.keys.audit.current.key,
    verifyUntil: null,
  }];
  const rotatedFactory = createVendorDiagnosticKeyFactory({
    ...rotatedOptions,
    now: () => Date.parse('2026-04-15T00:00:00.000Z'),
  });
  storage = openStorage(root, rotatedFactory);
  await appendStorageAudit(storage, rotatedFactory, 'post-rotation');
  await storage.close();
  storage = openStorage(root, rotatedFactory);
  assert.equal(storage.db.prepare(`
    SELECT COUNT(*) AS count FROM vd_audit WHERE action = 'diagnostics_viewed'
  `).get().count, 2);
  assert.deepEqual(storage.health(), { ready: true, productionReady: false, degradedCode: null });
  await storage.close();
});
