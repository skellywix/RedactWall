'use strict';

const {
  createVendorDiagnosticIntelligence,
  IDEMPOTENCY_HORIZON_MS,
  KEY_RETENTION_MARGIN_MS,
} = require('./vendor-diagnostic-intelligence');
const {
  controlStateKey,
  createVendorDiagnosticSqliteStorage,
} = require('./vendor-diagnostic-sqlite');

const POSTGRES_ADAPTER_CONTRACT = Object.freeze({
  contractVersion: 'vendor-diagnostic-serializable-v2',
  requirements: Object.freeze([
    'serializable customer-scoped transactions',
    'durable authenticated pending commit record before database commit',
    'independent non-rewindable store and scope witness with signed exact CAS',
    'fresh-connection commit outcome verification',
    'streaming startup audit verification and incremental transaction verification',
    'normalized indexed tenant, deployment, type, expiry, and immutable order columns',
    'bounded SQL-only search, compaction, export, and deletion',
    'bounded deletion-scope leases and resumable exact deletion batches',
    'authenticated complete-state backup manifest and single-use fresh-scope restore claim',
    'durable body-free per-customer access evidence with retained-record exact replay',
    'full audit-epoch verification-key retention',
  ]),
});

const POSTGRES_BLOCKER = Object.freeze({
  code: 'VENDOR_DIAGNOSTIC_POSTGRES_NOT_IMPLEMENTED',
  message: `The vendor diagnostic Postgres adapter must satisfy ${POSTGRES_ADAPTER_CONTRACT.contractVersion} before it can be enabled.`,
});

function createVendorDiagnosticRuntime(options = {}) {
  assertReferenceRuntime();
  const configuration = checkedOptions(options);
  if (configuration.driver === 'postgres') throw postgresBlocker();
  const manifest = configuration.keyFactory.manifest();
  if (!Number.isSafeInteger(manifest.requiredVerifyHorizonMs)
      || manifest.requiredVerifyHorizonMs < IDEMPOTENCY_HORIZON_MS + KEY_RETENTION_MARGIN_MS
      || manifest.auditRetentionMode !== 'full_epoch'
      || manifest.witnessRetentionMode !== 'full_epoch') {
    const error = configurationError();
    error.code = 'VENDOR_DIAGNOSTIC_KEY_HORIZON_TOO_SHORT';
    throw error;
  }
  const purposes = configuration.keyFactory.fingerprints();
  const owner = manifest.ownerAuthorityManifest;
  const authorities = diagnosticAuthorities(configuration.keyFactory);
  assertDiagnosticIntegrityBinding(authorities.integrity, purposes, owner);
  const authorityFingerprints = Object.freeze({
    diagnosticAccess: purposes.access,
    diagnosticAudit: purposes.audit,
    diagnosticCursor: purposes.cursor,
    diagnosticCustomerGrant: purposes.customerGrant,
    diagnosticIntegrity: purposes.integrity,
    diagnosticOwnerAuth: purposes.ownerAuth,
    diagnosticWitness: purposes.diagnosticWitness,
    ...Object.fromEntries(Object.entries(owner).map(([purpose, record]) => (
      [purpose, record.identity]
    ))),
  });
  const storage = createVendorDiagnosticSqliteStorage({
    directory: configuration.directory,
    allowTestWitness: configuration.allowTestWitness,
    auditAuthority: authorities.audit,
    witnessAuthority: configuration.witnessAuthority,
    witnessIntegrityAuthority: authorities.diagnosticWitness,
    backupManifest: configuration.backupManifest,
    restoreAuthorization: configuration.restoreAuthorization,
    security: configuration.security,
  });
  let intelligence;
  try {
    intelligence = createVendorDiagnosticIntelligence({
      storage,
      accessAuthority: authorities.access,
      ownerAuthAuthority: authorities.ownerAuth,
      auditAuthority: authorities.audit,
      cursorAuthority: authorities.cursor,
      customerGrantAuthority: authorities.customerGrant,
      integrityAuthority: authorities.integrity,
      deletionIntentKeyRegistry: configuration.deletionIntentKeyRegistry,
      authorityFingerprints,
      currentPrincipal: configuration.currentPrincipal,
      retentionDays: configuration.retentionDays,
      dailyEventLimit: configuration.dailyEventLimit,
    });
  } catch (error) {
    storage.db.close();
    throw error;
  }
  return Object.freeze({
    intelligence,
    storage,
    authorityFingerprints,
    manifestDigest: configuration.keyFactory.manifestDigest,
    publishControlState(command) {
      const input = checkedPublication(command);
      return storage.publishControlState({
        ...input,
        key: controlStateKey(input.kind, input.record),
      });
    },
    createAuthenticatedBackupManifest: (command) => (
      storage.createAuthenticatedBackupManifest(command)
    ),
    createFreshRestoreAuthorization: (command) => (
      storage.createFreshRestoreAuthorization(command)
    ),
    health: () => storage.health(),
    close: () => storage.close(),
  });
}

function diagnosticAuthorities(keyFactory) {
  return Object.freeze(Object.fromEntries([
    'access', 'audit', 'cursor', 'customerGrant', 'diagnosticWitness', 'integrity', 'ownerAuth',
  ].map((purpose) => [purpose, keyFactory.authority(purpose)])));
}

function assertDiagnosticIntegrityBinding(authority, purposes, ownerManifest) {
  const owner = ownerManifest && ownerManifest.diagnostic_integrity;
  if (!authority || typeof authority.keyId !== 'string'
      || typeof authority.fingerprint !== 'string'
      || !purposes || purposes.integrity !== authority.fingerprint
      || !owner || owner.keyId !== authority.keyId
      || owner.identity !== authority.fingerprint) {
    const error = configurationError();
    error.code = 'VENDOR_DIAGNOSTIC_INTEGRITY_MANIFEST_MISMATCH';
    throw error;
  }
}

function createVendorDiagnosticPostgresStorage() { throw postgresBlocker(); }

function checkedOptions(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) throw configurationError();
  const allowed = new Set([
    'allowTestWitness', 'backupManifest', 'deletionIntentKeyRegistry', 'driver',
    'directory', 'keyFactory', 'currentPrincipal', 'restoreAuthorization',
    'retentionDays', 'dailyEventLimit', 'security', 'witnessAuthority',
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))
      || !value.keyFactory || typeof value.keyFactory.authority !== 'function'
      || typeof value.keyFactory.fingerprints !== 'function'
      || typeof value.keyFactory.manifest !== 'function'
      || !value.deletionIntentKeyRegistry
      || typeof value.deletionIntentKeyRegistry.verify !== 'function'
      || typeof value.currentPrincipal !== 'function'
      || !value.witnessAuthority) throw configurationError();
  const driver = value.driver || 'sqlite';
  if (!['sqlite', 'postgres'].includes(driver)
      || (driver === 'sqlite' && typeof value.directory !== 'string')) throw configurationError();
  return {
    driver,
    directory: value.directory,
    allowTestWitness: value.allowTestWitness === true,
    backupManifest: value.backupManifest,
    deletionIntentKeyRegistry: value.deletionIntentKeyRegistry,
    keyFactory: value.keyFactory,
    witnessAuthority: value.witnessAuthority,
    restoreAuthorization: value.restoreAuthorization,
    currentPrincipal: value.currentPrincipal,
    retentionDays: value.retentionDays === undefined ? 30 : value.retentionDays,
    dailyEventLimit: value.dailyEventLimit === undefined ? 100_000 : value.dailyEventLimit,
    security: value.security || {},
  };
}

function checkedPublication(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',')
        !== ['audit', 'expectedRecordDigest', 'kind', 'record'].sort().join(',')) {
    throw configurationError();
  }
  return { ...value };
}

function configurationError() {
  const error = new Error('vendor diagnostic runtime configuration rejected');
  error.code = 'VENDOR_DIAGNOSTIC_RUNTIME_CONFIGURATION_INVALID';
  return error;
}

function postgresBlocker() {
  const error = new Error(POSTGRES_BLOCKER.message);
  error.code = POSTGRES_BLOCKER.code;
  return error;
}

function assertReferenceRuntime() {
  if (String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production') {
    const error = configurationError();
    error.code = 'vendor_diagnostic_reference_runtime_forbidden';
    throw error;
  }
}

module.exports = {
  POSTGRES_ADAPTER_CONTRACT,
  POSTGRES_BLOCKER,
  createVendorDiagnosticPostgresStorage,
  createVendorDiagnosticRuntime,
};
