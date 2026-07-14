'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const {
  assertProductionMonotonicAnchorAuthority,
  INDEPENDENT_WITNESS_ASSURANCE,
  TEST_WITNESS_ASSURANCE,
} = require('./monotonic-anchor-authority');
const { assertProductionVendorShadowAiStorage } = require('./vendor-shadow-ai-sqlite');
const {
  KEY_PURPOSES,
  keyFingerprint,
  parsePublicOnlyEd25519Key,
} = require('./vendor-signed-artifact');

const MAX_STEP_UP_AGE_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const OBSERVATION_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
const MAX_OBSERVATIONS_PER_SCOPE = 10_000;
const MAX_CLASSIFICATIONS = 10_000;
const MAX_GLOBAL_RELEASES = 128;
const MAX_DISTRIBUTIONS_PER_DEPLOYMENT = 128;
const GLOBAL_ROLLBACK_WINDOW = 32;
const DISTRIBUTION_ROLLBACK_WINDOW = 32;
const MAX_GLOBAL_HISTORY_TOMBSTONES = 128;
const MAX_DISTRIBUTION_HISTORY_TOMBSTONES = 128;
const MAX_DELIVERY_ATTEMPTS = 8;
const MAX_ACKNOWLEDGEMENTS = 8;
const MAX_FAILURES = 8;
const MAX_PAGE_SIZE = 100;
const PAGE_SNAPSHOT_TTL_MS = 5 * 60 * 1000;
const MAX_ACTIVE_PAGE_SNAPSHOTS = 32;
const MAX_CURSOR_BYTES = 2048;
const MAX_ARCHIVED_KEYS = 18;
const MAX_ACTIVE_AUDIT_EVENTS = 2048;
const MAX_GOVERNANCE_ROOTS = 50_000;
const GLOBAL_CATALOG_SIGNATURE_DOMAIN = protocol.SIGNATURE_DOMAINS[
  protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE
];
const INTEGRITY_DOMAINS = Object.freeze({
  AUTHORIZATION: 'shadow.authorization-link.v1',
  OBSERVATION: 'shadow.observation.v1',
  REVIEW: 'shadow.review.v1',
  CLASSIFICATION: 'shadow.classification.v1',
  DOMAIN_CLAIM: 'shadow.domain-claim.v1',
  GLOBAL_RELEASE: 'shadow.global-release.v1',
  DISTRIBUTION: 'shadow.distribution.v1',
  ADOPTION: 'shadow.adoption.v1',
  ACK_CLAIM: 'shadow.ack-claim.v1',
  AUDIT_EVENT: 'shadow.audit-event.v1',
  AUDIT_HIGH_WATER: 'shadow.audit-high-water.v1',
  AUDIT_CHECKPOINT: 'shadow.audit-checkpoint.v1',
  STATE_HEAD: 'shadow.state-head.v1',
  STATE_PENDING: 'shadow.state-pending.v1',
  PAGE_DESCRIPTOR: 'shadow.page-descriptor.v1',
  PAGE_CURSOR: 'shadow.page-cursor.v1',
  CONSENT_EPOCH: 'shadow.consent-epoch.v1',
  GLOBAL_HISTORY_TOMBSTONE: 'shadow.global-history-tombstone.v1',
  GLOBAL_HISTORY_CHECKPOINT: 'shadow.global-history-checkpoint.v1',
  DISTRIBUTION_HISTORY_TOMBSTONE: 'shadow.distribution-history-tombstone.v1',
  DISTRIBUTION_HISTORY_CHECKPOINT: 'shadow.distribution-history-checkpoint.v1',
});
const AUDIT_INTEGRITY_DOMAINS = new Set([
  INTEGRITY_DOMAINS.AUDIT_EVENT,
  INTEGRITY_DOMAINS.AUDIT_HIGH_WATER,
  INTEGRITY_DOMAINS.AUDIT_CHECKPOINT,
]);
const COMMAND_INTEGRITY_DOMAINS = new Set([
  INTEGRITY_DOMAINS.AUTHORIZATION,
  INTEGRITY_DOMAINS.ACK_CLAIM,
]);
const PAGINATION_INTEGRITY_DOMAINS = new Set([
  INTEGRITY_DOMAINS.PAGE_DESCRIPTOR,
  INTEGRITY_DOMAINS.PAGE_CURSOR,
]);
const AUDIT_ACTIONS = Object.freeze({
  CANDIDATE_INGESTED: 'shadow_candidate_ingested',
  CANDIDATE_REVIEWED: 'shadow_candidate_reviewed',
  GLOBAL_CATALOG_PUBLISHED: 'shadow_global_catalog_published',
  GLOBAL_CATALOG_ROLLED_BACK: 'shadow_global_catalog_rolled_back',
  DISTRIBUTION_CREATED: 'shadow_distribution_created',
  DISTRIBUTION_DELIVERED: 'shadow_distribution_delivered',
  DISTRIBUTION_ACKNOWLEDGED: 'shadow_distribution_acknowledged',
  CUSTOMER_OBSERVATIONS_READ: 'shadow_customer_observations_read',
  GLOBAL_CLASSIFICATIONS_READ: 'shadow_global_classifications_read',
  DISTRIBUTION_STATUS_READ: 'shadow_distribution_status_read',
  CONSENT_LOCAL_DATA_PURGED: 'shadow_consent_local_data_purged',
});

const PURPOSE_ROLES = Object.freeze({
  connector_ingest: new Set(['customer_connector']),
  analyst_review: new Set(['shadow_ai_analyst', 'vendor_security_admin']),
  global_publish: new Set(['vendor_owner', 'vendor_security_admin']),
  global_rollback: new Set(['vendor_owner', 'vendor_security_admin']),
  distribution_create: new Set(['vendor_owner', 'catalog_publisher']),
  distribution_deliver: new Set(['vendor_owner', 'catalog_publisher']),
  customer_ack: new Set(['customer_connector']),
  customer_observation_read: new Set([
    'customer_security_admin', 'shadow_ai_analyst', 'vendor_owner', 'vendor_security_admin',
  ]),
  global_catalog_read: new Set(['shadow_ai_analyst', 'vendor_owner', 'vendor_security_admin']),
  distribution_status: new Set(['customer_security_admin', 'vendor_owner', 'catalog_publisher']),
});
const STEP_UP_PURPOSES = new Set([
  'analyst_review', 'global_publish', 'global_rollback',
  'distribution_create', 'distribution_deliver',
]);
const GLOBAL_ONLY_PURPOSES = new Set([
  'global_publish', 'global_rollback', 'global_catalog_read',
]);
const CONFIRMATION_PURPOSES = new Set([
  'global_publish', 'global_rollback', 'distribution_create',
  'distribution_deliver', 'shadow_domain_override',
]);
const AUTHORIZATION_KEYS = [
  'actorRole', 'authEventId', 'authenticatedAt', 'customerId', 'deploymentId',
  'expiresAt', 'purposes', 'schemaVersion', 'stepUpAt',
];
const CONFIRMATION_KEYS = [
  'authEventId', 'confirmationId', 'confirmedAt', 'expiresAt',
  'operationDigest', 'purpose', 'schemaVersion',
];
const CONSENT_KEYS = [
  'consentId', 'customerId', 'deploymentId', 'grantedAt', 'revision',
  'revokedAt', 'schemaVersion', 'scope', 'status',
];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const SAFE_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const FORBIDDEN_METADATA_KEY_RE = /^(?:prompt|promptText|rawPrompt|rawContent|requestBody|responseBody)$/i;
const SENSITIVE_VALUE_PATTERNS = Object.freeze([
  /\b\d{3}-\d{2}-\d{4}\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /(?:prompt|sensitive|secret)[_-]?canary/i,
]);
const PRIVATE_TX_RESULT = Symbol('vendor-shadow-ai-transaction-result');
const EXTERNAL_GOVERNANCE_PREFIX = 'shadow-governance:';
const EXTERNAL_AUDIT_NAMESPACE = 'shadow-audit';
const ZERO_DIGEST = '0'.repeat(64);
const OWNER_CATALOG_WITNESS_PURPOSE = 'owner_catalog_witness';

function createVendorShadowAiIntelligence(options = {}) {
  if (referenceRuntimeProhibited(options)) throw fault('production_constructor_required');
  const storage = options.storage;
  if (!storage || typeof storage.transaction !== 'function') throw fault('storage_contract_invalid');
  const production = false;
  const clock = typeof options.clock === 'function' ? options.clock : Date.now;
  const randomUUID = typeof options.randomUUID === 'function' ? options.randomUUID : crypto.randomUUID;
  const integrity = createIntegrityRouter(options);
  const anchorAuthority = requireAnchorAuthority(
    options.anchorAuthority, options.allowTestWitness === true,
  );
  const anchorDescriptor = anchorAuthority.describe();
  const keyAuthority = createCatalogKeyAuthority(
    options.catalogKeyAuthority, options.authorityManifest,
    new Set([...integrity.fingerprints, anchorDescriptor.identity]), integrity,
    new Set([integrity.descriptor('catalog').identity, anchorDescriptor.identity]),
  );
  const coordinator = { tail: Promise.resolve() };

  return Object.freeze({
    ingestCandidate: (command) => ingestCandidate(command, context()),
    reviewCandidate: (command) => reviewCandidate(command, context()),
    publishGlobalCatalog: (command) => publishGlobalCatalog(command, context()),
    rollbackGlobalCatalog: (command) => rollbackGlobalCatalog(command, context()),
    createDistribution: (command) => createDistribution(command, context()),
    markDelivered: (command) => markDelivered(command, context()),
    recordCustomerAcknowledgement: (command) => recordCustomerAcknowledgement(command, context()),
    listCustomerObservations: (command) => listCustomerObservations(command, context()),
    listGlobalClassifications: (command) => listGlobalClassifications(command, context()),
    distributionStatus: (command) => distributionStatus(command, context()),
    applyConsentTransition: (scope) => applyConsentTransition(scope, context()),
    readiness: () => vendorReadiness(context()),
    reconcileIntegrity: () => reconcileIntegrity(context()),
    signingKeyReferenceCounts: () => vendorSigningKeyReferenceCounts(context()),
  });

  function context() {
    return {
      storage, clock, randomUUID, integrity, keyAuthority, anchorAuthority, coordinator, production,
    };
  }
}

function referenceRuntimeProhibited(options) {
  const actualProduction = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (actualProduction) return true;
  const requestedProduction = String(options?.env?.NODE_ENV || '')
    .trim().toLowerCase() === 'production';
  return requestedProduction || options?.production === true;
}

function createProductionVendorShadowAiIntelligence(options = {}) {
  try {
    assertProductionVendorShadowAiStorage(options.storage);
    assertProductionMonotonicAnchorAuthority(options.anchorAuthority);
  } catch { throw fault('shadow_ai_production_adapter_required'); }
  if (!options.authorityManifest || typeof options.authorityManifest.read !== 'function'
      || typeof options.authorityManifest.reconcile !== 'function') {
    throw fault('authority_manifest_required');
  }
  // Owner's synchronous consent transition/outbox adapter is not wired yet.
  throw fault('consent_transition_adapter_unavailable');
}

function requireAnchorAuthority(value, allowTestWitness) {
  const methods = ['abort', 'describe', 'finalize', 'list', 'listPending', 'prepare', 'read'];
  if (!value || typeof value !== 'object'
      || methods.some((method) => typeof value[method] !== 'function')) {
    throw fault('anchor_authority_invalid');
  }
  const descriptor = value.describe();
  if (!plainRecord(descriptor)
      || !exactKeys(descriptor, ['assurance', 'identity', 'keyId', 'purpose'])
      || descriptor.purpose !== OWNER_CATALOG_WITNESS_PURPOSE
      || ![INDEPENDENT_WITNESS_ASSURANCE, TEST_WITNESS_ASSURANCE].includes(
        descriptor.assurance,
      )
      || (descriptor.assurance === TEST_WITNESS_ASSURANCE && !allowTestWitness)
      || !/^rw-anchor-[a-z0-9][a-z0-9_.-]{0,87}$/.test(String(descriptor.keyId || ''))
      || !SHA256_RE.test(String(descriptor.identity || ''))) {
    throw fault('anchor_authority_invalid');
  }
  return value;
}

function createIntegrityRouter(options) {
  if (options.integrityAuthority !== undefined) throw fault('integrity_authority_split_required');
  const catalog = createIntegrityAuthority(options.catalogIntegrityAuthority,
    'rw-catalog-integrity-');
  const audit = createIntegrityAuthority(options.platformAuditAuthority,
    'rw-platform-audit-');
  const command = createIntegrityAuthority(options.commandIdempotencyAuthority,
    'rw-command-idempotency-');
  const pagination = createIntegrityAuthority(options.paginationCursorAuthority,
    'rw-pagination-cursor-');
  const authorities = { catalog, audit, command, pagination };
  const fingerprints = new Set(Object.values(authorities).map((value) => value.fingerprint));
  if (fingerprints.size !== Object.keys(authorities).length) {
    throw fault('integrity_authority_identity_reused');
  }
  return Object.freeze({
    fingerprints,
    descriptor(role) {
      const value = authorities[role];
      if (!value) throw fault('integrity_authority_invalid');
      return Object.freeze({ keyId: value.keyId, identity: value.fingerprint });
    },
    seal(domain, payload) { return integrityAuthorityFor(domain, authorities).seal(domain, payload); },
    open(domain, wrapped) { return integrityAuthorityFor(domain, authorities).open(domain, wrapped); },
  });
}

function integrityAuthorityFor(domain, authorities) {
  if (AUDIT_INTEGRITY_DOMAINS.has(domain)) return authorities.audit;
  if (COMMAND_INTEGRITY_DOMAINS.has(domain)) return authorities.command;
  if (PAGINATION_INTEGRITY_DOMAINS.has(domain)) return authorities.pagination;
  if (!Object.values(INTEGRITY_DOMAINS).includes(domain)) {
    throw fault('integrity_domain_invalid');
  }
  return authorities.catalog;
}

function createIntegrityAuthority(value, keyPrefix) {
  if (!plainRecord(value) || !exactKeys(value, ['keyId', 'secret'])) {
    throw fault('integrity_authority_invalid');
  }
  if (!SAFE_ID_RE.test(value.keyId) || !value.keyId.startsWith(keyPrefix)) {
    throw fault('integrity_authority_invalid');
  }
  if (!Buffer.isBuffer(value.secret) || value.secret.length !== 32) {
    throw fault('integrity_authority_invalid');
  }
  const secret = Buffer.from(value.secret);
  const fingerprint = digestBytes(secret);
  return Object.freeze({
    keyId: value.keyId,
    fingerprint,
    seal(domain, payload) {
      assertPlainTree(payload);
      assertNoSensitiveMetadata(payload);
      const snapshot = clone(payload);
      const mac = crypto.createHmac('sha256', secret)
        .update(integrityInput(domain, value.keyId, snapshot)).digest('hex');
      return Object.freeze({ integrityVersion: 1, keyId: value.keyId, domain, payload: snapshot, mac });
    },
    open(domain, wrapped) {
      if (!plainRecord(wrapped)
          || !exactKeys(wrapped, ['domain', 'integrityVersion', 'keyId', 'mac', 'payload'])
          || wrapped.integrityVersion !== 1 || wrapped.keyId !== value.keyId
          || wrapped.domain !== domain || !SHA256_RE.test(String(wrapped.mac || ''))) {
        throw fault('integrity_state_invalid');
      }
      assertPlainTree(wrapped.payload);
      assertNoSensitiveMetadata(wrapped.payload);
      const expected = crypto.createHmac('sha256', secret)
        .update(integrityInput(domain, value.keyId, wrapped.payload)).digest();
      const supplied = Buffer.from(wrapped.mac, 'hex');
      if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
        throw fault('integrity_state_invalid');
      }
      return clone(wrapped.payload);
    },
  });
}

function createCatalogKeyAuthority(provider, authorityManifest, additionalForbiddenIdentities,
  integrity, supplementalIdentities) {
  if (typeof provider !== 'function') throw fault('catalog_key_authority_invalid');
  if (authorityManifest !== undefined
      && (!authorityManifest || typeof authorityManifest.registry !== 'function'
        || typeof authorityManifest.reconcile !== 'function')) {
    throw fault('catalog_key_authority_invalid');
  }
  return Object.freeze({
    resolve() {
      const raw = provider();
      if (!plainRecord(raw)
          || !exactKeys(raw, ['distribution', 'forbiddenPublicKeyFingerprints', 'global'])) {
        throw fault('catalog_key_authority_invalid');
      }
      const forbidden = normalizeForbiddenFingerprints(raw.forbiddenPublicKeyFingerprints);
      const identities = new Set([...forbidden, ...additionalForbiddenIdentities]);
      const global = normalizeCatalogPurpose(raw.global, 'global', identities);
      const distribution = normalizeCatalogPurpose(raw.distribution, 'distribution', identities);
      if (authorityManifest) authorityManifest.reconcile();
      const registry = authorityManifest ? authorityManifest.registry() : null;
      if (registry) {
        assertManifestForbiddenAuthorities(
          registry, raw.forbiddenPublicKeyFingerprints,
        );
        assertManifestIntegrityAuthority(
          registry, KEY_PURPOSES.PLATFORM_AUDIT, integrity.descriptor('audit'),
        );
        assertManifestIntegrityAuthority(
          registry, KEY_PURPOSES.COMMAND_IDEMPOTENCY, integrity.descriptor('command'),
        );
        assertManifestIntegrityAuthority(
          registry, KEY_PURPOSES.PAGINATION_CURSOR, integrity.descriptor('pagination'),
        );
        assertSupplementalIdentitiesDistinct(registry, supplementalIdentities);
        assertCatalogManifest(registry, KEY_PURPOSES.CATALOG_GLOBAL, global);
        assertCatalogManifest(registry, KEY_PURPOSES.CATALOG_DISTRIBUTION, distribution);
      }
      return Object.freeze({
        global, distribution, forbidden, registry,
        manifestGeneration: registry?.generation || 1,
      });
    },
  });
}

function assertManifestForbiddenAuthorities(registry, value) {
  const purposes = {
    audit_request: KEY_PURPOSES.AUDIT_REQUEST,
    entitlement: KEY_PURPOSES.ENTITLEMENT,
    offline_license: KEY_PURPOSES.OFFLINE_LICENSE,
    online_verdict: KEY_PURPOSES.ONLINE_VERDICT,
    policy: KEY_PURPOSES.POLICY,
  };
  for (const [name, purpose] of Object.entries(purposes)) {
    let record;
    try { record = registry.get(purpose); }
    catch { throw fault('catalog_key_authority_invalid'); }
    if (!record || record.identity !== value[name]) {
      throw fault('catalog_key_authority_invalid');
    }
  }
}

function assertManifestIntegrityAuthority(registry, purpose, descriptor) {
  let record;
  try { record = registry.get(purpose); }
  catch { throw fault('catalog_key_authority_invalid'); }
  if (!record || record.keyId !== descriptor.keyId || record.identity !== descriptor.identity) {
    throw fault('catalog_key_authority_invalid');
  }
}

function assertSupplementalIdentitiesDistinct(registry, supplemental) {
  const manifestIdentities = new Set();
  try {
    for (const purpose of Object.values(KEY_PURPOSES)) {
      for (const record of registry.list(purpose)) manifestIdentities.add(record.identity);
    }
  } catch { throw fault('catalog_key_authority_invalid'); }
  if ([...supplemental].some((identity) => manifestIdentities.has(identity))) {
    throw fault('vendor_key_identity_reused');
  }
}

function assertCatalogManifest(registry, purpose, resolved) {
  if (!registry || typeof registry.list !== 'function'
      || typeof registry.get !== 'function' || !Number.isSafeInteger(registry.generation)
      || registry.generation < 1) throw fault('catalog_key_authority_invalid');
  let records;
  try { records = registry.list(purpose); }
  catch { throw fault('catalog_key_authority_invalid'); }
  if (!Array.isArray(records) || records.length < 1 || records.length > MAX_ARCHIVED_KEYS
      || records.filter((record) => ['current', 'next'].includes(record.slot)).length > 2) {
    throw fault('catalog_key_authority_invalid');
  }
  const byId = new Map(records.map((record) => [record.keyId, record]));
  if (byId.size !== records.length || byId.size !== resolved.archived.size
      || registry.get(purpose)?.keyId !== resolved.current.keyId
      || records.find((record) => record.slot === 'next')?.keyId
        !== (resolved.next?.keyId || undefined)) {
    throw fault('catalog_key_authority_invalid');
  }
  for (const [keyId, trusted] of resolved.archived) {
    const record = byId.get(keyId);
    if (!record || record.identity !== trusted.fingerprint
        || !['current', 'next', 'verifyOnly'].includes(record.slot)) {
      throw fault('catalog_key_authority_invalid');
    }
  }
}

function normalizeForbiddenFingerprints(value) {
  if (!plainRecord(value)
      || !exactKeys(value, [
        'audit_request', 'entitlement', 'offline_license', 'online_verdict', 'policy',
      ])) {
    throw fault('catalog_key_authority_invalid');
  }
  const fingerprints = Object.values(value);
  if (!fingerprints.every((item) => SHA256_RE.test(String(item || '')))
      || new Set(fingerprints).size !== fingerprints.length) {
    throw fault('catalog_key_authority_invalid');
  }
  return new Set(fingerprints);
}

function normalizeCatalogPurpose(value, purpose, identities) {
  if (!plainRecord(value)
      || !exactKeys(value, ['archivedPublicKeys', 'current', 'next'])) {
    throw fault('catalog_key_authority_invalid');
  }
  const archived = normalizeArchivedKeys(value.archivedPublicKeys, identities, purpose);
  const current = normalizeSigningSlot(value.current, 'current', archived, identities, purpose);
  const next = value.next === null ? null
    : normalizeSigningSlot(value.next, 'next', archived, identities, purpose);
  if (next && (next.keyId === current.keyId || next.fingerprint === current.fingerprint)) {
    throw fault('vendor_key_identity_reused');
  }
  return Object.freeze({ current, next, archived });
}

function normalizeArchivedKeys(value, identities, purpose) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fault('catalog_key_authority_invalid');
  }
  const entries = value instanceof Map ? [...value.entries()] : Object.entries(value);
  if (!entries.length || entries.length > MAX_ARCHIVED_KEYS) throw fault('catalog_key_authority_invalid');
  const output = new Map();
  const fingerprints = new Set();
  for (const [rawId, rawKey] of entries) {
    const keyId = String(rawId || '');
    if (!SAFE_ID_RE.test(keyId) || !keyId.startsWith(`rw-catalog-${purpose}-`)) {
      throw fault('vendor_key_purpose_mismatch');
    }
    const publicKey = publicEd25519(rawKey);
    const fingerprint = keyFingerprint(publicKey);
    if (identities.has(fingerprint) || fingerprints.has(fingerprint)) {
      throw fault('vendor_key_identity_reused');
    }
    fingerprints.add(fingerprint);
    identities.add(fingerprint);
    output.set(keyId, Object.freeze({ publicKey, fingerprint }));
  }
  return output;
}

function normalizeSigningSlot(value, slot, archived, identities, purpose) {
  if (!plainRecord(value) || !exactKeys(value, ['keyId', 'privateKey'])) {
    throw fault('catalog_key_authority_invalid');
  }
  const keyId = String(value.keyId || '');
  if (!SAFE_ID_RE.test(keyId) || !keyId.startsWith(`rw-catalog-${purpose}-`)) {
    throw fault('vendor_key_purpose_mismatch');
  }
  let privateKey;
  try { privateKey = value.privateKey instanceof crypto.KeyObject
    ? value.privateKey : crypto.createPrivateKey(value.privateKey); }
  catch { throw fault('catalog_key_authority_invalid'); }
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw fault('catalog_key_authority_invalid');
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const fingerprint = keyFingerprint(publicKey);
  const trusted = archived.get(keyId);
  if (!trusted || trusted.fingerprint !== fingerprint) {
    throw fault('catalog_key_authority_invalid');
  }
  return Object.freeze({ slot, keyId, privateKey, publicKey, fingerprint });
}

function publicEd25519(value) {
  let key;
  try { key = parsePublicOnlyEd25519Key(value); }
  catch { throw fault('catalog_key_authority_invalid'); }
  return key;
}

function integrityInput(domain, keyId, payload) {
  return Buffer.from(`${domain}\0${keyId}\0${protocol.canonicalJson(payload)}`, 'utf8');
}

async function transact(ctx, work) {
  const execute = () => transactSerialized(ctx, work);
  const result = ctx.coordinator.tail.then(execute, execute);
  ctx.coordinator.tail = result.then(() => undefined, () => undefined);
  return result;
}

async function transactSerialized(ctx, work) {
  let callbacks = 0;
  const token = Object.freeze({});
  const postCommit = [];
  const lifecycle = Object.freeze({
    defer(callback) {
      if (typeof callback !== 'function') throw fault('storage_contract_invalid');
      postCommit.push(callback);
    },
  });
  const returned = await ctx.storage.transaction(async (tx) => {
    callbacks += 1;
    if (callbacks !== 1 || !tx || typeof tx !== 'object') throw fault('storage_contract_invalid');
    const value = await work(tx, lifecycle);
    return Object.freeze({ [PRIVATE_TX_RESULT]: token, value });
  });
  if (callbacks !== 1 || !returned || returned[PRIVATE_TX_RESULT] !== token) {
    throw fault('storage_contract_invalid');
  }
  for (const callback of postCommit) await callback();
  return returned.value;
}

function trustedNow(clock) {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 0
      || value > 8_640_000_000_000_000 - OBSERVATION_RETENTION_MS) {
    throw fault('trusted_clock_invalid');
  }
  let iso;
  try { iso = new Date(value).toISOString(); }
  catch { throw fault('trusted_clock_invalid'); }
  return Object.freeze({ ms: value, iso });
}

function operationDigest(value) {
  assertPlainTree(value);
  assertNoSensitiveMetadata(value);
  return digestText(protocol.canonicalJson(value));
}

function exactCommand(value, keys, code) {
  if (!plainRecord(value) || !exactKeys(value, keys)) throw fault(code);
  assertPlainTree(value);
  assertNoSensitiveMetadata(value);
  return clone(value);
}

function exactKeys(value, keys) {
  return Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertPlainTree(value, depth = 0) {
  if (depth > 32) throw fault('plain_data_required');
  if (value === null || ['string', 'boolean'].includes(typeof value)) return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (Array.isArray(value)) {
    for (const item of value) assertPlainTree(item, depth + 1);
    return;
  }
  if (!plainRecord(value)) throw fault('plain_data_required');
  for (const item of Object.values(value)) assertPlainTree(item, depth + 1);
}

function clone(value) {
  assertPlainTree(value);
  assertNoSensitiveMetadata(value);
  return JSON.parse(JSON.stringify(value));
}

function assertNoSensitiveMetadata(value, depth = 0, seen = new Set()) {
  if (depth > 32) throw fault('sensitive_metadata_forbidden');
  if (typeof value === 'string') {
    if (SENSITIVE_VALUE_PATTERNS.some((pattern) => pattern.test(value))) {
      throw fault('sensitive_metadata_forbidden');
    }
    return;
  }
  if (value === null || ['boolean', 'number', 'undefined'].includes(typeof value)) return;
  if (typeof value !== 'object') throw fault('sensitive_metadata_forbidden');
  if (seen.has(value)) throw fault('sensitive_metadata_forbidden');
  seen.add(value);
  if (value instanceof Map) {
    for (const [key, item] of value.entries()) {
      assertNoSensitiveMetadata(key, depth + 1, seen);
      assertNoSensitiveMetadata(item, depth + 1, seen);
    }
  } else if (Array.isArray(value)) {
    for (const item of value) assertNoSensitiveMetadata(item, depth + 1, seen);
  } else {
    for (const [key, item] of Object.entries(value)) {
      if (FORBIDDEN_METADATA_KEY_RE.test(key)) throw fault('sensitive_metadata_forbidden');
      assertNoSensitiveMetadata(item, depth + 1, seen);
    }
  }
  seen.delete(value);
}

function digestText(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function digestBytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function fault(code) {
  const error = new Error('vendor Shadow AI intelligence operation rejected');
  error.code = code;
  return error;
}

async function authorize(tx, request, now, ctx) {
  const { integrity } = ctx;
  const { authEventId, purpose, opDigest, scope = null } = request;
  if (!UUID_RE.test(String(authEventId || '')) || !PURPOSE_ROLES[purpose]) {
    throw fault('authorization_invalid');
  }
  await assertNoPendingGovernance(tx, ctx);
  await readAuditState(tx, now, ctx);
  const raw = await call(tx, 'resolveAuthorization', authEventId);
  const authorization = validateAuthorization(raw, purpose, scope, now);
  if (authorization.authEventId !== authEventId) throw fault('authorization_invalid');
  const claim = claimResult(await call(tx, 'claimAuthorization', authEventId, opDigest));
  if (claim === 'conflict') throw fault('authorization_reuse_conflict');
  if (!['claimed', 'replay'].includes(claim)) throw fault('storage_contract_invalid');
  const linkPayload = {
    schemaVersion: 1,
    linkId: digestText(`authorization\0${authEventId}\0${purpose}\0${opDigest}`),
    authEventId,
    actorRole: authorization.actorRole,
    purpose,
    operationDigest: opDigest,
    scopeDigest: digestText(protocol.canonicalJson(scope)),
    authorizationDigest: operationDigest(authorization),
    linkedAt: now.iso,
  };
  const sealed = integrity.seal(INTEGRITY_DOMAINS.AUTHORIZATION, linkPayload);
  const existing = await call(tx, 'readAuthorizationLink', linkPayload.linkId);
  if (existing) {
    const opened = integrity.open(INTEGRITY_DOMAINS.AUTHORIZATION, existing);
    if (operationDigest(withoutTime(opened, 'linkedAt'))
        !== operationDigest(withoutTime(linkPayload, 'linkedAt'))) {
      throw fault('authorization_link_conflict');
    }
  } else if (await call(tx, 'insertAuthorizationLink', linkPayload.linkId, sealed) !== true) {
    throw fault('authorization_link_conflict');
  }
  return Object.freeze({ authorization, link: linkPayload, claim });
}

function validateAuthorization(value, purpose, scope, now) {
  if (!plainRecord(value) || !exactKeys(value, AUTHORIZATION_KEYS)
      || value.schemaVersion !== 1 || !UUID_RE.test(String(value.authEventId || ''))
      || !PURPOSE_ROLES[purpose].has(value.actorRole)
      || !Array.isArray(value.purposes) || !value.purposes.includes(purpose)
      || new Set(value.purposes).size !== value.purposes.length
      || !sortedStrings(value.purposes)
      || !value.purposes.every((item) => Object.hasOwn(PURPOSE_ROLES, item))) {
    throw fault('authorization_invalid');
  }
  assertNullableScope(value.customerId, value.deploymentId);
  const authenticatedAt = parseIso(value.authenticatedAt, 'authorization_invalid');
  const expiresAt = parseIso(value.expiresAt, 'authorization_invalid');
  if (authenticatedAt > now.ms + MAX_CLOCK_SKEW_MS || expiresAt <= now.ms
      || expiresAt <= authenticatedAt || expiresAt - authenticatedAt > 24 * 60 * 60 * 1000) {
    throw fault('authorization_invalid');
  }
  if (STEP_UP_PURPOSES.has(purpose)) validateStepUp(value.stepUpAt, now);
  else if (value.stepUpAt !== null) parseIso(value.stepUpAt, 'authorization_invalid');
  validateAuthorizationScope(value, purpose, scope);
  return clone(value);
}

function validateAuthorizationScope(value, purpose, scope) {
  const customerBound = new Set([
    'analyst_review', 'connector_ingest', 'customer_ack', 'customer_observation_read',
    'distribution_create', 'distribution_deliver', 'distribution_status',
  ]);
  if (GLOBAL_ONLY_PURPOSES.has(purpose)) {
    if (value.customerId !== null || value.deploymentId !== null) {
      throw fault('authorization_scope_invalid');
    }
    return;
  }
  if (!scope || !customerBound.has(purpose)) {
    if (['connector_ingest', 'customer_ack'].includes(purpose)) throw fault('authorization_scope_invalid');
    return;
  }
  validateScope(scope.customerId, scope.deploymentId);
  const isGlobalVendor = value.actorRole.startsWith('vendor_')
    || ['catalog_publisher', 'shadow_ai_analyst'].includes(value.actorRole);
  if (isGlobalVendor && value.customerId === null && value.deploymentId === null) return;
  if (value.customerId !== scope.customerId || value.deploymentId !== scope.deploymentId) {
    throw fault('authorization_scope_invalid');
  }
}

function validateStepUp(value, now) {
  if (value === null) throw fault('step_up_required');
  const stepUpAt = parseIso(value, 'step_up_required');
  if (stepUpAt > now.ms + MAX_CLOCK_SKEW_MS || now.ms - stepUpAt > MAX_STEP_UP_AGE_MS) {
    throw fault('step_up_required');
  }
}

async function confirmOperation(tx, request, authority, now, integrity) {
  const { confirmationId, purpose, opDigest } = request;
  if (!UUID_RE.test(String(confirmationId || '')) || !CONFIRMATION_PURPOSES.has(purpose)) {
    throw fault('confirmation_invalid');
  }
  const value = await call(tx, 'resolveConfirmation', confirmationId);
  if (!plainRecord(value) || !exactKeys(value, CONFIRMATION_KEYS)
      || value.schemaVersion !== 1 || value.confirmationId !== confirmationId
      || value.authEventId !== authority.authorization.authEventId || value.purpose !== purpose
      || value.operationDigest !== opDigest) {
    throw fault('confirmation_invalid');
  }
  const confirmedAt = parseIso(value.confirmedAt, 'confirmation_invalid');
  const expiresAt = parseIso(value.expiresAt, 'confirmation_invalid');
  if (confirmedAt > now.ms + MAX_CLOCK_SKEW_MS || now.ms - confirmedAt > MAX_STEP_UP_AGE_MS
      || expiresAt <= now.ms || expiresAt <= confirmedAt
      || expiresAt - confirmedAt > MAX_STEP_UP_AGE_MS) {
    throw fault('confirmation_invalid');
  }
  const claim = claimResult(await call(tx, 'claimConfirmation', confirmationId, opDigest));
  if (claim === 'conflict') throw fault('confirmation_reuse_conflict');
  if (!['claimed', 'replay'].includes(claim)) throw fault('storage_contract_invalid');
  const link = {
    schemaVersion: 1,
    linkId: digestText(`confirmation\0${confirmationId}\0${purpose}\0${opDigest}`),
    authEventId: value.authEventId,
    confirmationId,
    purpose,
    operationDigest: opDigest,
    parentAuthorizationLinkId: authority.link.linkId,
    confirmationDigest: operationDigest(value),
    linkedAt: now.iso,
  };
  const sealed = integrity.seal(INTEGRITY_DOMAINS.AUTHORIZATION, link);
  const existing = await call(tx, 'readAuthorizationLink', link.linkId);
  if (existing) {
    const opened = integrity.open(INTEGRITY_DOMAINS.AUTHORIZATION, existing);
    if (operationDigest(withoutTime(opened, 'linkedAt'))
        !== operationDigest(withoutTime(link, 'linkedAt'))) {
      throw fault('authorization_link_conflict');
    }
  } else if (await call(tx, 'insertAuthorizationLink', link.linkId, sealed) !== true) {
    throw fault('authorization_link_conflict');
  }
  return Object.freeze({ claim, link });
}

function validateConsent(value, expected, now, requireGranted = true) {
  if (!plainRecord(value) || !exactKeys(value, CONSENT_KEYS)
      || value.schemaVersion !== 1 || !UUID_RE.test(String(value.consentId || ''))
      || value.consentId !== expected.consentId
      || value.customerId !== expected.customerId || value.deploymentId !== expected.deploymentId
      || value.scope !== 'shadow_ai_candidates'
      || !['granted', 'revoked'].includes(value.status)
      || !Number.isSafeInteger(value.revision) || value.revision < 1) {
    throw fault('candidate_consent_invalid');
  }
  const grantedAt = parseIso(value.grantedAt, 'candidate_consent_invalid');
  if (grantedAt > now.ms + MAX_CLOCK_SKEW_MS) throw fault('candidate_consent_invalid');
  if (value.status === 'revoked') {
    if (value.revokedAt === null) throw fault('candidate_consent_invalid');
    const revokedAt = parseIso(value.revokedAt, 'candidate_consent_invalid');
    if (revokedAt < grantedAt || revokedAt > now.ms + MAX_CLOCK_SKEW_MS) {
      throw fault('candidate_consent_invalid');
    }
  } else if (value.revokedAt !== null) throw fault('candidate_consent_invalid');
  if (requireGranted && value.status !== 'granted') throw fault('candidate_consent_required');
  return clone(value);
}

async function enforceScopeConsent(tx, scope, now, ctx, authorizationLinkId, lifecycle,
  options = {}) {
  const raw = await call(tx, 'resolveScopeConsent', scope.customerId, scope.deploymentId);
  const consent = raw === null || raw === undefined ? null : validateConsent(raw, {
    consentId: raw.consentId,
    ...scope,
  }, now, false);
  const epochTransition = await syncConsentEpoch(tx, scope, consent, now, ctx.integrity);
  const consentEpoch = epochTransition.state;
  const granted = consent?.status === 'granted';
  const bindingChanged = epochTransition.changed && epochTransition.previous !== null;
  if (granted && !bindingChanged) return { granted: true, consent, consentEpoch };
  const result = await call(tx, 'purgeScopeObservations', scope.customerId,
    scope.deploymentId, MAX_OBSERVATIONS_PER_SCOPE);
  if (!plainRecord(result) || !exactKeys(result, ['purged', 'remaining'])
      || !Number.isSafeInteger(result.purged) || result.purged < 0
      || result.purged > MAX_OBSERVATIONS_PER_SCOPE
      || result.remaining !== 0) throw fault('storage_contract_invalid');
  const snapshots = await call(tx, 'purgeScopePageSnapshots', scope.customerId,
    scope.deploymentId, MAX_ACTIVE_PAGE_SNAPSHOTS);
  if (!plainRecord(snapshots) || !exactKeys(snapshots, ['purged', 'remaining'])
      || !Number.isSafeInteger(snapshots.purged) || snapshots.purged < 0
      || snapshots.purged > MAX_ACTIVE_PAGE_SNAPSHOTS || snapshots.remaining !== 0) {
    throw fault('storage_contract_invalid');
  }
  const status = granted ? 'superseded' : (consent ? 'revoked' : 'deleted');
  if (!granted || options.auditGrantedTransition === true) {
    await appendAudit(tx, {
      action: AUDIT_ACTIONS.CONSENT_LOCAL_DATA_PURGED,
      outcome: status,
      authorizationLinkId,
      scope,
      referenceDigest: operationDigest({
        scope,
        status,
        consentId: consent?.consentId || null,
        consentRevision: consent?.revision || null,
        consentEpoch: consentEpoch.epoch,
        previousConsentBinding: epochTransition.previous
          ? operationDigest(consentEpochBinding(epochTransition.previous)) : null,
        currentConsentBinding: operationDigest(consentEpochBinding(consentEpoch)),
        purged: result.purged,
        snapshotsPurged: snapshots.purged,
      }),
    }, now, ctx, lifecycle);
  }
  if (granted) return { granted: true, consent, consentEpoch };
  return { granted: false, code: consent ? 'consent_revoked' : 'consent_deleted',
    consentEpoch };
}

async function syncConsentEpoch(tx, scope, consent, now, integrity) {
  const wrapped = await call(tx, 'readScopeConsentEpoch', scope.customerId, scope.deploymentId);
  const current = wrapped ? integrity.open(INTEGRITY_DOMAINS.CONSENT_EPOCH, wrapped) : null;
  if (current) validateConsentEpoch(current, scope, now);
  const binding = {
    consentId: consent?.consentId || null,
    consentRevision: consent?.revision || null,
    consentDigest: consent ? operationDigest(consent) : null,
    status: consent?.status || 'deleted',
  };
  if (current && current.consentId === binding.consentId
      && current.consentRevision === binding.consentRevision
      && current.consentDigest === binding.consentDigest && current.status === binding.status) {
    return { state: current, previous: current, changed: false };
  }
  const next = {
    schemaVersion: 1,
    ...scope,
    epoch: (current?.epoch || 0) + 1,
    ...binding,
    updatedAt: now.iso,
  };
  const sealed = integrity.seal(INTEGRITY_DOMAINS.CONSENT_EPOCH, next);
  if (await call(tx, 'compareAndSetScopeConsentEpoch', scope.customerId,
    scope.deploymentId, current?.epoch || 0, sealed) !== true) {
    throw fault('consent_epoch_conflict');
  }
  return { state: next, previous: current, changed: true };
}

function consentEpochBinding(value) {
  return {
    consentId: value.consentId,
    consentRevision: value.consentRevision,
    consentDigest: value.consentDigest,
    status: value.status,
    epoch: value.epoch,
  };
}

async function applyConsentTransition(scopeValue, ctx) {
  const scope = exactCommand(scopeValue, ['customerId', 'deploymentId'],
    'consent_transition_scope_invalid');
  validateScope(scope.customerId, scope.deploymentId);
  return transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authorizationLinkId = operationDigest({
      kind: 'shadow_consent_transition_adapter',
      scope,
    });
    const result = await enforceScopeConsent(tx, scope, now, ctx,
      authorizationLinkId, lifecycle, { auditGrantedTransition: true });
    const epoch = result.consentEpoch || null;
    return {
      schemaVersion: 1,
      ...scope,
      status: result.granted ? 'granted' : result.code,
      epoch: epoch?.epoch || null,
      consentId: epoch?.consentId || null,
      consentRevision: epoch?.consentRevision || null,
      consentDigest: epoch?.consentDigest || null,
    };
  });
}

function validateConsentEpoch(value, scope, now) {
  const keys = [
    'consentDigest', 'consentId', 'consentRevision', 'customerId', 'deploymentId',
    'epoch', 'schemaVersion', 'status', 'updatedAt',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || value.customerId !== scope.customerId || value.deploymentId !== scope.deploymentId
      || !Number.isSafeInteger(value.epoch) || value.epoch < 1
      || !['granted', 'revoked', 'deleted'].includes(value.status)) {
    throw fault('consent_epoch_invalid');
  }
  const deleted = value.status === 'deleted';
  if (deleted !== (value.consentId === null && value.consentRevision === null
      && value.consentDigest === null)) throw fault('consent_epoch_invalid');
  if (!deleted && (!UUID_RE.test(String(value.consentId || ''))
      || !Number.isSafeInteger(value.consentRevision) || value.consentRevision < 1
      || !SHA256_RE.test(String(value.consentDigest || '')))) {
    throw fault('consent_epoch_invalid');
  }
  if (parseIso(value.updatedAt, 'consent_epoch_invalid') > now.ms) {
    throw fault('clock_rollback');
  }
}

async function appendAudit(tx, request, now, ctx, lifecycle) {
  const { integrity } = ctx;
  const current = await readAuditState(tx, now, ctx);
  if (current.activeCount >= MAX_ACTIVE_AUDIT_EVENTS) {
    const firstWrapped = current.firstActiveWrapped;
    if (!firstWrapped) throw fault('audit_compaction_failed');
    const first = integrity.open(INTEGRITY_DOMAINS.AUDIT_EVENT, firstWrapped);
    validateAuditEvent(first);
    if (first.sequence !== current.checkpoint.sequence + 1
        || first.previousDigest !== current.checkpoint.headDigest) {
      throw fault('audit_compaction_failed');
    }
    const checkpoint = {
      schemaVersion: 1,
      sequence: first.sequence,
      count: current.checkpoint.count + 1,
      headDigest: first.eventDigest,
      recordedAt: first.recordedAt,
    };
    if (checkpoint.count !== checkpoint.sequence
        || await call(tx, 'compareAndSetAuditCheckpoint', current.checkpoint.sequence,
          integrity.seal(INTEGRITY_DOMAINS.AUDIT_CHECKPOINT, checkpoint)) !== true
        || await call(tx, 'deleteAuditEvent', first.sequence,
          operationDigest(firstWrapped)) !== true) throw fault('audit_compaction_failed');
  }
  const sequence = current.sequence + 1;
  const descriptor = {
    schemaVersion: 1,
    sequence,
    action: request.action,
    outcome: request.outcome || 'success',
    authorizationLinkId: request.authorizationLinkId,
    scopeDigest: digestText(protocol.canonicalJson(request.scope || null)),
    referenceDigest: request.referenceDigest,
    version: request.version ?? null,
    recordedAt: now.iso,
  };
  const eventDigest = digestText(`${current.headDigest}\0${protocol.canonicalJson(descriptor)}`);
  const event = { ...descriptor, previousDigest: current.headDigest, eventDigest };
  const eventWrapped = integrity.seal(INTEGRITY_DOMAINS.AUDIT_EVENT, event);
  if (await call(tx, 'appendAudit', sequence, eventDigest, eventWrapped) !== true) {
    throw fault('audit_commit_failed');
  }
  const next = integrity.seal(INTEGRITY_DOMAINS.AUDIT_HIGH_WATER, {
    schemaVersion: 1, sequence, count: current.count + 1,
    headDigest: eventDigest, recordedAt: now.iso,
  });
  if (await call(tx, 'compareAndSetAuditHighWater', current.sequence, next) !== true) {
    throw fault('audit_high_water_conflict');
  }
  const transition = {
    namespace: EXTERNAL_AUDIT_NAMESPACE,
    expectedRevision: current.sequence,
    expectedDigest: current.headDigest,
    targetRevision: sequence,
    targetDigest: eventDigest,
    witnessDigest: operationDigest(eventWrapped),
  };
  const anchor = ctx.anchorAuthority.prepare(transition);
  if (!anchor.pending || anchor.revision !== current.sequence
      || anchor.headDigest !== current.headDigest) throw fault('audit_anchor_conflict');
  lifecycle.defer(() => {
    const finalized = ctx.anchorAuthority.finalize(transition);
    if (finalized.pending || finalized.revision !== sequence
        || finalized.headDigest !== eventDigest) throw fault('audit_anchor_conflict');
  });
  return { sequence, count: current.count + 1, headDigest: eventDigest,
    recordedAt: now.iso, auditIntentDigest: operationDigest(request),
    checkpointSequence: current.activeCount >= MAX_ACTIVE_AUDIT_EVENTS
      ? current.checkpoint.sequence + 1 : current.checkpoint.sequence };
}

async function readAuditState(tx, now, ctx) {
  const state = await readPrimaryAuditState(tx, now, ctx.integrity);
  const anchor = ctx.anchorAuthority.read(EXTERNAL_AUDIT_NAMESPACE);
  if (anchor.pending) throw fault('control_plane_readiness_frozen');
  if (anchor.revision !== state.sequence || anchor.headDigest !== state.headDigest) {
    throw fault('audit_anchor_invalid');
  }
  return state;
}

async function readPrimaryAuditState(tx, now, integrity) {
  const checkpointWrapped = await call(tx, 'readAuditCheckpoint');
  let checkpoint = { schemaVersion: 1, sequence: 0, count: 0,
    headDigest: '0'.repeat(64), recordedAt: '1970-01-01T00:00:00.000Z' };
  if (checkpointWrapped) {
    checkpoint = integrity.open(INTEGRITY_DOMAINS.AUDIT_CHECKPOINT, checkpointWrapped);
    validateAuditCheckpoint(checkpoint, now);
  }
  const currentWrapped = await call(tx, 'readAuditHighWater');
  const tailWrapped = await call(tx, 'readAuditTail');
  if (!currentWrapped && !tailWrapped) {
    const rows = await call(tx, 'listAuditEvents', checkpoint.sequence + 1, 1);
    if (checkpoint.sequence !== 0 || !Array.isArray(rows) || rows.length) {
      throw fault('audit_high_water_invalid');
    }
    return { schemaVersion: 1, sequence: 0, count: 0, headDigest: '0'.repeat(64),
      recordedAt: '1970-01-01T00:00:00.000Z', activeCount: 0,
      firstActiveWrapped: null, checkpoint, checkpointSequence: 0 };
  }
  if (!currentWrapped || !tailWrapped) {
    throw fault('audit_high_water_invalid');
  }
  const current = integrity.open(INTEGRITY_DOMAINS.AUDIT_HIGH_WATER, currentWrapped);
  validateAuditHighWater(current, now);
  if (checkpoint.sequence >= current.sequence
      || checkpoint.count > current.count) throw fault('audit_anchor_invalid');
  const tail = integrity.open(INTEGRITY_DOMAINS.AUDIT_EVENT, tailWrapped);
  validateAuditEvent(tail);
  if (tail.sequence !== current.sequence || tail.eventDigest !== current.headDigest
      || tail.recordedAt !== current.recordedAt) throw fault('audit_high_water_invalid');
  const rows = await call(tx, 'listAuditEvents', checkpoint.sequence + 1,
    MAX_ACTIVE_AUDIT_EVENTS + 1);
  if (!Array.isArray(rows) || rows.length !== current.count - checkpoint.count
      || rows.length !== current.sequence - checkpoint.sequence
      || rows.length < 1 || rows.length > MAX_ACTIVE_AUDIT_EVENTS) {
    throw fault('audit_high_water_invalid');
  }
  let prior = checkpoint.headDigest;
  for (let index = 0; index < rows.length; index += 1) {
    const event = integrity.open(INTEGRITY_DOMAINS.AUDIT_EVENT, rows[index]);
    validateAuditEvent(event);
    if (event.sequence !== checkpoint.sequence + index + 1 || event.previousDigest !== prior) {
      throw fault('audit_high_water_invalid');
    }
    prior = event.eventDigest;
  }
  if (prior !== current.headDigest) throw fault('audit_high_water_invalid');
  return { ...current, activeCount: rows.length, firstActiveWrapped: rows[0],
    checkpoint, checkpointSequence: checkpoint.sequence };
}

function validateAuditCheckpoint(value, now) {
  if (!plainRecord(value)
      || !exactKeys(value, ['count', 'headDigest', 'recordedAt', 'schemaVersion', 'sequence'])
      || value.schemaVersion !== 1 || !Number.isSafeInteger(value.sequence)
      || value.sequence < 1 || value.count !== value.sequence
      || !SHA256_RE.test(String(value.headDigest || ''))) {
    throw fault('audit_checkpoint_invalid');
  }
  if (parseIso(value.recordedAt, 'audit_checkpoint_invalid') > now.ms) {
    throw fault('clock_rollback');
  }
}

function validateAuditAnchor(value) {
  if (!plainRecord(value) || !exactKeys(value, ['count', 'headDigest', 'sequence'])
      || !Number.isSafeInteger(value.sequence) || value.sequence < 1
      || value.count !== value.sequence || !SHA256_RE.test(String(value.headDigest || ''))) {
    throw fault('audit_anchor_invalid');
  }
}

function validateAuditEvent(value) {
  const keys = [
    'action', 'authorizationLinkId', 'eventDigest', 'outcome', 'previousDigest',
    'recordedAt', 'referenceDigest', 'schemaVersion', 'scopeDigest', 'sequence', 'version',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || !Number.isSafeInteger(value.sequence) || value.sequence < 1
      || !SAFE_ID_RE.test(value.action) || !SAFE_ID_RE.test(value.outcome)
      || !SHA256_RE.test(value.authorizationLinkId) || !SHA256_RE.test(value.previousDigest)
      || !SHA256_RE.test(value.referenceDigest) || !SHA256_RE.test(value.scopeDigest)
      || !SHA256_RE.test(value.eventDigest)
      || (value.version !== null && (!Number.isSafeInteger(value.version) || value.version < 1))) {
    throw fault('audit_event_invalid');
  }
  parseIso(value.recordedAt, 'audit_event_invalid');
  const descriptor = clone(value);
  delete descriptor.previousDigest;
  delete descriptor.eventDigest;
  if (digestText(`${value.previousDigest}\0${protocol.canonicalJson(descriptor)}`)
      !== value.eventDigest) throw fault('audit_event_invalid');
}

function validateAuditHighWater(value, now) {
  if (!plainRecord(value)
      || !exactKeys(value, ['count', 'headDigest', 'recordedAt', 'schemaVersion', 'sequence'])
      || value.schemaVersion !== 1 || !Number.isSafeInteger(value.sequence) || value.sequence < 0
      || !Number.isSafeInteger(value.count) || value.count !== value.sequence
      || !SHA256_RE.test(String(value.headDigest || ''))) {
    throw fault('audit_high_water_invalid');
  }
  const recordedAt = parseIso(value.recordedAt, 'audit_high_water_invalid');
  if (recordedAt > now.ms) throw fault('clock_rollback');
}

function governanceNamespace(kind, identity = null) {
  if (!SAFE_ID_RE.test(kind)) throw fault('governance_namespace_invalid');
  return identity === null ? kind : `${kind}:${operationDigest(identity)}`;
}

async function prepareGovernedMutation(tx, input, now, ctx) {
  const { integrity } = ctx;
  const pending = await call(tx, 'readGovernancePending', input.namespace);
  if (pending) throw fault('control_plane_readiness_frozen');
  const wrappedHead = await call(tx, 'readGovernanceHead', input.namespace);
  const anchorNamespace = externalGovernanceNamespace(input.namespace);
  const anchor = ctx.anchorAuthority.read(anchorNamespace);
  if (anchor.pending) throw fault('control_plane_readiness_frozen');
  const audit = await readAuditState(tx, now, ctx);
  let previousHeadDigest = ZERO_DIGEST;
  if (input.expectedRevision === 0) {
    if (wrappedHead || anchor.revision !== 0 || anchor.headDigest !== ZERO_DIGEST) {
      throw fault('governance_head_conflict');
    }
  } else {
    if (!wrappedHead) throw fault('governance_head_invalid');
    const head = integrity.open(INTEGRITY_DOMAINS.STATE_HEAD, wrappedHead);
    validateGovernanceHead(head, input.namespace);
    const headDigest = operationDigest(head);
    if (head.revision !== input.expectedRevision
        || head.stateDigest !== input.currentStateDigest
        || anchor.revision !== head.revision || anchor.headDigest !== headDigest) {
      throw fault('governance_head_invalid');
    }
    await verifyGovernanceHeadAudit(tx, head, audit, integrity);
    previousHeadDigest = headDigest;
  }
  const witness = {
    schemaVersion: 1,
    namespace: input.namespace,
    expectedRevision: input.expectedRevision,
    currentStateDigest: input.currentStateDigest,
    previousHeadDigest,
    targetRevision: input.targetRevision,
    targetStateDigest: input.targetStateDigest,
    targetAuditSequence: audit.sequence + 1,
    targetAuditCount: audit.count + 1,
    auditIntentDigest: operationDigest(input.auditRequest),
    preparedAt: now.iso,
  };
  const wrapped = integrity.seal(INTEGRITY_DOMAINS.STATE_PENDING, witness);
  const witnessDigest = operationDigest(wrapped);
  if (await call(tx, 'writeGovernancePending', input.namespace,
    input.expectedRevision, wrapped) !== true) throw fault('governance_pending_conflict');
  return { witness, witnessDigest };
}

async function finalizeGovernedMutation(tx, prepared, audit, ctx, lifecycle) {
  const { integrity } = ctx;
  const { witness } = prepared;
  if (audit.sequence !== witness.targetAuditSequence || audit.count !== witness.targetAuditCount) {
    throw fault('governance_audit_conflict');
  }
  if (audit.auditIntentDigest !== witness.auditIntentDigest) {
    throw fault('governance_audit_conflict');
  }
  const head = {
    schemaVersion: 1,
    namespace: witness.namespace,
    revision: witness.targetRevision,
    stateDigest: witness.targetStateDigest,
    previousHeadDigest: witness.previousHeadDigest,
    auditSequence: audit.sequence,
    auditCount: audit.count,
    auditHead: audit.headDigest,
    auditIntentDigest: witness.auditIntentDigest,
  };
  const wrappedHead = integrity.seal(INTEGRITY_DOMAINS.STATE_HEAD, head);
  const headDigest = operationDigest(head);
  if (await call(tx, 'compareAndSetGovernanceHead', witness.namespace,
    witness.expectedRevision, wrappedHead) !== true) throw fault('governance_head_conflict');
  const transition = {
    namespace: externalGovernanceNamespace(witness.namespace),
    expectedRevision: witness.expectedRevision,
    expectedDigest: witness.previousHeadDigest,
    targetRevision: witness.targetRevision,
    targetDigest: headDigest,
    witnessDigest: prepared.witnessDigest,
  };
  const anchor = ctx.anchorAuthority.prepare(transition);
  if (!anchor.pending || anchor.revision !== transition.expectedRevision
      || anchor.headDigest !== transition.expectedDigest) throw fault('governance_anchor_conflict');
  lifecycle.defer(async () => {
    const finalized = ctx.anchorAuthority.finalize(transition);
    if (finalized.pending || finalized.revision !== transition.targetRevision
        || finalized.headDigest !== transition.targetDigest) {
      throw fault('governance_anchor_conflict');
    }
    await ctx.storage.transaction(async (cleanupTx) => {
      const wrapped = await call(cleanupTx, 'readGovernancePending', witness.namespace);
      if (!wrapped || operationDigest(wrapped) !== prepared.witnessDigest
          || await call(cleanupTx, 'clearGovernancePending', witness.namespace,
            prepared.witnessDigest) !== true) throw fault('governance_pending_clear_failed');
    });
  });
  const readbackHead = integrity.open(INTEGRITY_DOMAINS.STATE_HEAD,
    await call(tx, 'readGovernanceHead', witness.namespace));
  if (operationDigest(readbackHead) !== headDigest
      || !await call(tx, 'readGovernancePending', witness.namespace)) {
    throw fault('governance_cas_readback_failed');
  }
}

async function verifyGovernedState(tx, input, now, ctx) {
  const { integrity } = ctx;
  if (await call(tx, 'readGovernancePending', input.namespace)) {
    throw fault('control_plane_readiness_frozen');
  }
  const wrapped = await call(tx, 'readGovernanceHead', input.namespace);
  const anchor = ctx.anchorAuthority.read(externalGovernanceNamespace(input.namespace));
  if (!wrapped || anchor.pending) throw fault(anchor.pending
    ? 'control_plane_readiness_frozen' : 'governance_head_invalid');
  const head = integrity.open(INTEGRITY_DOMAINS.STATE_HEAD, wrapped);
  validateGovernanceHead(head, input.namespace);
  const headDigest = operationDigest(head);
  if (head.revision !== input.revision || head.stateDigest !== input.stateDigest
      || anchor.revision !== head.revision || anchor.headDigest !== headDigest) {
    throw fault('governance_head_invalid');
  }
  const audit = await readAuditState(tx, now, ctx);
  await verifyGovernanceHeadAudit(tx, head, audit, integrity);
  return head;
}

function externalGovernanceNamespace(namespace) {
  const value = `${EXTERNAL_GOVERNANCE_PREFIX}${namespace}`;
  if (value.length > 160) throw fault('governance_namespace_invalid');
  return value;
}

async function verifyGovernanceHeadAudit(tx, head, audit, integrity,
  code = 'governance_head_invalid') {
  if (head.auditCount !== head.auditSequence || head.auditSequence > audit.sequence
      || head.auditCount > audit.count) throw fault(code);
  if (head.auditSequence <= audit.checkpointSequence) {
    if (head.auditSequence === audit.checkpointSequence
        && head.auditHead !== audit.checkpoint.headDigest) throw fault(code);
    return;
  }
  const wrappedEvent = await call(tx, 'readAuditEvent', head.auditSequence);
  if (!wrappedEvent) throw fault(code);
  const event = integrity.open(INTEGRITY_DOMAINS.AUDIT_EVENT, wrappedEvent);
  validateAuditEvent(event);
  if (event.eventDigest !== head.auditHead) throw fault(code);
}

function validateGovernanceHead(value, namespace) {
  const keys = [
    'auditCount', 'auditHead', 'auditIntentDigest', 'auditSequence', 'namespace',
    'previousHeadDigest', 'revision', 'schemaVersion', 'stateDigest',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || value.namespace !== namespace || !Number.isSafeInteger(value.revision)
      || value.revision < 1 || !Number.isSafeInteger(value.auditSequence)
      || value.auditSequence < 1 || !Number.isSafeInteger(value.auditCount)
      || value.auditCount !== value.auditSequence || !SHA256_RE.test(value.auditHead)
      || !SHA256_RE.test(value.auditIntentDigest) || !SHA256_RE.test(value.previousHeadDigest)
      || !SHA256_RE.test(value.stateDigest)) throw fault('governance_head_invalid');
}

async function assertNoPendingGovernance(tx, ctx) {
  const values = await call(tx, 'listGovernancePending', MAX_GOVERNANCE_ROOTS + 1);
  if (!Array.isArray(values) || values.length > MAX_GOVERNANCE_ROOTS) {
    throw fault('storage_contract_invalid');
  }
  const anchors = ctx.anchorAuthority.listPending(MAX_GOVERNANCE_ROOTS)
    .filter((value) => value.namespace.startsWith(EXTERNAL_GOVERNANCE_PREFIX));
  if (values.length || anchors.length) throw fault('control_plane_readiness_frozen');
  await verifyExternalGovernanceRoots(tx, ctx);
}

async function verifyExternalGovernanceRoots(tx, ctx) {
  const anchors = ctx.anchorAuthority.list(MAX_GOVERNANCE_ROOTS)
    .filter((value) => value.namespace.startsWith(EXTERNAL_GOVERNANCE_PREFIX)
      && value.revision > 0);
  const rows = await call(tx, 'listGovernanceHeads', MAX_GOVERNANCE_ROOTS + 1);
  if (!Array.isArray(rows) || rows.length > MAX_GOVERNANCE_ROOTS
      || anchors.length !== rows.length) throw fault('governance_head_invalid');
  const byNamespace = new Map(anchors.map((anchor) => [
    anchor.namespace.slice(EXTERNAL_GOVERNANCE_PREFIX.length), anchor,
  ]));
  for (const row of rows) {
    if (!plainRecord(row) || !exactKeys(row, ['namespace', 'wrapped'])) {
      throw fault('governance_head_invalid');
    }
    const head = ctx.integrity.open(INTEGRITY_DOMAINS.STATE_HEAD, row.wrapped);
    validateGovernanceHead(head, row.namespace);
    const anchor = byNamespace.get(row.namespace);
    if (!anchor || anchor.pending || anchor.revision !== head.revision
        || anchor.headDigest !== operationDigest(head)) throw fault('governance_head_invalid');
  }
}

async function vendorReadiness(ctx) {
  if (ctx.production && ctx.storage.productionReady !== true) {
    return { ready: false, reason: 'production_storage_required', productionReady: false };
  }
  try {
    return await transact(ctx, async (tx) => {
      const now = trustedNow(ctx.clock);
      await assertNoPendingGovernance(tx, ctx);
      await readAuditState(tx, now, ctx);
      await assertVendorHistory(tx, ctx);
      return { ready: true, reason: 'ready', productionReady: false };
    });
  } catch (error) {
    return {
      ready: false,
      reason: error.code || 'control_plane_integrity_invalid',
      productionReady: false,
    };
  }
}

async function reconcileAuditAnchor(tx, now, ctx) {
  const primary = await readPrimaryAuditState(tx, now, ctx.integrity);
  const anchor = ctx.anchorAuthority.read(EXTERNAL_AUDIT_NAMESPACE);
  if (!anchor.pending) {
    if (anchor.revision !== primary.sequence || anchor.headDigest !== primary.headDigest) {
      throw fault('audit_anchor_invalid');
    }
    return primary;
  }
  const transition = transitionFromExternalAnchor(anchor);
  const committed = primary.sequence === transition.targetRevision
    && primary.headDigest === transition.targetDigest;
  const rolledBack = primary.sequence === transition.expectedRevision
    && primary.headDigest === transition.expectedDigest;
  if (!committed && !rolledBack) throw fault('audit_reconciliation_required');
  if (committed) ctx.anchorAuthority.finalize(transition);
  else ctx.anchorAuthority.abort(transition);
  return primary;
}

async function reconcileIntegrity(ctx) {
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    const audit = await reconcileAuditAnchor(tx, now, ctx);
    const pendingRows = await call(tx, 'listGovernancePending', MAX_GOVERNANCE_ROOTS + 1);
    const externalPending = ctx.anchorAuthority.listPending(MAX_GOVERNANCE_ROOTS)
      .filter((anchor) => anchor.namespace.startsWith(EXTERNAL_GOVERNANCE_PREFIX));
    if (!Array.isArray(pendingRows) || pendingRows.length > MAX_GOVERNANCE_ROOTS) {
      throw fault('storage_contract_invalid');
    }
    const rowsByNamespace = new Map();
    for (const row of pendingRows) {
      if (!plainRecord(row) || !exactKeys(row, ['namespace', 'wrapped'])
          || rowsByNamespace.has(row.namespace)) throw fault('governance_pending_invalid');
      rowsByNamespace.set(row.namespace, row.wrapped);
    }
    const namespaces = new Set(rowsByNamespace.keys());
    for (const anchor of externalPending) {
      namespaces.add(anchor.namespace.slice(EXTERNAL_GOVERNANCE_PREFIX.length));
    }
    let finalized = 0;
    let rolledBack = 0;
    for (const namespace of [...namespaces].sort()) {
      const externalNamespace = externalGovernanceNamespace(namespace);
      const anchor = ctx.anchorAuthority.read(externalNamespace);
      const row = rowsByNamespace.get(namespace) || null;
      let witness = null;
      let witnessDigest = null;
      let transition = anchor.pending ? transitionFromExternalAnchor(anchor) : null;
      if (row) {
        witness = ctx.integrity.open(INTEGRITY_DOMAINS.STATE_PENDING, row);
        validateGovernanceWitness(witness, namespace, now, audit);
        witnessDigest = operationDigest(row);
      }
      const headWrapped = await call(tx, 'readGovernanceHead', namespace);
      let head = null;
      let headDigest = null;
      if (headWrapped) {
        head = ctx.integrity.open(INTEGRITY_DOMAINS.STATE_HEAD, headWrapped);
        validateGovernanceHead(head, namespace);
        await verifyGovernanceHeadAudit(tx, head, audit, ctx.integrity,
          'governance_pending_invalid');
        headDigest = operationDigest(head);
        if (witness && !(head.revision === witness.targetRevision
            && head.stateDigest === witness.targetStateDigest
            && head.previousHeadDigest === witness.previousHeadDigest
            && head.auditSequence === witness.targetAuditSequence
            && head.auditCount === witness.targetAuditCount
            && head.auditIntentDigest === witness.auditIntentDigest)) {
          throw fault('governance_reconciliation_required');
        }
      }
      if (!transition && witness) {
        transition = {
          namespace: externalNamespace,
          expectedRevision: witness.expectedRevision,
          expectedDigest: witness.previousHeadDigest,
          targetRevision: witness.targetRevision,
          targetDigest: headDigest || ZERO_DIGEST,
          witnessDigest,
        };
      }
      if (!transition || (witness && (transition.expectedRevision !== witness.expectedRevision
          || transition.expectedDigest !== witness.previousHeadDigest
          || transition.targetRevision !== witness.targetRevision
          || transition.witnessDigest !== witnessDigest))) {
        throw fault('governance_reconciliation_required');
      }
      const committed = Boolean(head) && head.revision === transition.targetRevision
        && headDigest === transition.targetDigest;
      const previousMatches = transition.expectedRevision === 0
        ? !head : Boolean(head) && head.revision === transition.expectedRevision
          && headDigest === transition.expectedDigest;
      if (!committed && !previousMatches) throw fault('governance_reconciliation_required');
      if (anchor.pending) {
        if (committed) ctx.anchorAuthority.finalize(transition);
        else ctx.anchorAuthority.abort(transition);
      } else if ((committed && (anchor.revision !== transition.targetRevision
          || anchor.headDigest !== transition.targetDigest))
          || (previousMatches && (anchor.revision !== transition.expectedRevision
            || anchor.headDigest !== transition.expectedDigest))) {
        throw fault('governance_reconciliation_required');
      }
      if (row && await call(tx, 'clearGovernancePending', namespace,
        witnessDigest) !== true) throw fault('governance_pending_clear_failed');
      if (committed) finalized += 1;
      else rolledBack += 1;
    }
    return { finalized, rolledBack };
  });
}

function transitionFromExternalAnchor(anchor) {
  return {
    namespace: anchor.namespace,
    expectedRevision: anchor.pending.expectedRevision,
    expectedDigest: anchor.pending.expectedDigest,
    targetRevision: anchor.pending.targetRevision,
    targetDigest: anchor.pending.targetDigest,
    witnessDigest: anchor.pending.witnessDigest,
  };
}

function validateGovernanceWitness(value, namespace, now, audit) {
  const keys = [
    'auditIntentDigest', 'currentStateDigest', 'expectedRevision', 'namespace',
    'preparedAt', 'previousHeadDigest', 'schemaVersion', 'targetAuditCount',
    'targetAuditSequence', 'targetRevision', 'targetStateDigest',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || value.namespace !== namespace || !Number.isSafeInteger(value.expectedRevision)
      || value.expectedRevision < 0 || value.targetRevision !== value.expectedRevision + 1
      || !Number.isSafeInteger(value.targetAuditSequence) || value.targetAuditSequence < 1
      || !Number.isSafeInteger(value.targetAuditCount)
      || value.targetAuditCount !== value.targetAuditSequence
      || value.targetAuditSequence > audit.sequence + 1
      || !SHA256_RE.test(value.currentStateDigest)
      || !SHA256_RE.test(value.previousHeadDigest)
      || !SHA256_RE.test(value.targetStateDigest)
      || !SHA256_RE.test(value.auditIntentDigest)) {
    throw fault('governance_pending_invalid');
  }
  const preparedAt = parseIso(value.preparedAt, 'governance_pending_invalid');
  if (preparedAt > now.ms) throw fault('clock_rollback');
}

async function ingestCandidate(commandValue, ctx) {
  const command = exactCommand(commandValue,
    ['authEventId', 'candidate', 'consentId', 'idempotencyKey'], 'ingest_command_invalid');
  if (!UUID_RE.test(command.authEventId) || !UUID_RE.test(command.consentId)
      || !UUID_RE.test(command.idempotencyKey)) throw fault('ingest_command_invalid');
  const candidate = protocol.assertChannel(command.candidate, protocol.CHANNEL_KINDS.SHADOW_CANDIDATE);
  const scope = scopeOf(candidate);
  const candidateDigest = protocol.payloadDigest(candidate, protocol.CHANNEL_KINDS.SHADOW_CANDIDATE);
  const opDigest = operationDigest({ candidateDigest, consentId: command.consentId,
    idempotencyKey: command.idempotencyKey });
  const result = await transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'connector_ingest', opDigest, scope,
    }, now, ctx);
    const consentEnforcement = await enforceScopeConsent(tx, scope, now, ctx,
      authority.link.linkId, lifecycle);
    if (!consentEnforcement.granted) return { consentDenied: consentEnforcement.code };
    const replay = await call(tx, 'findObservationByIdempotency',
      scope.customerId, scope.deploymentId, command.idempotencyKey);
    if (replay) return replayObservation(replay, opDigest, ctx.integrity);
    const consent = consentEnforcement.consent;
    if (consent.consentId !== command.consentId) throw fault('candidate_consent_invalid');
    const purged = await call(tx, 'purgeExpiredObservations', scope.customerId,
      scope.deploymentId, now.iso, MAX_OBSERVATIONS_PER_SCOPE);
    if (!Number.isSafeInteger(purged) || purged < 0 || purged > MAX_OBSERVATIONS_PER_SCOPE) {
      throw fault('storage_contract_invalid');
    }
    const count = await call(tx, 'countActiveObservations', scope.customerId,
      scope.deploymentId, now.iso);
    if (!Number.isSafeInteger(count) || count < 0) throw fault('storage_contract_invalid');
    if (count >= MAX_OBSERVATIONS_PER_SCOPE) throw fault('observation_quota_exceeded');
    const observation = {
      schemaVersion: 1,
      observationId: checkedUuid(ctx.randomUUID),
      ...scope,
      idempotencyKey: command.idempotencyKey,
      operationDigest: opDigest,
      candidate,
      candidateDigest,
      consentId: consent.consentId,
      consentRevision: consent.revision,
      consentDigest: operationDigest(consent),
      observedAt: now.iso,
      retainUntil: new Date(now.ms + OBSERVATION_RETENTION_MS).toISOString(),
    };
    const sealed = ctx.integrity.seal(INTEGRITY_DOMAINS.OBSERVATION, observation);
    if (await call(tx, 'insertObservation', observation.observationId,
      scope.customerId, scope.deploymentId, command.idempotencyKey, sealed) !== true) {
      throw fault('observation_conflict');
    }
    await appendAudit(tx, {
      action: AUDIT_ACTIONS.CANDIDATE_INGESTED,
      authorizationLinkId: authority.link.linkId,
      scope,
      referenceDigest: candidateDigest,
    }, now, ctx, lifecycle);
    return publicObservation(observation);
  });
  if (result?.consentDenied) throw fault(result.consentDenied);
  return result;
}

function replayObservation(wrapped, opDigest, integrity) {
  const observation = integrity.open(INTEGRITY_DOMAINS.OBSERVATION, wrapped);
  validateObservation(observation);
  if (observation.operationDigest !== opDigest) throw fault('idempotency_conflict');
  return publicObservation(observation);
}

function validateObservation(value) {
  const keys = [
    'candidate', 'candidateDigest', 'consentDigest', 'consentId', 'consentRevision',
    'customerId', 'deploymentId', 'idempotencyKey', 'observedAt', 'observationId',
    'operationDigest', 'retainUntil', 'schemaVersion',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || !UUID_RE.test(value.observationId) || !UUID_RE.test(value.consentId)
      || !UUID_RE.test(value.idempotencyKey)
      || !SHA256_RE.test(value.candidateDigest) || !SHA256_RE.test(value.consentDigest)
      || !SHA256_RE.test(value.operationDigest) || !Number.isSafeInteger(value.consentRevision)
      || value.consentRevision < 1) throw fault('observation_state_invalid');
  validateScope(value.customerId, value.deploymentId);
  const candidate = protocol.assertChannel(value.candidate, protocol.CHANNEL_KINDS.SHADOW_CANDIDATE);
  if (candidate.customerId !== value.customerId || candidate.deploymentId !== value.deploymentId
      || protocol.payloadDigest(candidate, protocol.CHANNEL_KINDS.SHADOW_CANDIDATE) !== value.candidateDigest
      || parseIso(value.retainUntil, 'observation_state_invalid')
        <= parseIso(value.observedAt, 'observation_state_invalid')) {
    throw fault('observation_state_invalid');
  }
}

function publicObservation(value) {
  return clone({
    observationId: value.observationId,
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    candidate: value.candidate,
    candidateDigest: value.candidateDigest,
    consentId: value.consentId,
    consentRevision: value.consentRevision,
    observedAt: value.observedAt,
    retainUntil: value.retainUntil,
  });
}

async function reviewCandidate(commandValue, ctx) {
  const command = exactCommand(commandValue, [
    'authEventId', 'catalogRecord', 'customerId', 'decision', 'deploymentId',
    'domainOverrideConfirmationId', 'expectedCandidateDigest',
    'expectedClassificationDigest', 'expectedClassificationRevision',
    'idempotencyKey', 'observationId', 'reasonCode',
  ], 'review_command_invalid');
  validateReviewCommand(command);
  const scope = scopeOf(command);
  const catalogRecord = command.decision === 'approve'
    ? normalizeCatalogRecord(command.catalogRecord) : null;
  const opDigest = operationDigest({
    catalogRecord,
    customerId: command.customerId,
    decision: command.decision,
    deploymentId: command.deploymentId,
    expectedCandidateDigest: command.expectedCandidateDigest,
    expectedClassificationDigest: command.expectedClassificationDigest,
    expectedClassificationRevision: command.expectedClassificationRevision,
    idempotencyKey: command.idempotencyKey,
    observationId: command.observationId,
    reasonCode: command.reasonCode,
  });
  const result = await transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'analyst_review', opDigest, scope,
    }, now, ctx);
    const consentEnforcement = await enforceScopeConsent(tx, scope, now, ctx,
      authority.link.linkId, lifecycle);
    if (!consentEnforcement.granted) return { consentDenied: consentEnforcement.code };
    let authorizationLinkId = authority.link.linkId;
    const replay = await call(tx, 'findReviewByIdempotency',
      command.customerId, command.deploymentId, command.idempotencyKey);
    if (replay) return replayReview(replay, opDigest, ctx.integrity);
    const observation = readObservation(await call(tx, 'readObservation',
      command.customerId, command.deploymentId, command.observationId), ctx.integrity);
    validateReviewObservation(command, observation, now);
    await requireUnchangedConsent(tx, observation, now);
    const needsDomainOverride = catalogRecord && (
      catalogRecord.registrableDomain !== observation.candidate.registrableDomain
      || catalogRecord.aliases.length > 0
    );
    if (needsDomainOverride) {
      if (command.reasonCode !== 'verified_override'
          || command.domainOverrideConfirmationId === null) {
        throw fault('classification_domain_mismatch');
      }
      const confirmation = await confirmOperation(tx, {
        confirmationId: command.domainOverrideConfirmationId,
        purpose: 'shadow_domain_override', opDigest,
      }, authority, now, ctx.integrity);
      authorizationLinkId = confirmation.link.linkId;
    } else if (command.domainOverrideConfirmationId !== null
        || (catalogRecord && command.reasonCode !== 'approved')) {
      throw fault('review_command_invalid');
    }
    const classificationDigest = catalogRecord ? operationDigest(catalogRecord) : null;
    const auditRequest = {
      action: AUDIT_ACTIONS.CANDIDATE_REVIEWED,
      authorizationLinkId,
      scope,
      referenceDigest: operationDigest({ candidateDigest: observation.candidateDigest,
        decision: command.decision, classificationDigest }),
    };
    const classification = catalogRecord
      ? await applyClassification(tx, catalogRecord, {
        revision: command.expectedClassificationRevision,
        recordDigest: command.expectedClassificationDigest,
      }, auditRequest, now, ctx)
      : { action: 'none', catalogId: null, recordDigest: null };
    const review = {
      schemaVersion: 1,
      reviewId: checkedUuid(ctx.randomUUID),
      ...scope,
      observationId: observation.observationId,
      candidateDigest: observation.candidateDigest,
      idempotencyKey: command.idempotencyKey,
      operationDigest: opDigest,
      decision: command.decision,
      reasonCode: command.reasonCode,
      catalogId: classification.catalogId,
      classificationAction: classification.action,
      classificationDigest: classification.recordDigest,
      reviewedAt: now.iso,
    };
    if (await call(tx, 'insertReview', review.reviewId, command.customerId,
      command.deploymentId, command.observationId, command.idempotencyKey,
      ctx.integrity.seal(INTEGRITY_DOMAINS.REVIEW, review)) !== true) {
      throw fault('review_conflict');
    }
    const audit = await appendAudit(tx, auditRequest, now, ctx, lifecycle);
    if (classification.governance) {
      await finalizeGovernedMutation(tx, classification.governance, audit, ctx, lifecycle);
    }
    return publicReview(review);
  });
  if (result?.consentDenied) throw fault(result.consentDenied);
  return result;
}

function validateReviewCommand(command) {
  if (!UUID_RE.test(command.authEventId) || !UUID_RE.test(command.observationId)
      || !SHA256_RE.test(command.expectedCandidateDigest)
      || !UUID_RE.test(command.idempotencyKey)
      || !['approve', 'reject'].includes(command.decision)
      || (command.domainOverrideConfirmationId !== null
        && !UUID_RE.test(command.domainOverrideConfirmationId))
      || (command.expectedClassificationRevision !== null
        && (!Number.isSafeInteger(command.expectedClassificationRevision)
          || command.expectedClassificationRevision < 1))) {
    throw fault('review_command_invalid');
  }
  validateScope(command.customerId, command.deploymentId);
  const reasonCodes = command.decision === 'approve'
    ? new Set(['approved', 'verified_override'])
    : new Set(['insufficient_evidence', 'not_ai', 'duplicate']);
  if (!reasonCodes.has(command.reasonCode)
      || (command.decision === 'approve') !== (command.catalogRecord !== null)
      || (command.decision === 'reject' && command.expectedClassificationRevision !== null)
      || ((command.expectedClassificationRevision === null)
        !== (command.expectedClassificationDigest === null))
      || (command.expectedClassificationDigest !== null
        && !SHA256_RE.test(String(command.expectedClassificationDigest || '')))) {
    throw fault('review_command_invalid');
  }
}

function normalizeCatalogRecord(value) {
  assertPlainTree(value);
  const records = [value];
  const parsed = protocol.assertChannel({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: '00000000-0000-4000-8000-000000000001',
    kind: protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    authorityManifestGeneration: 1,
    authorityManifestKeySlot: 'current',
    globalReleaseId: '00000000-0000-4000-8000-000000000002',
    globalVersion: 1,
    previousGlobalVersion: 0,
    rollbackOfGlobalVersion: null,
    issuedAt: '2026-01-01T00:00:00.000Z',
    recordsDigest: protocol.catalogRecordsDigest(records),
    records,
  }, protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE);
  return parsed.records[0];
}

function readObservation(wrapped, integrity) {
  if (!wrapped) throw fault('observation_not_found');
  const observation = integrity.open(INTEGRITY_DOMAINS.OBSERVATION, wrapped);
  validateObservation(observation);
  return observation;
}

function validateReviewObservation(command, observation, now) {
  if (observation.customerId !== command.customerId
      || observation.deploymentId !== command.deploymentId
      || observation.observationId !== command.observationId) throw fault('scope_mismatch');
  if (observation.candidateDigest !== command.expectedCandidateDigest) {
    throw fault('candidate_digest_conflict');
  }
  if (parseIso(observation.retainUntil, 'observation_state_invalid') <= now.ms) {
    throw fault('observation_expired');
  }
}

async function requireUnchangedConsent(tx, observation, now) {
  const consent = validateConsent(await call(tx, 'resolveConsent', observation.consentId), {
    consentId: observation.consentId,
    customerId: observation.customerId,
    deploymentId: observation.deploymentId,
  }, now, false);
  if (consent.status !== 'granted' || consent.revision !== observation.consentRevision
      || operationDigest(consent) !== observation.consentDigest) {
    throw fault('consent_revoked');
  }
}

async function applyClassification(tx, record, expected, auditRequest, now, ctx) {
  const wrapped = await call(tx, 'readClassification', record.catalogId);
  const current = wrapped ? readClassification(wrapped, ctx.integrity, {
    catalogId: record.catalogId,
    revision: expected.revision,
    recordDigest: expected.recordDigest,
  }) : null;
  if ((!current && expected.revision !== null)
      || (current && (expected.revision !== current.revision
        || expected.recordDigest !== current.recordDigest))) {
    throw fault('classification_revision_conflict');
  }
  const namespace = governanceNamespace('classification', { catalogId: record.catalogId });
  if (current) {
    await verifyGovernedState(tx, {
      namespace,
      revision: current.revision,
      stateDigest: operationDigest(current),
    }, now, ctx);
  }
  const recordDigest = operationDigest(record);
  const identical = current && current.recordDigest === recordDigest;
  if (!current) {
    const count = await call(tx, 'countClassifications');
    if (!Number.isSafeInteger(count) || count < 0) throw fault('storage_contract_invalid');
    if (count >= MAX_CLASSIFICATIONS) throw fault('classification_quota_exceeded');
  }
  const nextRevision = current ? current.revision + (identical ? 0 : 1) : 1;
  const domains = [record.registrableDomain, ...record.aliases].sort();
  const claimPayload = {
    schemaVersion: 1, catalogId: record.catalogId, revision: nextRevision,
    recordDigest, domains, claimedAt: now.iso,
  };
  const claim = claimResult(await call(tx, 'claimClassificationDomains', {
    catalogId: record.catalogId,
    expectedRevision: current?.revision || 0,
    recordDigest,
    domains,
    sealedClaim: ctx.integrity.seal(INTEGRITY_DOMAINS.DOMAIN_CLAIM, claimPayload),
  }));
  if (claim === 'conflict') throw fault('classification_domain_conflict');
  if (!['claimed', 'owned', 'replay'].includes(claim)) throw fault('storage_contract_invalid');
  let governance = null;
  if (!identical) {
    const classification = {
      schemaVersion: 1,
      revision: nextRevision,
      record,
      recordDigest,
      createdAt: current?.createdAt || now.iso,
      updatedAt: now.iso,
    };
    governance = await prepareGovernedMutation(tx, {
      namespace,
      expectedRevision: current?.revision || 0,
      currentStateDigest: current ? operationDigest(current) : '0'.repeat(64),
      targetRevision: classification.revision,
      targetStateDigest: operationDigest(classification),
      auditRequest,
    }, now, ctx);
    const changed = await call(tx, 'compareAndSetClassification', record.catalogId,
      current?.revision || 0, ctx.integrity.seal(INTEGRITY_DOMAINS.CLASSIFICATION, classification));
    if (changed !== true) throw fault('classification_revision_conflict');
    const readback = readClassification(await call(tx, 'readClassification', record.catalogId),
      ctx.integrity, {
        catalogId: record.catalogId,
        revision: classification.revision,
        recordDigest: classification.recordDigest,
      });
    if (operationDigest(readback) !== operationDigest(classification)) {
      throw fault('classification_cas_readback_failed');
    }
  }
  return { action: current ? (identical ? 'merged' : 'updated') : 'created',
    catalogId: record.catalogId, recordDigest, governance };
}

function readClassification(wrapped, integrity, expected = null) {
  const value = integrity.open(INTEGRITY_DOMAINS.CLASSIFICATION, wrapped);
  const keys = ['createdAt', 'record', 'recordDigest', 'revision', 'schemaVersion', 'updatedAt'];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || !Number.isSafeInteger(value.revision) || value.revision < 1
      || operationDigest(normalizeCatalogRecord(value.record)) !== value.recordDigest) {
    throw fault('classification_state_invalid');
  }
  parseIso(value.createdAt, 'classification_state_invalid');
  parseIso(value.updatedAt, 'classification_state_invalid');
  if (expected && (value.record.catalogId !== expected.catalogId
      || value.revision !== expected.revision || value.recordDigest !== expected.recordDigest)) {
    throw fault('classification_lookup_mismatch');
  }
  return value;
}

function replayReview(wrapped, opDigest, integrity) {
  const review = integrity.open(INTEGRITY_DOMAINS.REVIEW, wrapped);
  validateReviewState(review);
  if (review.operationDigest !== opDigest) throw fault('idempotency_conflict');
  return publicReview(review);
}

function validateReviewState(value) {
  const keys = [
    'candidateDigest', 'catalogId', 'classificationAction', 'classificationDigest',
    'customerId', 'decision', 'deploymentId', 'idempotencyKey', 'observationId',
    'operationDigest', 'reasonCode', 'reviewId', 'reviewedAt', 'schemaVersion',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || !UUID_RE.test(value.reviewId) || !UUID_RE.test(value.observationId)
      || !UUID_RE.test(value.idempotencyKey)
      || !SHA256_RE.test(value.candidateDigest) || !SHA256_RE.test(value.operationDigest)
      || !['approve', 'reject'].includes(value.decision)
      || (value.catalogId === null) !== (value.classificationDigest === null)) {
    throw fault('review_state_invalid');
  }
  if (value.classificationDigest !== null && !SHA256_RE.test(value.classificationDigest)) {
    throw fault('review_state_invalid');
  }
  validateScope(value.customerId, value.deploymentId);
  parseIso(value.reviewedAt, 'review_state_invalid');
}

function publicReview(value) {
  return clone({
    reviewId: value.reviewId,
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    observationId: value.observationId,
    decision: value.decision,
    reasonCode: value.reasonCode,
    catalogId: value.catalogId,
    classificationAction: value.classificationAction,
    reviewedAt: value.reviewedAt,
  });
}

async function publishGlobalCatalog(commandValue, ctx) {
  const command = exactCommand(commandValue, [
    'authEventId', 'confirmationId', 'expectedGlobalArtifactDigest',
    'expectedGlobalRecordsDigest', 'expectedGlobalReleaseId', 'expectedGlobalVersion',
    'idempotencyKey', 'keySlot',
  ], 'publish_command_invalid');
  validateReleaseCommand(command, 'publish_command_invalid');
  const opDigest = operationDigest({
    expectedGlobalVersion: command.expectedGlobalVersion,
    expectedGlobalReleaseId: command.expectedGlobalReleaseId,
    expectedGlobalArtifactDigest: command.expectedGlobalArtifactDigest,
    expectedGlobalRecordsDigest: command.expectedGlobalRecordsDigest,
    idempotencyKey: command.idempotencyKey,
    keySlot: command.keySlot,
    operation: 'publish',
  });
  return transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'global_publish', opDigest,
    }, now, ctx);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose: 'global_publish', opDigest,
    }, authority, now, ctx.integrity);
    const replay = await call(tx, 'findGlobalReleaseByIdempotency', command.idempotencyKey);
    if (replay) return replayGlobalRelease(replay, opDigest, ctx);
    const current = await readCurrentGlobalRelease(tx, ctx,
      expectedGlobalFromCommand(command), now);
    await compactGlobalHistory(tx, ctx, command.expectedGlobalVersion);
    const count = await call(tx, 'countGlobalReleases');
    validateStorageCount(count, MAX_GLOBAL_RELEASES, 'global_release_quota_exceeded');
    const records = await readAllClassificationRecords(tx, ctx, now);
    const signingAuthority = ctx.keyAuthority.resolve();
    const release = buildGlobalRelease({
      idempotencyKey: command.idempotencyKey,
      operationDigest: opDigest,
      globalVersion: command.expectedGlobalVersion + 1,
      previousVersion: command.expectedGlobalVersion,
      rollbackOfVersion: null,
      records,
      issuedAt: now.iso,
      keySlot: command.keySlot,
    }, ctx, signingAuthority);
    const auditRequest = {
      action: AUDIT_ACTIONS.GLOBAL_CATALOG_PUBLISHED,
      authorizationLinkId: confirmation.link.linkId,
      referenceDigest: release.artifactDigest,
      version: release.globalVersion,
    };
    const governance = await prepareGovernedMutation(tx, {
      namespace: governanceNamespace('global-current'),
      expectedRevision: command.expectedGlobalVersion,
      currentStateDigest: current ? operationDigest(current) : '0'.repeat(64),
      targetRevision: release.globalVersion,
      targetStateDigest: operationDigest(release),
      auditRequest,
    }, now, ctx);
    assertCatalogAuthorityCurrent(ctx, signingAuthority);
    if (await call(tx, 'compareAndSetGlobalRelease', command.expectedGlobalVersion,
      command.idempotencyKey, release.globalVersion,
      ctx.integrity.seal(INTEGRITY_DOMAINS.GLOBAL_RELEASE, release)) !== true) {
      throw fault('global_version_conflict');
    }
    await compactGlobalHistory(tx, ctx, release.globalVersion);
    const publishedReadback = readGlobalRelease(await call(tx, 'readGlobalRelease',
      release.globalVersion), ctx, {
      globalVersion: release.globalVersion,
      globalReleaseId: release.globalReleaseId,
      artifactDigest: release.artifactDigest,
      recordsDigest: release.recordsDigest,
    });
    if (operationDigest(publishedReadback) !== operationDigest(release)) {
      throw fault('global_release_cas_readback_failed');
    }
    const audit = await appendAudit(tx, auditRequest, now, ctx, lifecycle);
    await finalizeGovernedMutation(tx, governance, audit, ctx, lifecycle);
    const verified = verifyGlobalReleaseRecord(release, ctx);
    assertCatalogAuthorityCurrent(ctx, signingAuthority);
    return publicGlobalRelease(verified);
  });
}

async function rollbackGlobalCatalog(commandValue, ctx) {
  const command = exactCommand(commandValue, [
    'authEventId', 'confirmationId', 'expectedGlobalArtifactDigest',
    'expectedGlobalRecordsDigest', 'expectedGlobalReleaseId', 'expectedGlobalVersion',
    'idempotencyKey', 'keySlot', 'targetArtifactDigest', 'targetRecordsDigest',
    'targetReleaseId', 'targetVersion',
  ], 'rollback_command_invalid');
  validateReleaseCommand(command, 'rollback_command_invalid');
  if (!Number.isSafeInteger(command.targetVersion) || command.targetVersion < 1
      || command.targetVersion >= command.expectedGlobalVersion
      || !UUID_RE.test(String(command.targetReleaseId || ''))
      || !SHA256_RE.test(String(command.targetArtifactDigest || ''))
      || !SHA256_RE.test(String(command.targetRecordsDigest || ''))) {
    throw fault('rollback_command_invalid');
  }
  const opDigest = operationDigest({
    expectedGlobalVersion: command.expectedGlobalVersion,
    expectedGlobalReleaseId: command.expectedGlobalReleaseId,
    expectedGlobalArtifactDigest: command.expectedGlobalArtifactDigest,
    expectedGlobalRecordsDigest: command.expectedGlobalRecordsDigest,
    idempotencyKey: command.idempotencyKey,
    keySlot: command.keySlot,
    operation: 'rollback',
    targetVersion: command.targetVersion,
    targetReleaseId: command.targetReleaseId,
    targetArtifactDigest: command.targetArtifactDigest,
    targetRecordsDigest: command.targetRecordsDigest,
  });
  return transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'global_rollback', opDigest,
    }, now, ctx);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose: 'global_rollback', opDigest,
    }, authority, now, ctx.integrity);
    const replay = await call(tx, 'findGlobalReleaseByIdempotency', command.idempotencyKey);
    if (replay) return replayGlobalRelease(replay, opDigest, ctx);
    const current = await readCurrentGlobalRelease(tx, ctx,
      expectedGlobalFromCommand(command), now);
    const targetWrapped = await call(tx, 'readGlobalRelease', command.targetVersion);
    if (!targetWrapped) throw fault('rollback_target_not_found');
    const target = readGlobalRelease(targetWrapped, ctx, {
      globalVersion: command.targetVersion,
      globalReleaseId: command.targetReleaseId,
      artifactDigest: command.targetArtifactDigest,
      recordsDigest: command.targetRecordsDigest,
    });
    await compactGlobalHistory(tx, ctx, command.expectedGlobalVersion);
    const count = await call(tx, 'countGlobalReleases');
    validateStorageCount(count, MAX_GLOBAL_RELEASES, 'global_release_quota_exceeded');
    const signingAuthority = ctx.keyAuthority.resolve();
    const release = buildGlobalRelease({
      idempotencyKey: command.idempotencyKey,
      operationDigest: opDigest,
      globalVersion: command.expectedGlobalVersion + 1,
      previousVersion: command.expectedGlobalVersion,
      rollbackOfVersion: command.targetVersion,
      records: target.artifact.payload.records,
      issuedAt: now.iso,
      keySlot: command.keySlot,
    }, ctx, signingAuthority);
    const auditRequest = {
      action: AUDIT_ACTIONS.GLOBAL_CATALOG_ROLLED_BACK,
      authorizationLinkId: confirmation.link.linkId,
      referenceDigest: release.artifactDigest,
      version: release.globalVersion,
    };
    const governance = await prepareGovernedMutation(tx, {
      namespace: governanceNamespace('global-current'),
      expectedRevision: command.expectedGlobalVersion,
      currentStateDigest: operationDigest(current),
      targetRevision: release.globalVersion,
      targetStateDigest: operationDigest(release),
      auditRequest,
    }, now, ctx);
    assertCatalogAuthorityCurrent(ctx, signingAuthority);
    if (await call(tx, 'compareAndSetGlobalRelease', command.expectedGlobalVersion,
      command.idempotencyKey, release.globalVersion,
      ctx.integrity.seal(INTEGRITY_DOMAINS.GLOBAL_RELEASE, release)) !== true) {
      throw fault('global_version_conflict');
    }
    await compactGlobalHistory(tx, ctx, release.globalVersion);
    const rollbackReadback = readGlobalRelease(await call(tx, 'readGlobalRelease',
      release.globalVersion), ctx, {
      globalVersion: release.globalVersion,
      globalReleaseId: release.globalReleaseId,
      artifactDigest: release.artifactDigest,
      recordsDigest: release.recordsDigest,
    });
    if (operationDigest(rollbackReadback) !== operationDigest(release)) {
      throw fault('global_release_cas_readback_failed');
    }
    const audit = await appendAudit(tx, auditRequest, now, ctx, lifecycle);
    await finalizeGovernedMutation(tx, governance, audit, ctx, lifecycle);
    const verified = verifyGlobalReleaseRecord(release, ctx);
    assertCatalogAuthorityCurrent(ctx, signingAuthority);
    return publicGlobalRelease(verified);
  });
}

function validateReleaseCommand(command, code) {
  if (!UUID_RE.test(command.authEventId) || !UUID_RE.test(command.confirmationId)
      || !Number.isSafeInteger(command.expectedGlobalVersion)
      || command.expectedGlobalVersion < 0 || !UUID_RE.test(command.idempotencyKey)
      || !['current', 'next'].includes(command.keySlot)) throw fault(code);
  const genesis = command.expectedGlobalVersion === 0;
  const expectedFields = [command.expectedGlobalReleaseId,
    command.expectedGlobalArtifactDigest, command.expectedGlobalRecordsDigest];
  if ((genesis && expectedFields.some((value) => value !== null))
      || (!genesis && (!UUID_RE.test(String(command.expectedGlobalReleaseId || ''))
        || !SHA256_RE.test(String(command.expectedGlobalArtifactDigest || ''))
        || !SHA256_RE.test(String(command.expectedGlobalRecordsDigest || ''))))) throw fault(code);
}

async function readCurrentGlobalRelease(tx, ctx, expected, now) {
  const wrapped = await call(tx, 'readCurrentGlobalRelease');
  if (!wrapped) {
    if (expected && expected.globalVersion !== 0) throw fault('global_version_conflict');
    return null;
  }
  const value = readGlobalRelease(wrapped, ctx, expected);
  await verifyGovernedState(tx, {
    namespace: governanceNamespace('global-current'),
    revision: value.globalVersion,
    stateDigest: operationDigest(value),
  }, now, ctx);
  return value;
}

function expectedGlobalFromCommand(command) {
  return {
    globalVersion: command.expectedGlobalVersion,
    globalReleaseId: command.expectedGlobalReleaseId,
    artifactDigest: command.expectedGlobalArtifactDigest,
    recordsDigest: command.expectedGlobalRecordsDigest,
  };
}

async function readAllClassificationRecords(tx, ctx, now) {
  const wrapped = await call(tx, 'listAllClassifications', MAX_CLASSIFICATIONS + 1);
  if (!Array.isArray(wrapped) || wrapped.length > MAX_CLASSIFICATIONS) {
    throw fault('classification_quota_exceeded');
  }
  const values = [];
  for (const item of wrapped) {
    const value = readClassification(item, ctx.integrity);
    await verifyGovernedState(tx, {
      namespace: governanceNamespace('classification', { catalogId: value.record.catalogId }),
      revision: value.revision,
      stateDigest: operationDigest(value),
    }, now, ctx);
    values.push(value);
  }
  const records = values.map((value) => value.record)
    .sort((left, right) => left.catalogId.localeCompare(right.catalogId));
  if (new Set(records.map((record) => record.catalogId)).size !== records.length) {
    throw fault('classification_state_invalid');
  }
  return records;
}

function buildGlobalRelease(input, ctx, keys = ctx.keyAuthority.resolve()) {
  const signing = selectedSigningSlot(keys.global, input.keySlot);
  const records = clone(input.records);
  const payload = protocol.assertChannel({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: checkedUuid(ctx.randomUUID),
    kind: protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE,
    authorityManifestGeneration: keys.manifestGeneration,
    authorityManifestKeySlot: signing.slot,
    globalReleaseId: checkedUuid(ctx.randomUUID),
    globalVersion: input.globalVersion,
    previousGlobalVersion: input.previousVersion,
    rollbackOfGlobalVersion: input.rollbackOfVersion,
    issuedAt: input.issuedAt,
    records,
    recordsDigest: protocol.catalogRecordsDigest(records),
  }, protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE);
  const artifact = {
    keyId: signing.keyId,
    payload,
    signature: crypto.sign(null, globalSigningInput(payload, signing.keyId), signing.privateKey)
      .toString('base64'),
  };
  return {
    schemaVersion: 1,
    idempotencyKey: input.idempotencyKey,
    operationDigest: input.operationDigest,
    globalReleaseId: payload.globalReleaseId,
    globalVersion: input.globalVersion,
    previousVersion: input.previousVersion,
    rollbackOfVersion: input.rollbackOfVersion,
    recordsDigest: payload.recordsDigest,
    artifactDigest: operationDigest(artifact),
    artifact,
  };
}

function selectedSigningSlot(keys, slot) {
  const selected = slot === 'current' ? keys.current : keys.next;
  if (!selected) throw fault('catalog_signing_key_unavailable');
  return selected;
}

function globalSigningInput(payload, keyId) {
  return protocol.signingInput(payload, keyId);
}

function validateGlobalPayload(value) {
  try {
    return protocol.assertChannel(value, protocol.CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE);
  } catch { throw fault('global_release_state_invalid'); }
}

function verifyGlobalArtifact(value, ctx) {
  if (!plainRecord(value) || !exactKeys(value, ['keyId', 'payload', 'signature'])
      || !SAFE_ID_RE.test(String(value.keyId || ''))) throw fault('global_release_state_invalid');
  validateGlobalPayload(value.payload);
  const signature = decodeSignature(value.signature, 'global_release_state_invalid');
  const authority = ctx.keyAuthority.resolve();
  const trusted = authority.global.archived.get(value.keyId);
  assertArtifactAuthorityBinding(
    authority, authority.global, KEY_PURPOSES.CATALOG_GLOBAL, value,
  );
  if (!trusted || !crypto.verify(null, globalSigningInput(value.payload, value.keyId),
    trusted.publicKey, signature)) throw fault('global_release_signature_invalid');
  return clone(value);
}

function verifyGlobalReleaseRecord(value, ctx) {
  const keys = [
    'artifact', 'artifactDigest', 'globalReleaseId', 'globalVersion', 'idempotencyKey', 'operationDigest',
    'previousVersion', 'recordsDigest', 'rollbackOfVersion', 'schemaVersion',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || !UUID_RE.test(value.idempotencyKey) || !SHA256_RE.test(value.operationDigest)
      || !SHA256_RE.test(value.artifactDigest) || !SHA256_RE.test(value.recordsDigest)) {
    throw fault('global_release_state_invalid');
  }
  const artifact = verifyGlobalArtifact(value.artifact, ctx);
  if (operationDigest(artifact) !== value.artifactDigest
      || artifact.payload.globalReleaseId !== value.globalReleaseId
      || artifact.payload.globalVersion !== value.globalVersion
      || artifact.payload.previousGlobalVersion !== value.previousVersion
      || artifact.payload.rollbackOfGlobalVersion !== value.rollbackOfVersion
      || artifact.payload.recordsDigest !== value.recordsDigest) {
    throw fault('global_release_state_invalid');
  }
  return { ...clone(value), artifact };
}

function readGlobalRelease(wrapped, ctx, expected = null) {
  const value = verifyGlobalReleaseRecord(
    ctx.integrity.open(INTEGRITY_DOMAINS.GLOBAL_RELEASE, wrapped), ctx,
  );
  if (expected && (value.globalVersion !== expected.globalVersion
      || value.globalReleaseId !== expected.globalReleaseId
      || value.artifactDigest !== expected.artifactDigest
      || value.recordsDigest !== expected.recordsDigest)) throw fault('global_release_lookup_mismatch');
  return value;
}

function replayGlobalRelease(wrapped, opDigest, ctx) {
  const release = readGlobalRelease(wrapped, ctx);
  if (release.operationDigest !== opDigest) throw fault('idempotency_conflict');
  return publicGlobalRelease(release);
}

function publicGlobalRelease(value) {
  return clone({
    globalReleaseId: value.globalReleaseId,
    globalVersion: value.globalVersion,
    previousVersion: value.previousVersion,
    rollbackOfVersion: value.rollbackOfVersion,
    recordsDigest: value.recordsDigest,
    artifactDigest: value.artifactDigest,
    artifact: value.artifact,
  });
}

async function createDistribution(commandValue, ctx) {
  const command = exactCommand(commandValue, [
    'authEventId', 'confirmationId', 'customerId', 'deploymentId',
    'expectedDistributionSequence', 'globalArtifactDigest', 'globalReleaseId',
    'globalVersion', 'idempotencyKey', 'keySlot', 'recordsDigest', 'rollout',
  ], 'distribution_command_invalid');
  validateDistributionCommand(command);
  const scope = scopeOf(command);
  const opDigest = operationDigest({
    ...scope,
    expectedDistributionSequence: command.expectedDistributionSequence,
    globalReleaseId: command.globalReleaseId,
    globalVersion: command.globalVersion,
    globalArtifactDigest: command.globalArtifactDigest,
    recordsDigest: command.recordsDigest,
    idempotencyKey: command.idempotencyKey,
    keySlot: command.keySlot,
    rollout: command.rollout,
  });
  return transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'distribution_create', opDigest, scope,
    }, now, ctx);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose: 'distribution_create', opDigest,
    }, authority, now, ctx.integrity);
    const replay = await call(tx, 'findDistributionByIdempotency',
      command.customerId, command.deploymentId, command.idempotencyKey);
    if (replay) return replayDistribution(replay, opDigest, ctx);
    const currentWrapped = await call(tx, 'readCurrentDistribution',
      command.customerId, command.deploymentId);
    const current = currentWrapped ? readDistribution(currentWrapped, ctx) : null;
    if ((current?.distributionSequence || 0) !== command.expectedDistributionSequence) {
      throw fault('deployment_version_conflict');
    }
    await compactDistributionHistory(tx, ctx, scope, command.expectedDistributionSequence);
    const distributionNamespace = governanceNamespace('distribution-current', scope);
    if (current) {
      await verifyGovernedState(tx, {
        namespace: distributionNamespace,
        revision: current.distributionSequence,
        stateDigest: operationDigest(current),
      }, now, ctx);
    }
    const global = await readCurrentGlobalRelease(tx, ctx, null, now);
    if (!global) throw fault('global_release_not_found');
    if (global.globalVersion !== command.globalVersion
        || global.globalReleaseId !== command.globalReleaseId
        || global.artifactDigest !== command.globalArtifactDigest
        || global.recordsDigest !== command.recordsDigest) {
      throw fault('global_release_not_current');
    }
    const signingAuthority = ctx.keyAuthority.resolve();
    assertGlobalReleaseCurrentAuthority(global, signingAuthority);
    const count = await call(tx, 'countDistributions', command.customerId, command.deploymentId);
    validateStorageCount(count, MAX_DISTRIBUTIONS_PER_DEPLOYMENT,
      'distribution_quota_exceeded');
    const distribution = buildDistribution(
      command, opDigest, global, now, ctx, signingAuthority,
    );
    const adoption = initialAdoption(distribution, now.iso);
    const auditRequest = {
      action: AUDIT_ACTIONS.DISTRIBUTION_CREATED,
      authorizationLinkId: confirmation.link.linkId,
      scope,
      referenceDigest: distribution.distributionDigest,
      version: distribution.distributionSequence,
    };
    const distributionGovernance = await prepareGovernedMutation(tx, {
      namespace: distributionNamespace,
      expectedRevision: command.expectedDistributionSequence,
      currentStateDigest: current ? operationDigest(current) : '0'.repeat(64),
      targetRevision: distribution.distributionSequence,
      targetStateDigest: operationDigest(distribution),
      auditRequest,
    }, now, ctx);
    const adoptionGovernance = await prepareGovernedMutation(tx, {
      namespace: adoptionNamespace(distribution),
      expectedRevision: 0,
      currentStateDigest: '0'.repeat(64),
      targetRevision: adoption.revision,
      targetStateDigest: operationDigest(adoption),
      auditRequest,
    }, now, ctx);
    assertCatalogAuthorityCurrent(ctx, signingAuthority);
    if (await call(tx, 'compareAndSetDistribution', command.customerId,
      command.deploymentId, command.expectedDistributionSequence, command.idempotencyKey,
      distribution.distributionSequence,
      ctx.integrity.seal(INTEGRITY_DOMAINS.DISTRIBUTION, distribution)) !== true) {
      throw fault('deployment_version_conflict');
    }
    if (await call(tx, 'compareAndSetAdoption', command.customerId, command.deploymentId,
      distribution.distributionSequence, 0,
      ctx.integrity.seal(INTEGRITY_DOMAINS.ADOPTION, adoption)) !== true) {
      throw fault('adoption_revision_conflict');
    }
    await compactDistributionHistory(
      tx, ctx, scope, distribution.distributionSequence,
    );
    const distributionReadback = readDistribution(await call(tx, 'readDistribution',
      command.customerId, command.deploymentId, distribution.distributionSequence), ctx);
    const adoptionReadback = ctx.integrity.open(INTEGRITY_DOMAINS.ADOPTION,
      await call(tx, 'readAdoption', command.customerId, command.deploymentId,
        distribution.distributionSequence));
    validateAdoption(adoptionReadback);
    if (operationDigest(distributionReadback) !== operationDigest(distribution)
        || operationDigest(adoptionReadback) !== operationDigest(adoption)) {
      throw fault('distribution_cas_readback_failed');
    }
    const audit = await appendAudit(tx, auditRequest, now, ctx, lifecycle);
    await finalizeGovernedMutation(tx, distributionGovernance, audit, ctx, lifecycle);
    await finalizeGovernedMutation(tx, adoptionGovernance, audit, ctx, lifecycle);
    const verified = verifyDistributionRecord(distribution, ctx);
    assertCatalogAuthorityCurrent(ctx, signingAuthority);
    return publicDistribution(verified);
  });
}

function validateDistributionCommand(command) {
  validateScope(command.customerId, command.deploymentId);
  if (!UUID_RE.test(command.authEventId) || !UUID_RE.test(command.confirmationId)
      || !UUID_RE.test(command.idempotencyKey)
      || !['current', 'next'].includes(command.keySlot)
      || !Number.isSafeInteger(command.globalVersion) || command.globalVersion < 1
      || !UUID_RE.test(String(command.globalReleaseId || ''))
      || !SHA256_RE.test(String(command.globalArtifactDigest || ''))
      || !SHA256_RE.test(String(command.recordsDigest || ''))
      || !Number.isSafeInteger(command.expectedDistributionSequence)
      || command.expectedDistributionSequence < 0
      || !plainRecord(command.rollout)
      || !exactKeys(command.rollout, ['cohortBps', 'mode'])
      || !['preview', 'staged', 'required'].includes(command.rollout.mode)
      || !Number.isSafeInteger(command.rollout.cohortBps)
      || command.rollout.cohortBps < 0 || command.rollout.cohortBps > 10_000) {
    throw fault('distribution_command_invalid');
  }
  if ((command.rollout.mode === 'preview' && command.rollout.cohortBps !== 0)
      || (command.rollout.mode === 'required' && command.rollout.cohortBps !== 10_000)
      || (command.rollout.mode === 'staged'
        && (command.rollout.cohortBps < 1 || command.rollout.cohortBps >= 10_000))) {
    throw fault('distribution_command_invalid');
  }
}

function buildDistribution(command, opDigest, global, now, ctx,
  authority = ctx.keyAuthority.resolve()) {
  const signing = selectedSigningSlot(authority.distribution, command.keySlot);
  const payload = {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: checkedUuid(ctx.randomUUID),
    customerId: command.customerId,
    deploymentId: command.deploymentId,
    kind: protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    authorityManifestGeneration: authority.manifestGeneration,
    authorityManifestKeySlot: signing.slot,
    distributionSequence: command.expectedDistributionSequence + 1,
    previousDistributionSequence: command.expectedDistributionSequence,
    globalReleaseId: global.globalReleaseId,
    globalVersion: command.globalVersion,
    globalArtifactDigest: global.artifactDigest,
    recordsDigest: global.recordsDigest,
    rollout: clone(command.rollout),
    issuedAt: now.iso,
  };
  const canonicalPayload = protocol.assertChannel(payload,
    protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION);
  const artifact = {
    keyId: signing.keyId,
    payload: canonicalPayload,
    signature: crypto.sign(null, protocol.signingInput(canonicalPayload, signing.keyId),
      signing.privateKey).toString('base64'),
  };
  const payloadDigest = protocol.payloadDigest(canonicalPayload,
    protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION);
  const artifactDigest = operationDigest(artifact);
  return {
    schemaVersion: 1,
    customerId: command.customerId,
    deploymentId: command.deploymentId,
    idempotencyKey: command.idempotencyKey,
    operationDigest: opDigest,
    distributionSequence: canonicalPayload.distributionSequence,
    previousDistributionSequence: canonicalPayload.previousDistributionSequence,
    globalReleaseId: global.globalReleaseId,
    globalVersion: command.globalVersion,
    globalArtifactDigest: global.artifactDigest,
    recordsDigest: global.recordsDigest,
    rollout: clone(command.rollout),
    payloadDigest,
    artifactDigest,
    // Compatibility alias for the previously ambiguous field.
    distributionDigest: artifactDigest,
    globalArtifact: clone(global.artifact),
    distributionArtifact: artifact,
    createdAt: now.iso,
  };
}

function assertGlobalReleaseCurrentAuthority(global, authority) {
  const artifact = global.artifact;
  const generation = artifact.payload.authorityManifestGeneration;
  const slot = artifact.payload.authorityManifestKeySlot;
  const selected = slot === 'current' ? authority.global.current : authority.global.next;
  if (generation !== authority.manifestGeneration || !selected
      || !['current', 'next'].includes(slot) || selected.keyId !== artifact.keyId) {
    throw fault('global_release_authority_stale');
  }
}

function catalogAuthorityDescriptor(authority) {
  const purpose = (value) => ({
    current: { keyId: value.current.keyId, fingerprint: value.current.fingerprint },
    next: value.next
      ? { keyId: value.next.keyId, fingerprint: value.next.fingerprint } : null,
    archived: [...value.archived].map(([keyId, record]) => ({
      keyId,
      fingerprint: record.fingerprint,
    })).sort((left, right) => left.keyId.localeCompare(right.keyId)),
  });
  return {
    manifestGeneration: authority.manifestGeneration,
    global: purpose(authority.global),
    distribution: purpose(authority.distribution),
  };
}

function assertCatalogAuthorityCurrent(ctx, expected) {
  const current = ctx.keyAuthority.resolve();
  if (operationDigest(catalogAuthorityDescriptor(current))
      !== operationDigest(catalogAuthorityDescriptor(expected))) {
    throw fault('catalog_authority_changed');
  }
}

function verifyDistributionRecord(value, ctx) {
  const keys = [
    'artifactDigest', 'createdAt', 'customerId', 'deploymentId', 'distributionArtifact',
    'distributionDigest', 'distributionSequence', 'globalArtifact', 'globalArtifactDigest',
    'globalReleaseId', 'globalVersion', 'idempotencyKey', 'operationDigest', 'payloadDigest',
    'previousDistributionSequence', 'recordsDigest', 'rollout', 'schemaVersion',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || !UUID_RE.test(value.idempotencyKey) || !SHA256_RE.test(value.operationDigest)
      || !SHA256_RE.test(value.globalArtifactDigest) || !SHA256_RE.test(value.recordsDigest)
      || !SHA256_RE.test(value.payloadDigest) || !SHA256_RE.test(value.artifactDigest)
      || value.distributionDigest !== value.artifactDigest) {
    throw fault('distribution_state_invalid');
  }
  validateScope(value.customerId, value.deploymentId);
  parseIso(value.createdAt, 'distribution_state_invalid');
  validateDistributionCommand({
    authEventId: '00000000-0000-4000-8000-000000000001',
    confirmationId: '00000000-0000-4000-8000-000000000002',
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    idempotencyKey: value.idempotencyKey,
    keySlot: 'current',
    globalReleaseId: value.globalReleaseId,
    globalVersion: value.globalVersion,
    globalArtifactDigest: value.globalArtifactDigest,
    recordsDigest: value.recordsDigest,
    expectedDistributionSequence: value.previousDistributionSequence,
    rollout: value.rollout,
  });
  const globalArtifact = verifyGlobalArtifact(value.globalArtifact, ctx);
  const artifact = verifyCatalogArtifact(value.distributionArtifact, ctx);
  if (artifact.payload.customerId !== value.customerId
      || artifact.payload.deploymentId !== value.deploymentId
      || artifact.payload.distributionSequence !== value.distributionSequence
      || artifact.payload.previousDistributionSequence !== value.previousDistributionSequence
      || artifact.payload.globalReleaseId !== value.globalReleaseId
      || artifact.payload.globalVersion !== value.globalVersion
      || artifact.payload.globalArtifactDigest !== value.globalArtifactDigest
      || artifact.payload.recordsDigest !== value.recordsDigest
      || artifact.payload.issuedAt !== value.createdAt
      || artifact.payloadDigest !== value.payloadDigest
      || operationDigest(globalArtifact) !== value.globalArtifactDigest
      || globalArtifact.payload.globalReleaseId !== value.globalReleaseId
      || globalArtifact.payload.globalVersion !== value.globalVersion
      || globalArtifact.payload.recordsDigest !== value.recordsDigest
      || operationDigest(value.distributionArtifact) !== value.artifactDigest) {
    throw fault('distribution_state_invalid');
  }
  return clone(value);
}

function verifyCatalogArtifact(value, ctx) {
  if (!plainRecord(value) || !exactKeys(value, ['keyId', 'payload', 'signature'])
      || !SAFE_ID_RE.test(String(value.keyId || ''))) throw fault('distribution_state_invalid');
  const payload = protocol.assertChannel(value.payload,
    protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION);
  const signature = decodeSignature(value.signature, 'distribution_state_invalid');
  const authority = ctx.keyAuthority.resolve();
  const trusted = authority.distribution.archived.get(value.keyId);
  assertArtifactAuthorityBinding(
    authority, authority.distribution, KEY_PURPOSES.CATALOG_DISTRIBUTION, value,
  );
  if (!trusted || !crypto.verify(null, protocol.signingInput(payload, value.keyId),
    trusted.publicKey, signature)) throw fault('distribution_signature_invalid');
  return { payload, payloadDigest: protocol.payloadDigest(payload,
    protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION) };
}

function assertArtifactAuthorityBinding(authority, purposeAuthority, purpose, artifact) {
  const generation = artifact.payload.authorityManifestGeneration;
  const slot = artifact.payload.authorityManifestKeySlot;
  if (!authority.registry) {
    const selected = slot === 'current' ? purposeAuthority.current : purposeAuthority.next;
    if (generation !== 1 || !selected || selected.keyId !== artifact.keyId) {
      throw fault('artifact_authority_binding_invalid');
    }
    return;
  }
  if (!Number.isSafeInteger(generation) || generation < 1
      || generation > authority.manifestGeneration) {
    throw fault('artifact_authority_binding_invalid');
  }
  let record;
  try {
    record = authority.registry.list(purpose)
      .find((candidate) => candidate.keyId === artifact.keyId);
  } catch { throw fault('artifact_authority_binding_invalid'); }
  const trusted = purposeAuthority.archived.get(artifact.keyId);
  if (!record || !trusted || record.identity !== trusted.fingerprint) {
    throw fault('artifact_authority_binding_invalid');
  }
  if (generation === authority.manifestGeneration
      && (record.slot !== slot || !['current', 'next'].includes(record.slot))) {
    throw fault('artifact_authority_binding_invalid');
  }
}

function readDistribution(wrapped, ctx) {
  return verifyDistributionRecord(
    ctx.integrity.open(INTEGRITY_DOMAINS.DISTRIBUTION, wrapped), ctx,
  );
}

function replayDistribution(wrapped, opDigest, ctx) {
  const value = readDistribution(wrapped, ctx);
  if (value.operationDigest !== opDigest) throw fault('idempotency_conflict');
  return publicDistribution(value);
}

function publicDistribution(value) {
  return clone({
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    distributionSequence: value.distributionSequence,
    previousDistributionSequence: value.previousDistributionSequence,
    globalReleaseId: value.globalReleaseId,
    globalVersion: value.globalVersion,
    globalArtifactDigest: value.globalArtifactDigest,
    recordsDigest: value.recordsDigest,
    rollout: value.rollout,
    payloadDigest: value.payloadDigest,
    artifactDigest: value.artifactDigest,
    distributionDigest: value.distributionDigest,
    globalArtifact: value.globalArtifact,
    distributionArtifact: value.distributionArtifact,
    createdAt: value.createdAt,
  });
}

function initialAdoption(distribution, recordedAt) {
  return {
    schemaVersion: 1,
    customerId: distribution.customerId,
    deploymentId: distribution.deploymentId,
    distributionSequence: distribution.distributionSequence,
    globalReleaseId: distribution.globalReleaseId,
    globalVersion: distribution.globalVersion,
    globalArtifactDigest: distribution.globalArtifactDigest,
    recordsDigest: distribution.recordsDigest,
    distributionDigest: distribution.distributionDigest,
    revision: 1,
    stage: 'published',
    deliveryAttempts: 0,
    acknowledgementCount: 0,
    failures: [],
    lastDeliveryConfirmationId: null,
    lastDeliveryOperationDigest: null,
    lastAcknowledgementId: null,
    lastAcknowledgementDigest: null,
    updatedAt: recordedAt,
  };
}

function adoptionNamespace(value) {
  return governanceNamespace('adoption', {
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    distributionSequence: value.distributionSequence,
  });
}

async function markDelivered(commandValue, ctx) {
  const command = exactCommand(commandValue, [
    'authEventId', 'confirmationId', 'customerId', 'deploymentId',
    'distributionSequence', 'expectedRevision', 'globalArtifactDigest',
    'globalReleaseId', 'globalVersion', 'recordsDigest',
  ], 'delivery_command_invalid');
  validateAdoptionCommand(command, 'delivery_command_invalid', true);
  const scope = scopeOf(command);
  const opDigest = operationDigest({ ...scope, expectedRevision: command.expectedRevision,
    distributionSequence: command.distributionSequence, globalReleaseId: command.globalReleaseId,
    globalVersion: command.globalVersion, globalArtifactDigest: command.globalArtifactDigest,
    recordsDigest: command.recordsDigest, operation: 'mark_delivered' });
  return transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'distribution_deliver', opDigest, scope,
    }, now, ctx);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose: 'distribution_deliver', opDigest,
    }, authority, now, ctx.integrity);
    const distribution = await requireDistribution(tx, command, ctx, now);
    const adoption = await requireAdoption(tx, command, ctx, now);
    if (confirmation.claim === 'replay'
        && adoption.lastDeliveryConfirmationId === command.confirmationId
        && adoption.lastDeliveryOperationDigest === opDigest) return publicAdoption(adoption);
    if (adoption.revision !== command.expectedRevision) throw fault('adoption_revision_conflict');
    if (!['published', 'rejected'].includes(adoption.stage)) throw fault('adoption_stage_conflict');
    if (adoption.deliveryAttempts >= MAX_DELIVERY_ATTEMPTS) throw fault('delivery_attempts_exhausted');
    const next = {
      ...adoption,
      revision: adoption.revision + 1,
      stage: 'delivered',
      deliveryAttempts: adoption.deliveryAttempts + 1,
      lastDeliveryConfirmationId: command.confirmationId,
      lastDeliveryOperationDigest: opDigest,
      updatedAt: now.iso,
    };
    const auditRequest = {
      action: AUDIT_ACTIONS.DISTRIBUTION_DELIVERED,
      authorizationLinkId: confirmation.link.linkId,
      scope,
      referenceDigest: distribution.distributionDigest,
      version: command.distributionSequence,
    };
    const governance = await prepareGovernedMutation(tx, {
      namespace: adoptionNamespace(command),
      expectedRevision: adoption.revision,
      currentStateDigest: operationDigest(adoption),
      targetRevision: next.revision,
      targetStateDigest: operationDigest(next),
      auditRequest,
    }, now, ctx);
    await writeAdoption(tx, command, adoption.revision, next, ctx.integrity);
    const audit = await appendAudit(tx, auditRequest, now, ctx, lifecycle);
    await finalizeGovernedMutation(tx, governance, audit, ctx, lifecycle);
    return publicAdoption(next);
  });
}

async function recordCustomerAcknowledgement(commandValue, ctx) {
  const command = exactCommand(commandValue, [
    'acknowledgement', 'authEventId', 'customerId', 'deploymentId',
    'distributionSequence', 'expectedRevision', 'globalArtifactDigest',
    'globalReleaseId', 'globalVersion', 'recordsDigest',
  ], 'acknowledgement_command_invalid');
  validateAdoptionCommand(command, 'acknowledgement_command_invalid', false);
  const acknowledgement = protocol.assertChannel(command.acknowledgement,
    protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
  validateCustomerAcknowledgement(command, acknowledgement);
  const scope = scopeOf(command);
  const acknowledgementDigest = protocol.payloadDigest(acknowledgement,
    protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
  const transitionIdentity = acknowledgementTransitionIdentity(acknowledgement);
  const transitionKey = operationDigest(transitionIdentity);
  const opDigest = operationDigest({ ...scope, acknowledgementDigest,
    distributionSequence: command.distributionSequence,
    globalReleaseId: command.globalReleaseId, globalVersion: command.globalVersion,
    globalArtifactDigest: command.globalArtifactDigest, recordsDigest: command.recordsDigest });
  return transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'customer_ack', opDigest, scope,
    }, now, ctx);
    const claim = await call(tx, 'claimAcknowledgementTransition',
      transitionKey, acknowledgement.messageId, acknowledgementDigest);
    const status = claimResult(claim);
    if (status === 'conflict') throw fault('acknowledgement_reuse_conflict');
    if (status === 'replay') return replayAcknowledgementClaim(claim, acknowledgementDigest,
      ctx.integrity);
    if (status !== 'claimed') throw fault('storage_contract_invalid');
    const distribution = await requireDistribution(tx, command, ctx, now);
    if (distribution.payloadDigest !== acknowledgement.targetDigest) {
      throw fault('acknowledgement_target_conflict');
    }
    const adoption = await requireAdoption(tx, command, ctx, now);
    if (adoption.revision !== command.expectedRevision) throw fault('adoption_revision_conflict');
    const next = nextAcknowledgedAdoption(adoption, acknowledgement,
      acknowledgementDigest, now);
    const auditRequest = {
      action: AUDIT_ACTIONS.DISTRIBUTION_ACKNOWLEDGED,
      authorizationLinkId: authority.link.linkId,
      scope,
      referenceDigest: acknowledgementDigest,
      version: command.distributionSequence,
      outcome: acknowledgement.outcome,
    };
    const governance = await prepareGovernedMutation(tx, {
      namespace: adoptionNamespace(command),
      expectedRevision: adoption.revision,
      currentStateDigest: operationDigest(adoption),
      targetRevision: next.revision,
      targetStateDigest: operationDigest(next),
      auditRequest,
    }, now, ctx);
    await writeAdoption(tx, command, adoption.revision, next, ctx.integrity);
    const result = publicAdoption(next);
    const claimPayload = {
      schemaVersion: 1,
      transitionKey,
      transitionIdentity,
      messageId: acknowledgement.messageId,
      acknowledgementDigest,
      customerId: command.customerId,
      deploymentId: command.deploymentId,
      distributionSequence: command.distributionSequence,
      globalReleaseId: command.globalReleaseId,
      globalVersion: command.globalVersion,
      globalArtifactDigest: command.globalArtifactDigest,
      recordsDigest: command.recordsDigest,
      result,
      completedAt: now.iso,
    };
    if (await call(tx, 'completeAcknowledgementTransition', transitionKey,
      acknowledgementDigest, ctx.integrity.seal(INTEGRITY_DOMAINS.ACK_CLAIM,
        claimPayload)) !== true) throw fault('acknowledgement_claim_failed');
    const audit = await appendAudit(tx, auditRequest, now, ctx, lifecycle);
    await finalizeGovernedMutation(tx, governance, audit, ctx, lifecycle);
    return result;
  });
}

function acknowledgementTransitionIdentity(value) {
  return {
    schemaVersion: 1,
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    targetKind: value.targetKind,
    targetVersion: value.targetVersion,
    targetDigest: value.targetDigest,
    targetGlobalReleaseId: value.targetGlobalReleaseId,
    targetGlobalVersion: value.targetGlobalVersion,
    targetGlobalArtifactDigest: value.targetGlobalArtifactDigest,
    lifecycleStage: value.lifecycleStage,
    outcome: value.outcome,
  };
}

function validateAdoptionCommand(command, code, delivery) {
  validateScope(command.customerId, command.deploymentId);
  if (!UUID_RE.test(command.authEventId)
      || !Number.isSafeInteger(command.distributionSequence) || command.distributionSequence < 1
      || !UUID_RE.test(command.globalReleaseId)
      || !Number.isSafeInteger(command.globalVersion) || command.globalVersion < 1
      || !SHA256_RE.test(command.globalArtifactDigest) || !SHA256_RE.test(command.recordsDigest)
      || !Number.isSafeInteger(command.expectedRevision) || command.expectedRevision < 1
      || (delivery && !UUID_RE.test(command.confirmationId))) throw fault(code);
}

function validateCustomerAcknowledgement(command, value) {
  if (value.customerId !== command.customerId || value.deploymentId !== command.deploymentId
      || value.targetKind !== protocol.CHANNEL_KINDS.CATALOG_DISTRIBUTION
      || value.targetVersion !== command.distributionSequence
      || value.targetGlobalReleaseId !== command.globalReleaseId
      || value.targetGlobalVersion !== command.globalVersion
      || value.targetGlobalArtifactDigest !== command.globalArtifactDigest
      || value.lifecycleStage !== 'applied') {
    throw fault('acknowledgement_target_conflict');
  }
}

async function requireDistribution(tx, command, ctx, now) {
  const currentWrapped = await call(tx, 'readCurrentDistribution', command.customerId,
    command.deploymentId);
  if (!currentWrapped) throw fault('distribution_not_found');
  const current = readDistribution(currentWrapped, ctx);
  await verifyGovernedState(tx, {
    namespace: governanceNamespace('distribution-current', scopeOf(command)),
    revision: current.distributionSequence,
    stateDigest: operationDigest(current),
  }, now, ctx);
  const wrapped = await call(tx, 'readDistribution', command.customerId,
    command.deploymentId, command.distributionSequence);
  if (!wrapped) throw fault('distribution_not_found');
  const distribution = readDistribution(wrapped, ctx);
  if (distribution.customerId !== command.customerId
      || distribution.deploymentId !== command.deploymentId
      || distribution.distributionSequence !== command.distributionSequence
      || distribution.globalReleaseId !== command.globalReleaseId
      || distribution.globalVersion !== command.globalVersion
      || distribution.globalArtifactDigest !== command.globalArtifactDigest
      || distribution.recordsDigest !== command.recordsDigest) throw fault('distribution_lookup_mismatch');
  return distribution;
}

async function requireAdoption(tx, command, ctx, now) {
  const wrapped = await call(tx, 'readAdoption', command.customerId,
    command.deploymentId, command.distributionSequence);
  if (!wrapped) throw fault('adoption_not_found');
  const adoption = ctx.integrity.open(INTEGRITY_DOMAINS.ADOPTION, wrapped);
  validateAdoption(adoption);
  if (adoption.customerId !== command.customerId || adoption.deploymentId !== command.deploymentId
      || adoption.globalVersion !== command.globalVersion) throw fault('scope_mismatch');
  if (adoption.distributionSequence !== command.distributionSequence
      || adoption.globalReleaseId !== command.globalReleaseId
      || adoption.globalArtifactDigest !== command.globalArtifactDigest
      || adoption.recordsDigest !== command.recordsDigest) throw fault('adoption_lookup_mismatch');
  await verifyGovernedState(tx, {
    namespace: adoptionNamespace(command),
    revision: adoption.revision,
    stateDigest: operationDigest(adoption),
  }, now, ctx);
  return adoption;
}

async function writeAdoption(tx, command, expectedRevision, value, integrity) {
  validateAdoption(value);
  if (await call(tx, 'compareAndSetAdoption', command.customerId, command.deploymentId,
    command.distributionSequence, expectedRevision,
    integrity.seal(INTEGRITY_DOMAINS.ADOPTION, value)) !== true) {
    throw fault('adoption_revision_conflict');
  }
  const readback = integrity.open(INTEGRITY_DOMAINS.ADOPTION,
    await call(tx, 'readAdoption', command.customerId, command.deploymentId,
      command.distributionSequence));
  validateAdoption(readback);
  if (operationDigest(readback) !== operationDigest(value)) {
    throw fault('adoption_cas_readback_failed');
  }
}

function nextAcknowledgedAdoption(adoption, acknowledgement, acknowledgementDigest, now) {
  let failures = adoption.failures;
  let stage;
  if (acknowledgement.outcome === 'rejected' && failures.length >= MAX_FAILURES) {
    throw fault('adoption_failures_exhausted');
  }
  if (adoption.acknowledgementCount >= MAX_ACKNOWLEDGEMENTS) {
    throw fault('acknowledgements_exhausted');
  }
  if (acknowledgement.outcome === 'success') {
    if (!['delivered', 'applied'].includes(adoption.stage)) throw fault('adoption_stage_conflict');
    stage = 'applied';
  } else {
    if (!['published', 'delivered', 'rejected'].includes(adoption.stage)) {
      throw fault('adoption_stage_conflict');
    }
    stage = 'rejected';
    failures = [...failures, {
      reasonCode: acknowledgement.reasonCode,
      acknowledgementDigest,
      recordedAt: now.iso,
    }];
  }
  return {
    ...adoption,
    revision: adoption.revision + 1,
    stage,
    acknowledgementCount: adoption.acknowledgementCount + 1,
    failures,
    lastAcknowledgementId: acknowledgement.messageId,
    lastAcknowledgementDigest: acknowledgementDigest,
    updatedAt: now.iso,
  };
}

function validateAdoption(value) {
  const keys = [
    'acknowledgementCount', 'customerId', 'deliveryAttempts', 'deploymentId',
    'distributionDigest', 'distributionSequence', 'failures', 'globalArtifactDigest',
    'globalReleaseId', 'globalVersion', 'lastAcknowledgementDigest', 'lastAcknowledgementId',
    'lastDeliveryConfirmationId', 'lastDeliveryOperationDigest', 'revision', 'schemaVersion',
    'recordsDigest', 'stage', 'updatedAt',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || !Number.isSafeInteger(value.globalVersion) || value.globalVersion < 1
      || !Number.isSafeInteger(value.distributionSequence) || value.distributionSequence < 1
      || !UUID_RE.test(value.globalReleaseId) || !SHA256_RE.test(value.globalArtifactDigest)
      || !SHA256_RE.test(value.recordsDigest)
      || !Number.isSafeInteger(value.revision) || value.revision < 1
      || !Number.isSafeInteger(value.deliveryAttempts) || value.deliveryAttempts < 0
      || value.deliveryAttempts > MAX_DELIVERY_ATTEMPTS
      || !Number.isSafeInteger(value.acknowledgementCount) || value.acknowledgementCount < 0
      || value.acknowledgementCount > MAX_ACKNOWLEDGEMENTS
      || !['published', 'delivered', 'applied', 'rejected'].includes(value.stage)
      || !SHA256_RE.test(value.distributionDigest)
      || !Array.isArray(value.failures) || value.failures.length > MAX_FAILURES) {
    throw fault('adoption_state_invalid');
  }
  validateScope(value.customerId, value.deploymentId);
  parseIso(value.updatedAt, 'adoption_state_invalid');
  validateNullablePair(value.lastDeliveryConfirmationId,
    value.lastDeliveryOperationDigest, UUID_RE, SHA256_RE, 'adoption_state_invalid');
  validateNullablePair(value.lastAcknowledgementId,
    value.lastAcknowledgementDigest, UUID_RE, SHA256_RE, 'adoption_state_invalid');
  for (const failure of value.failures) {
    if (!plainRecord(failure)
        || !exactKeys(failure, ['acknowledgementDigest', 'reasonCode', 'recordedAt'])
        || !SHA256_RE.test(failure.acknowledgementDigest)
        || !SAFE_ID_RE.test(failure.reasonCode)) throw fault('adoption_state_invalid');
    parseIso(failure.recordedAt, 'adoption_state_invalid');
  }
}

function replayAcknowledgementClaim(claim, expectedDigest, integrity) {
  if (!plainRecord(claim) || !Object.hasOwn(claim, 'record')) throw fault('storage_contract_invalid');
  const value = integrity.open(INTEGRITY_DOMAINS.ACK_CLAIM, claim.record);
  const keys = [
    'acknowledgementDigest', 'completedAt', 'customerId', 'deploymentId',
    'distributionSequence', 'globalArtifactDigest', 'globalReleaseId', 'globalVersion',
    'messageId', 'recordsDigest', 'result', 'schemaVersion', 'transitionIdentity',
    'transitionKey',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || value.acknowledgementDigest !== expectedDigest || !UUID_RE.test(value.messageId)
      || !SHA256_RE.test(value.transitionKey)
      || operationDigest(value.transitionIdentity) !== value.transitionKey) {
    throw fault('acknowledgement_claim_invalid');
  }
  validateAdoption({ ...value.result });
  parseIso(value.completedAt, 'acknowledgement_claim_invalid');
  return clone(value.result);
}

function publicAdoption(value) {
  return clone(value);
}

async function createPortalSnapshot(tx, kind, scope, rows, pageSize, now, ctx,
  consentEpoch = null) {
  const snapshotId = checkedUuid(ctx.randomUUID);
  const scopeDigest = operationDigest(scope);
  const expiresAt = new Date(now.ms + PAGE_SNAPSHOT_TTL_MS).toISOString();
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const pages = [];
  for (let pageIndex = 0; pageIndex < pageCount; pageIndex += 1) {
    const pageRows = rows.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize);
    const descriptor = {
      schemaVersion: 1,
      snapshotId,
      kind,
      scopeDigest,
      pageIndex,
      pageCount,
      pageSize,
      consentEpoch: consentEpoch?.epoch || null,
      consentId: consentEpoch?.consentId || null,
      consentRevision: consentEpoch?.consentRevision || null,
      consentDigest: consentEpoch?.consentDigest || null,
      rowDigests: pageRows.map(operationDigest),
      nextPageIndex: pageIndex + 1 < pageCount ? pageIndex + 1 : null,
      expiresAt,
    };
    pages.push({
      descriptor: ctx.integrity.seal(INTEGRITY_DOMAINS.PAGE_DESCRIPTOR, descriptor),
      rows: clone(pageRows),
    });
  }
  if (await call(tx, 'createPageSnapshot', snapshotId, expiresAt, pages,
    MAX_ACTIVE_PAGE_SNAPSHOTS, now.iso, scope?.customerId || null,
    scope?.deploymentId || null, consentEpoch?.epoch || null) !== true) {
    throw fault('page_snapshot_quota_exceeded');
  }
  return { schemaVersion: 1, snapshotId, kind, scopeDigest,
    pageIndex: 0, pageCount, pageSize, expiresAt,
    consentEpoch: consentEpoch?.epoch || null,
    consentId: consentEpoch?.consentId || null,
    consentRevision: consentEpoch?.consentRevision || null,
    consentDigest: consentEpoch?.consentDigest || null };
}

function encodePageCursor(locator, integrity) {
  const wrapped = integrity.seal(INTEGRITY_DOMAINS.PAGE_CURSOR, locator);
  const token = Buffer.from(protocol.canonicalJson(wrapped), 'utf8').toString('base64url');
  if (Buffer.byteLength(token, 'utf8') > MAX_CURSOR_BYTES) throw fault('page_cursor_invalid');
  return token;
}

function decodePageCursor(token, expected, now, integrity) {
  if (typeof token !== 'string' || token.length < 1
      || Buffer.byteLength(token, 'utf8') > MAX_CURSOR_BYTES
      || !/^[A-Za-z0-9_-]+$/.test(token)) throw fault('page_cursor_invalid');
  let wrapped;
  try {
    const bytes = Buffer.from(token, 'base64url');
    if (bytes.toString('base64url') !== token) throw new Error('non-canonical cursor');
    wrapped = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw fault('page_cursor_invalid');
  }
  let value;
  try { value = integrity.open(INTEGRITY_DOMAINS.PAGE_CURSOR, wrapped); }
  catch { throw fault('page_cursor_invalid'); }
  validatePageLocator(value, expected, now);
  return value;
}

function validatePageLocator(value, expected, now) {
  const keys = [
    'consentDigest', 'consentEpoch', 'consentId', 'consentRevision', 'expiresAt',
    'kind', 'pageCount', 'pageIndex', 'pageSize', 'schemaVersion', 'scopeDigest',
    'snapshotId',
  ];
  if (!plainRecord(value) || !exactKeys(value, keys) || value.schemaVersion !== 1
      || !UUID_RE.test(value.snapshotId) || value.kind !== expected.kind
      || value.scopeDigest !== expected.scopeDigest
      || value.pageSize !== expected.pageSize
      || value.consentEpoch !== expected.consentEpoch
      || value.consentId !== expected.consentId
      || value.consentRevision !== expected.consentRevision
      || value.consentDigest !== expected.consentDigest
      || !Number.isSafeInteger(value.pageCount) || value.pageCount < 1
      || !Number.isSafeInteger(value.pageIndex) || value.pageIndex < 0
      || value.pageIndex >= value.pageCount) throw fault('page_cursor_invalid');
  validateCursorConsentBinding(value, 'page_cursor_invalid');
  const expiresAt = parseIso(value.expiresAt, 'page_cursor_invalid');
  if (expiresAt <= now.ms) throw fault('page_cursor_expired');
}

async function loadPortalSnapshotPage(tx, locator, now, ctx) {
  const stored = await call(tx, 'readPageSnapshot', locator.snapshotId,
    locator.pageIndex, now.iso);
  if (!plainRecord(stored) || !exactKeys(stored, ['descriptor', 'rows'])
      || !Array.isArray(stored.rows) || stored.rows.length > locator.pageSize) {
    throw fault('page_snapshot_invalid');
  }
  const descriptor = ctx.integrity.open(INTEGRITY_DOMAINS.PAGE_DESCRIPTOR,
    stored.descriptor);
  const keys = [
    'consentDigest', 'consentEpoch', 'consentId', 'consentRevision', 'expiresAt',
    'kind', 'nextPageIndex', 'pageCount', 'pageIndex', 'pageSize', 'rowDigests',
    'schemaVersion', 'scopeDigest', 'snapshotId',
  ];
  const expectedNext = locator.pageIndex + 1 < locator.pageCount
    ? locator.pageIndex + 1 : null;
  if (!plainRecord(descriptor) || !exactKeys(descriptor, keys)
      || descriptor.schemaVersion !== 1 || descriptor.snapshotId !== locator.snapshotId
      || descriptor.kind !== locator.kind || descriptor.scopeDigest !== locator.scopeDigest
      || descriptor.pageIndex !== locator.pageIndex || descriptor.pageCount !== locator.pageCount
      || descriptor.pageSize !== locator.pageSize || descriptor.expiresAt !== locator.expiresAt
      || descriptor.consentEpoch !== locator.consentEpoch
      || descriptor.consentId !== locator.consentId
      || descriptor.consentRevision !== locator.consentRevision
      || descriptor.consentDigest !== locator.consentDigest
      || descriptor.nextPageIndex !== expectedNext || !Array.isArray(descriptor.rowDigests)
      || descriptor.rowDigests.length !== stored.rows.length
      || (expectedNext !== null && stored.rows.length !== locator.pageSize)
      || !descriptor.rowDigests.every((digestValue) => SHA256_RE.test(digestValue))) {
    throw fault('page_snapshot_invalid');
  }
  validateCursorConsentBinding(descriptor, 'page_snapshot_invalid');
  if (descriptor.rowDigests.some((digestValue, index) =>
    digestValue !== operationDigest(stored.rows[index]))) throw fault('page_snapshot_invalid');
  if (parseIso(descriptor.expiresAt, 'page_snapshot_invalid') <= now.ms) {
    throw fault('page_cursor_expired');
  }
  return { descriptor, rows: stored.rows };
}

function validateCursorConsentBinding(value, code) {
  const empty = value.consentEpoch === null && value.consentId === null
    && value.consentRevision === null && value.consentDigest === null;
  const bound = Number.isSafeInteger(value.consentEpoch) && value.consentEpoch >= 1
    && UUID_RE.test(String(value.consentId || ''))
    && Number.isSafeInteger(value.consentRevision) && value.consentRevision >= 1
    && SHA256_RE.test(String(value.consentDigest || ''));
  if (!empty && !bound) throw fault(code);
}

async function releasePortalSnapshot(tx, descriptor) {
  if (descriptor.nextPageIndex !== null) return;
  if (await call(tx, 'releasePageSnapshot', descriptor.snapshotId) !== true) {
    throw fault('page_snapshot_release_failed');
  }
}

function nextPageCursor(locator, descriptor, integrity) {
  if (descriptor.nextPageIndex === null) return null;
  return encodePageCursor({ ...locator, pageIndex: descriptor.nextPageIndex }, integrity);
}

async function listCustomerObservations(commandValue, ctx) {
  const command = exactCommand(commandValue,
    ['authEventId', 'cursor', 'customerId', 'deploymentId', 'limit'],
    'observation_list_command_invalid');
  validatePageCommand(command, true, 'observation_list_command_invalid');
  const scope = scopeOf(command);
  const opDigest = operationDigest({ ...scope, cursor: command.cursor, limit: command.limit });
  const result = await transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'customer_observation_read', opDigest, scope,
    }, now, ctx);
    const consentEnforcement = await enforceScopeConsent(tx, scope, now, ctx,
      authority.link.linkId, lifecycle);
    if (!consentEnforcement.granted) return { consentDenied: consentEnforcement.code };
    const purged = await call(tx, 'purgeExpiredObservations', command.customerId,
      command.deploymentId, now.iso, MAX_OBSERVATIONS_PER_SCOPE);
    if (!Number.isSafeInteger(purged) || purged < 0 || purged > MAX_OBSERVATIONS_PER_SCOPE) {
      throw fault('storage_contract_invalid');
    }
    let locator;
    if (command.cursor === null) {
      const initialRows = await call(tx, 'listObservations', command.customerId,
        command.deploymentId, null, MAX_OBSERVATIONS_PER_SCOPE + 1, now.iso);
      if (!Array.isArray(initialRows) || initialRows.length > MAX_OBSERVATIONS_PER_SCOPE) {
        throw fault('storage_contract_invalid');
      }
      for (const wrapped of initialRows) {
        const observation = readObservation(wrapped, ctx.integrity);
        if (observation.customerId !== command.customerId
            || observation.deploymentId !== command.deploymentId
            || parseIso(observation.retainUntil, 'observation_state_invalid') <= now.ms) {
          throw fault('observation_state_invalid');
        }
      }
      locator = await createPortalSnapshot(tx, 'customer_observations', scope,
        initialRows, command.limit, now, ctx, consentEnforcement.consentEpoch);
    } else {
      locator = decodePageCursor(command.cursor, {
        kind: 'customer_observations', scopeDigest: operationDigest(scope),
        pageSize: command.limit,
        consentEpoch: consentEnforcement.consentEpoch.epoch,
        consentId: consentEnforcement.consentEpoch.consentId,
        consentRevision: consentEnforcement.consentEpoch.consentRevision,
        consentDigest: consentEnforcement.consentEpoch.consentDigest,
      }, now, ctx.integrity);
    }
    const snapshotPage = await loadPortalSnapshotPage(tx, locator, now, ctx);
    const observations = snapshotPage.rows.map((wrapped) =>
      readObservation(wrapped, ctx.integrity));
    for (const observation of observations) {
      if (observation.customerId !== command.customerId
          || observation.deploymentId !== command.deploymentId
          || parseIso(observation.retainUntil, 'observation_state_invalid') <= now.ms) {
        throw fault('observation_state_invalid');
      }
    }
    const pageResult = {
      items: observations.map(publicObservation),
      nextCursor: nextPageCursor(locator, snapshotPage.descriptor, ctx.integrity),
    };
    await releasePortalSnapshot(tx, snapshotPage.descriptor);
    await appendAudit(tx, {
      action: AUDIT_ACTIONS.CUSTOMER_OBSERVATIONS_READ,
      authorizationLinkId: authority.link.linkId,
      scope,
      referenceDigest: operationDigest({ snapshotId: locator.snapshotId,
        pageIndex: locator.pageIndex,
        returned: pageResult.items.map((item) => item.observationId) }),
    }, now, ctx, lifecycle);
    return pageResult;
  });
  if (result?.consentDenied) throw fault(result.consentDenied);
  return result;
}

async function listGlobalClassifications(commandValue, ctx) {
  const command = exactCommand(commandValue, ['authEventId', 'cursor', 'limit'],
    'classification_list_command_invalid');
  validatePageCommand(command, false, 'classification_list_command_invalid');
  const opDigest = operationDigest({ cursor: command.cursor, limit: command.limit });
  return transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'global_catalog_read', opDigest,
    }, now, ctx);
    let locator;
    if (command.cursor === null) {
      const initialRows = await call(tx, 'listAllClassifications', MAX_CLASSIFICATIONS + 1);
      if (!Array.isArray(initialRows) || initialRows.length > MAX_CLASSIFICATIONS) {
        throw fault('storage_contract_invalid');
      }
      for (const wrapped of initialRows) {
        const value = readClassification(wrapped, ctx.integrity);
        await verifyGovernedState(tx, {
          namespace: governanceNamespace('classification', { catalogId: value.record.catalogId }),
          revision: value.revision,
          stateDigest: operationDigest(value),
        }, now, ctx);
      }
      locator = await createPortalSnapshot(tx, 'global_classifications', null,
        initialRows, command.limit, now, ctx);
    } else {
      locator = decodePageCursor(command.cursor, {
        kind: 'global_classifications', scopeDigest: operationDigest(null),
        pageSize: command.limit, consentEpoch: null, consentId: null,
        consentRevision: null, consentDigest: null,
      }, now, ctx.integrity);
    }
    const snapshotPage = await loadPortalSnapshotPage(tx, locator, now, ctx);
    const classifications = snapshotPage.rows.map((wrapped) =>
      readClassification(wrapped, ctx.integrity));
    const pageResult = {
      items: classifications.map((item) => clone(item.record)),
      nextCursor: nextPageCursor(locator, snapshotPage.descriptor, ctx.integrity),
    };
    await releasePortalSnapshot(tx, snapshotPage.descriptor);
    await appendAudit(tx, {
      action: AUDIT_ACTIONS.GLOBAL_CLASSIFICATIONS_READ,
      authorizationLinkId: authority.link.linkId,
      referenceDigest: operationDigest({ snapshotId: locator.snapshotId,
        pageIndex: locator.pageIndex,
        returned: pageResult.items.map((item) => item.catalogId) }),
    }, now, ctx, lifecycle);
    return pageResult;
  });
}

async function distributionStatus(commandValue, ctx) {
  const command = exactCommand(commandValue,
    ['authEventId', 'customerId', 'deploymentId', 'distributionSequence',
      'globalArtifactDigest', 'globalReleaseId', 'globalVersion', 'recordsDigest'],
    'distribution_status_command_invalid');
  validateScope(command.customerId, command.deploymentId);
  if (!UUID_RE.test(command.authEventId)
      || !Number.isSafeInteger(command.distributionSequence) || command.distributionSequence < 1
      || !UUID_RE.test(command.globalReleaseId)
      || !Number.isSafeInteger(command.globalVersion) || command.globalVersion < 1
      || !SHA256_RE.test(command.globalArtifactDigest)
      || !SHA256_RE.test(command.recordsDigest)) throw fault('distribution_status_command_invalid');
  const scope = scopeOf(command);
  const opDigest = operationDigest({ ...scope,
    distributionSequence: command.distributionSequence,
    globalReleaseId: command.globalReleaseId, globalVersion: command.globalVersion,
    globalArtifactDigest: command.globalArtifactDigest, recordsDigest: command.recordsDigest });
  return transact(ctx, async (tx, lifecycle) => {
    const now = trustedNow(ctx.clock);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'distribution_status', opDigest, scope,
    }, now, ctx);
    const distribution = await requireDistribution(tx, command, ctx, now);
    const adoption = await requireAdoption(tx, command, ctx, now);
    const globalWrapped = await call(tx, 'readGlobalRelease', command.globalVersion);
    if (!globalWrapped) throw fault('global_release_not_found');
    const global = readGlobalRelease(globalWrapped, ctx, {
      globalVersion: command.globalVersion,
      globalReleaseId: command.globalReleaseId,
      artifactDigest: command.globalArtifactDigest,
      recordsDigest: command.recordsDigest,
    });
    if (global.globalReleaseId !== command.globalReleaseId
        || global.artifactDigest !== distribution.globalArtifactDigest
        || global.recordsDigest !== distribution.recordsDigest
        || adoption.distributionDigest !== distribution.distributionDigest) {
      throw fault('distribution_state_invalid');
    }
    const result = { distribution: publicDistribution(distribution),
      adoption: publicAdoption(adoption) };
    await appendAudit(tx, {
      action: AUDIT_ACTIONS.DISTRIBUTION_STATUS_READ,
      authorizationLinkId: authority.link.linkId,
      scope,
      referenceDigest: distribution.distributionDigest,
      version: command.distributionSequence,
    }, now, ctx, lifecycle);
    return result;
  });
}

function validatePageCommand(command, customerScoped, code) {
  if (!UUID_RE.test(command.authEventId)
      || !Number.isSafeInteger(command.limit) || command.limit < 1
      || command.limit > MAX_PAGE_SIZE
      || (command.cursor !== null && (typeof command.cursor !== 'string'
        || command.cursor.length < 1
        || Buffer.byteLength(command.cursor, 'utf8') > MAX_CURSOR_BYTES
        || !/^[A-Za-z0-9_-]+$/.test(command.cursor)))) throw fault(code);
  if (customerScoped) validateScope(command.customerId, command.deploymentId);
}

function validateScope(customerId, deploymentId) {
  if (!CUSTOMER_ID_RE.test(String(customerId || ''))
      || !isDeploymentId(deploymentId)) throw fault('scope_invalid');
}

function assertNullableScope(customerId, deploymentId) {
  if (customerId === null && deploymentId === null) return;
  validateScope(customerId, deploymentId);
}

function scopeOf(value) {
  validateScope(value.customerId, value.deploymentId);
  return Object.freeze({ customerId: value.customerId, deploymentId: value.deploymentId });
}

function validateNullablePair(left, right, leftPattern, rightPattern, code) {
  if (left === null && right === null) return;
  if (typeof left !== 'string' || typeof right !== 'string'
      || !leftPattern.test(left) || !rightPattern.test(right)) throw fault(code);
}

function parseIso(value, code) {
  if (typeof value !== 'string' || !ISO_MS_RE.test(value)) throw fault(code);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw fault(code);
  return parsed;
}

function checkedUuid(value) {
  const result = value();
  if (!UUID_RE.test(String(result || ''))) throw fault('random_source_invalid');
  return result;
}

function decodeSignature(value, code) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw fault(code);
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== value) throw fault(code);
  return decoded;
}

function sortedStrings(values) {
  return values.every((value, index) => typeof value === 'string'
    && (index === 0 || values[index - 1].localeCompare(value) < 0));
}

function claimResult(value) {
  const status = typeof value === 'string' ? value
    : (plainRecord(value) && typeof value.status === 'string' ? value.status : '');
  return ['claimed', 'replay', 'conflict', 'owned'].includes(status) ? status : '';
}

async function compactGlobalHistory(tx, ctx, currentVersion) {
  let rows = await globalHistoryRows(tx, ctx);
  if (rows.active.length > MAX_GLOBAL_RELEASES) throw fault('global_release_quota_exceeded');
  while (rows.active.length > GLOBAL_ROLLBACK_WINDOW) {
    const oldest = rows.active.shift();
    const tombstone = ctx.integrity.seal(INTEGRITY_DOMAINS.GLOBAL_HISTORY_TOMBSTONE,
      oldest.descriptor);
    if (await call(tx, 'writeGlobalHistoryTombstone', oldest.descriptor.sequence,
      oldest.descriptor.artifactDigest, tombstone) !== true
        || await call(tx, 'deleteGlobalRelease', oldest.descriptor.sequence,
          oldest.descriptor.artifactDigest, oldest.wrappedDigest,
          oldest.descriptor.idempotencyKey) !== true) {
      throw fault('global_history_compaction_failed');
    }
  }
  await compactGlobalTombstones(tx, ctx);
  await readGlobalHistory(tx, ctx, currentVersion);
}

async function compactGlobalTombstones(tx, ctx) {
  let rows = await globalHistoryRows(tx, ctx);
  while (rows.tombstones.length > MAX_GLOBAL_HISTORY_TOMBSTONES) {
    const oldest = rows.tombstones[0];
    const checkpoint = await readGlobalHistoryCheckpoint(tx, ctx);
    const descriptorBySequence = descriptorMap(rows);
    const advanced = advanceHistoryCheckpoint(
      checkpoint, oldest.descriptor.sequence, descriptorBySequence, 1, 'global', null,
    );
    if (await call(tx, 'compareAndSetGlobalHistoryCheckpoint', checkpoint.throughSequence,
      ctx.integrity.seal(INTEGRITY_DOMAINS.GLOBAL_HISTORY_CHECKPOINT, advanced)) !== true
        || await call(tx, 'deleteGlobalHistoryTombstone', oldest.descriptor.sequence,
          oldest.descriptor.artifactDigest, oldest.wrappedDigest) !== true) {
      throw fault('global_history_compaction_failed');
    }
    rows = await globalHistoryRows(tx, ctx);
  }
}

async function readGlobalHistory(tx, ctx, currentVersionValue = null) {
  const current = currentVersionValue === null
    ? await call(tx, 'readCurrentGlobalRelease') : null;
  const currentVersion = currentVersionValue === null
    ? (current ? readGlobalRelease(current, ctx).globalVersion : 0) : currentVersionValue;
  const rows = await globalHistoryRows(tx, ctx);
  const checkpoint = await readGlobalHistoryCheckpoint(tx, ctx);
  return verifyHistoryCoverage(checkpoint, rows, currentVersion, 1, 'global_history_invalid');
}

async function globalHistoryRows(tx, ctx) {
  const activeRaw = await call(tx, 'listGlobalReleases', MAX_GLOBAL_RELEASES + 1);
  const tombstoneRaw = await call(tx, 'listGlobalHistoryTombstones',
    MAX_GLOBAL_HISTORY_TOMBSTONES + 1);
  if (!Array.isArray(activeRaw) || !Array.isArray(tombstoneRaw)
      || activeRaw.length > MAX_GLOBAL_RELEASES + 1
      || tombstoneRaw.length > MAX_GLOBAL_HISTORY_TOMBSTONES + 1) {
    throw fault('storage_contract_invalid');
  }
  const active = activeRaw.map((row) => {
    if (!plainRecord(row) || !exactKeys(row, ['version', 'wrapped'])) {
      throw fault('global_history_invalid');
    }
    const release = readGlobalRelease(row.wrapped, ctx);
    if (release.globalVersion !== row.version) throw fault('global_history_invalid');
    return {
      descriptor: globalHistoryDescriptor(release),
      wrappedDigest: operationDigest(row.wrapped),
    };
  }).sort(historyRowOrder);
  const tombstones = tombstoneRaw.map((wrapped) => ({
    descriptor: validateGlobalHistoryDescriptor(
      ctx.integrity.open(INTEGRITY_DOMAINS.GLOBAL_HISTORY_TOMBSTONE, wrapped),
    ),
    wrappedDigest: operationDigest(wrapped),
  })).sort(historyRowOrder);
  return { active, tombstones };
}

function globalHistoryDescriptor(release) {
  return {
    schemaVersion: 1,
    sequence: release.globalVersion,
    globalReleaseId: release.globalReleaseId,
    artifactDigest: release.artifactDigest,
    recordsDigest: release.recordsDigest,
    signingKeyId: release.artifact.keyId,
    idempotencyKey: release.idempotencyKey,
    rollbackOfVersion: release.rollbackOfVersion,
  };
}

function validateGlobalHistoryDescriptor(value) {
  if (!plainRecord(value) || !exactKeys(value, [
    'artifactDigest', 'globalReleaseId', 'idempotencyKey', 'recordsDigest',
    'rollbackOfVersion', 'schemaVersion', 'sequence', 'signingKeyId',
  ]) || value.schemaVersion !== 1 || !Number.isSafeInteger(value.sequence)
      || value.sequence < 1 || !UUID_RE.test(value.globalReleaseId)
      || !UUID_RE.test(value.idempotencyKey) || !SHA256_RE.test(value.artifactDigest)
      || !SHA256_RE.test(value.recordsDigest)
      || !String(value.signingKeyId).startsWith('rw-catalog-global-')
      || (value.rollbackOfVersion !== null
        && (!Number.isSafeInteger(value.rollbackOfVersion)
          || value.rollbackOfVersion < 1 || value.rollbackOfVersion >= value.sequence))) {
    throw fault('global_history_invalid');
  }
  return value;
}

async function readGlobalHistoryCheckpoint(tx, ctx) {
  const wrapped = await call(tx, 'readGlobalHistoryCheckpoint');
  return wrapped ? openHistoryCheckpoint(ctx, wrapped, 'global', null,
    INTEGRITY_DOMAINS.GLOBAL_HISTORY_CHECKPOINT) : emptyHistoryCheckpoint('global', null);
}

async function compactDistributionHistory(tx, ctx, scope, currentSequence) {
  let rows = await distributionHistoryRows(tx, ctx, scope);
  if (rows.active.length > MAX_DISTRIBUTIONS_PER_DEPLOYMENT) {
    throw fault('distribution_quota_exceeded');
  }
  while (rows.active.length > DISTRIBUTION_ROLLBACK_WINDOW) {
    const oldest = rows.active.shift();
    const tombstone = ctx.integrity.seal(INTEGRITY_DOMAINS.DISTRIBUTION_HISTORY_TOMBSTONE,
      oldest.descriptor);
    if (await call(tx, 'writeDistributionHistoryTombstone', scope.customerId,
      scope.deploymentId, oldest.descriptor.sequence, oldest.descriptor.artifactDigest,
      tombstone) !== true
        || await call(tx, 'deleteDistributionHistory', scope.customerId, scope.deploymentId,
          oldest.descriptor.sequence, oldest.descriptor.artifactDigest, oldest.wrappedDigest,
          oldest.descriptor.idempotencyKey, oldest.descriptor.adoptionDigest) !== true) {
      throw fault('distribution_history_compaction_failed');
    }
  }
  await compactDistributionTombstones(tx, ctx, scope);
  await readDistributionHistory(tx, ctx, scope, currentSequence);
}

async function compactDistributionTombstones(tx, ctx, scope) {
  let rows = await distributionHistoryRows(tx, ctx, scope);
  while (rows.tombstones.length > MAX_DISTRIBUTION_HISTORY_TOMBSTONES) {
    const oldest = rows.tombstones[0];
    const checkpoint = await readDistributionHistoryCheckpoint(tx, ctx, scope);
    const advanced = advanceHistoryCheckpoint(
      checkpoint, oldest.descriptor.sequence, descriptorMap(rows), 2, 'distribution', scope,
    );
    if (await call(tx, 'compareAndSetDistributionHistoryCheckpoint', scope.customerId,
      scope.deploymentId, checkpoint.throughSequence,
      ctx.integrity.seal(INTEGRITY_DOMAINS.DISTRIBUTION_HISTORY_CHECKPOINT, advanced)) !== true
        || await call(tx, 'deleteDistributionHistoryTombstone', scope.customerId,
          scope.deploymentId, oldest.descriptor.sequence, oldest.descriptor.artifactDigest,
          oldest.wrappedDigest) !== true) {
      throw fault('distribution_history_compaction_failed');
    }
    rows = await distributionHistoryRows(tx, ctx, scope);
  }
}

async function readDistributionHistory(tx, ctx, scope, currentSequenceValue = null) {
  const current = currentSequenceValue === null
    ? await call(tx, 'readCurrentDistribution', scope.customerId, scope.deploymentId) : null;
  const currentSequence = currentSequenceValue === null
    ? (current ? readDistribution(current, ctx).distributionSequence : 0) : currentSequenceValue;
  const rows = await distributionHistoryRows(tx, ctx, scope);
  const checkpoint = await readDistributionHistoryCheckpoint(tx, ctx, scope);
  return verifyHistoryCoverage(
    checkpoint, rows, currentSequence, 2, 'distribution_history_invalid',
  );
}

async function distributionHistoryRows(tx, ctx, scope) {
  const activeRaw = await call(tx, 'listDistributions', scope.customerId, scope.deploymentId,
    MAX_DISTRIBUTIONS_PER_DEPLOYMENT + 1);
  const tombstoneRaw = await call(tx, 'listDistributionHistoryTombstones', scope.customerId,
    scope.deploymentId, MAX_DISTRIBUTION_HISTORY_TOMBSTONES + 1);
  if (!Array.isArray(activeRaw) || !Array.isArray(tombstoneRaw)
      || activeRaw.length > MAX_DISTRIBUTIONS_PER_DEPLOYMENT + 1
      || tombstoneRaw.length > MAX_DISTRIBUTION_HISTORY_TOMBSTONES + 1) {
    throw fault('storage_contract_invalid');
  }
  const active = [];
  for (const row of activeRaw) {
    if (!plainRecord(row) || !exactKeys(row, ['sequence', 'wrapped'])) {
      throw fault('distribution_history_invalid');
    }
    const distribution = readDistribution(row.wrapped, ctx);
    if (distribution.distributionSequence !== row.sequence
        || distribution.customerId !== scope.customerId
        || distribution.deploymentId !== scope.deploymentId) {
      throw fault('distribution_history_invalid');
    }
    const adoptionWrapped = await call(tx, 'readAdoption', scope.customerId,
      scope.deploymentId, row.sequence);
    const adoption = ctx.integrity.open(INTEGRITY_DOMAINS.ADOPTION, adoptionWrapped);
    validateAdoption(adoption);
    active.push({
      descriptor: distributionHistoryDescriptor(distribution, adoptionWrapped, adoption),
      wrappedDigest: operationDigest(row.wrapped),
    });
  }
  active.sort(historyRowOrder);
  const tombstones = tombstoneRaw.map((wrapped) => ({
    descriptor: validateDistributionHistoryDescriptor(
      ctx.integrity.open(INTEGRITY_DOMAINS.DISTRIBUTION_HISTORY_TOMBSTONE, wrapped), scope,
    ),
    wrappedDigest: operationDigest(wrapped),
  })).sort(historyRowOrder);
  return { active, tombstones };
}

function distributionHistoryDescriptor(distribution, adoptionWrapped, adoption) {
  return {
    schemaVersion: 1,
    customerId: distribution.customerId,
    deploymentId: distribution.deploymentId,
    sequence: distribution.distributionSequence,
    artifactDigest: distribution.artifactDigest,
    payloadDigest: distribution.payloadDigest,
    globalArtifactDigest: distribution.globalArtifactDigest,
    globalSigningKeyId: distribution.globalArtifact.keyId,
    distributionSigningKeyId: distribution.distributionArtifact.keyId,
    idempotencyKey: distribution.idempotencyKey,
    adoptionDigest: operationDigest(adoptionWrapped),
    adoptionRevision: adoption.revision,
    adoptionStage: adoption.stage,
  };
}

function validateDistributionHistoryDescriptor(value, scope) {
  if (!plainRecord(value) || !exactKeys(value, [
    'adoptionDigest', 'adoptionRevision', 'adoptionStage', 'artifactDigest', 'customerId',
    'deploymentId', 'distributionSigningKeyId', 'globalArtifactDigest',
    'globalSigningKeyId', 'idempotencyKey', 'payloadDigest', 'schemaVersion', 'sequence',
  ]) || value.schemaVersion !== 1 || value.customerId !== scope.customerId
      || value.deploymentId !== scope.deploymentId || !Number.isSafeInteger(value.sequence)
      || value.sequence < 1 || !SHA256_RE.test(value.artifactDigest)
      || !SHA256_RE.test(value.payloadDigest) || !SHA256_RE.test(value.globalArtifactDigest)
      || !SHA256_RE.test(value.adoptionDigest) || !UUID_RE.test(value.idempotencyKey)
      || !Number.isSafeInteger(value.adoptionRevision) || value.adoptionRevision < 1
      || !['published', 'delivered', 'applied', 'rejected'].includes(value.adoptionStage)
      || !String(value.globalSigningKeyId).startsWith('rw-catalog-global-')
      || !String(value.distributionSigningKeyId).startsWith('rw-catalog-distribution-')) {
    throw fault('distribution_history_invalid');
  }
  return value;
}

async function readDistributionHistoryCheckpoint(tx, ctx, scope) {
  const wrapped = await call(tx, 'readDistributionHistoryCheckpoint',
    scope.customerId, scope.deploymentId);
  return wrapped ? openHistoryCheckpoint(ctx, wrapped, 'distribution', scope,
    INTEGRITY_DOMAINS.DISTRIBUTION_HISTORY_CHECKPOINT)
    : emptyHistoryCheckpoint('distribution', scope);
}

function emptyHistoryCheckpoint(kind, scope) {
  return {
    schemaVersion: 1,
    kind,
    customerId: scope?.customerId || null,
    deploymentId: scope?.deploymentId || null,
    throughSequence: 0,
    count: 0,
    headDigest: ZERO_DIGEST,
    keyReferences: {},
  };
}

function openHistoryCheckpoint(ctx, wrapped, kind, scope, domain) {
  const value = ctx.integrity.open(domain, wrapped);
  if (!plainRecord(value) || !exactKeys(value, [
    'count', 'customerId', 'deploymentId', 'headDigest', 'keyReferences', 'kind',
    'schemaVersion', 'throughSequence',
  ]) || value.schemaVersion !== 1 || value.kind !== kind
      || value.customerId !== (scope?.customerId || null)
      || value.deploymentId !== (scope?.deploymentId || null)
      || !Number.isSafeInteger(value.throughSequence) || value.throughSequence < 1
      || value.count !== value.throughSequence || !SHA256_RE.test(value.headDigest)) {
    throw fault(`${kind}_history_invalid`);
  }
  value.keyReferences = checkedHistoryKeyReferences(value.keyReferences, value.count,
    kind === 'global' ? 1 : 2, `${kind}_history_invalid`);
  return value;
}

function advanceHistoryCheckpoint(checkpoint, throughSequence, descriptors, keysPerRecord,
  kind, scope) {
  if (throughSequence <= checkpoint.throughSequence) throw fault(`${kind}_history_invalid`);
  let headDigest = checkpoint.headDigest;
  const references = new Map(Object.entries(checkpoint.keyReferences));
  for (let sequence = checkpoint.throughSequence + 1;
    sequence <= throughSequence; sequence += 1) {
    const descriptor = descriptors.get(sequence);
    if (!descriptor) throw fault(`${kind}_history_invalid`);
    headDigest = historyChainDigest(headDigest, descriptor);
    addVendorHistoryReferences(references, descriptor);
  }
  const value = {
    schemaVersion: 1,
    kind,
    customerId: scope?.customerId || null,
    deploymentId: scope?.deploymentId || null,
    throughSequence,
    count: throughSequence,
    headDigest,
    keyReferences: sortedVendorReferenceObject(references),
  };
  checkedHistoryKeyReferences(value.keyReferences, value.count, keysPerRecord,
    `${kind}_history_invalid`);
  return value;
}

function verifyHistoryCoverage(checkpoint, rows, currentSequence, keysPerRecord, code) {
  if (!Number.isSafeInteger(currentSequence) || currentSequence < checkpoint.throughSequence) {
    throw fault(code);
  }
  if (rows.tombstones.some((row) => row.descriptor.sequence <= checkpoint.throughSequence)
      || rows.active.some((row) => row.descriptor.sequence <= checkpoint.throughSequence)) {
    throw fault(code);
  }
  const combined = [...rows.active, ...rows.tombstones].sort(historyRowOrder);
  let sequence = checkpoint.throughSequence;
  let headDigest = checkpoint.headDigest;
  const references = new Map(Object.entries(checkpoint.keyReferences));
  for (const row of combined) {
    if (row.descriptor.sequence !== sequence + 1) throw fault(code);
    sequence = row.descriptor.sequence;
    headDigest = historyChainDigest(headDigest, row.descriptor);
    addVendorHistoryReferences(references, row.descriptor);
  }
  if (sequence !== currentSequence) throw fault(code);
  const keyReferences = sortedVendorReferenceObject(references);
  checkedHistoryKeyReferences(keyReferences, currentSequence, keysPerRecord, code);
  return { count: currentSequence, headDigest, keyReferences };
}

async function vendorSigningKeyReferenceCounts(ctx) {
  return transact(ctx, async (tx) => {
    const global = await readGlobalHistory(tx, ctx);
    const references = new Map(Object.entries(global.keyReferences));
    const scopes = await call(tx, 'listDistributionHistoryScopes', MAX_GOVERNANCE_ROOTS + 1);
    if (!Array.isArray(scopes) || scopes.length > MAX_GOVERNANCE_ROOTS) {
      throw fault('storage_contract_invalid');
    }
    for (const scope of scopes) {
      validateScope(scope.customerId, scope.deploymentId);
      const history = await readDistributionHistory(tx, ctx, scope);
      for (const [keyId, count] of Object.entries(history.keyReferences)) {
        references.set(keyId, (references.get(keyId) || 0) + count);
      }
    }
    return sortedVendorReferenceObject(references);
  });
}

async function assertVendorHistory(tx, ctx) {
  await readGlobalHistory(tx, ctx);
  const scopes = await call(tx, 'listDistributionHistoryScopes', MAX_GOVERNANCE_ROOTS + 1);
  if (!Array.isArray(scopes) || scopes.length > MAX_GOVERNANCE_ROOTS) {
    throw fault('storage_contract_invalid');
  }
  for (const scope of scopes) {
    validateScope(scope.customerId, scope.deploymentId);
    await readDistributionHistory(tx, ctx, scope);
  }
}

function descriptorMap(rows) {
  const output = new Map();
  for (const row of [...rows.active, ...rows.tombstones]) {
    if (output.has(row.descriptor.sequence)) throw fault('history_state_invalid');
    output.set(row.descriptor.sequence, row.descriptor);
  }
  return output;
}

function historyRowOrder(left, right) {
  return left.descriptor.sequence - right.descriptor.sequence;
}

function historyChainDigest(previousDigest, descriptor) {
  return operationDigest({ previousDigest, descriptor });
}

function addVendorHistoryReferences(references, descriptor) {
  const ids = descriptor.signingKeyId
    ? [descriptor.signingKeyId]
    : [descriptor.globalSigningKeyId, descriptor.distributionSigningKeyId];
  for (const keyId of ids) references.set(keyId, (references.get(keyId) || 0) + 1);
}

function sortedVendorReferenceObject(references) {
  return Object.fromEntries([...references].filter(([, count]) => count > 0)
    .sort(([left], [right]) => left.localeCompare(right)));
}

function checkedHistoryKeyReferences(value, count, keysPerRecord, code) {
  if (!plainRecord(value)) throw fault(code);
  const entries = Object.entries(value);
  if (entries.some(([keyId, references]) => !SAFE_ID_RE.test(keyId)
      || !/^rw-catalog-(?:global|distribution)-/.test(keyId)
      || !Number.isSafeInteger(references) || references < 1)
      || entries.reduce((sum, [, references]) => sum + references, 0)
        !== count * keysPerRecord) throw fault(code);
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right)));
}

function validateStorageCount(value, maximum, code) {
  if (!Number.isSafeInteger(value) || value < 0) throw fault('storage_contract_invalid');
  if (value > maximum) throw fault(code);
}

function validateBoundedCount(value, maximum, code) {
  if (!Number.isSafeInteger(value) || value < 0) throw fault('storage_contract_invalid');
  if (value >= maximum) throw fault(code);
}

function withoutTime(value, key) {
  const copy = clone(value);
  delete copy[key];
  return copy;
}

async function call(target, method, ...args) {
  if (!target || typeof target[method] !== 'function') throw fault('storage_contract_invalid');
  return target[method](...args);
}

module.exports = {
  AUDIT_ACTIONS,
  GLOBAL_CATALOG_SIGNATURE_DOMAIN,
  INTEGRITY_DOMAINS,
  GLOBAL_ROLLBACK_WINDOW,
  DISTRIBUTION_ROLLBACK_WINDOW,
  MAX_GLOBAL_HISTORY_TOMBSTONES,
  MAX_DISTRIBUTION_HISTORY_TOMBSTONES,
  MAX_ARCHIVED_KEYS,
  MAX_ACTIVE_AUDIT_EVENTS,
  MAX_ACKNOWLEDGEMENTS,
  MAX_CLASSIFICATIONS,
  MAX_DELIVERY_ATTEMPTS,
  MAX_DISTRIBUTIONS_PER_DEPLOYMENT,
  MAX_FAILURES,
  MAX_GLOBAL_RELEASES,
  MAX_OBSERVATIONS_PER_SCOPE,
  MAX_PAGE_SIZE,
  MAX_STEP_UP_AGE_MS,
  OBSERVATION_RETENTION_MS,
  createVendorShadowAiIntelligence,
  createReferenceVendorShadowAiIntelligence: createVendorShadowAiIntelligence,
  createProductionVendorShadowAiIntelligence,
};
