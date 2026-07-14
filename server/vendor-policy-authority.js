'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const policyState = require('./connected-policy-state');
const policyProtocol = require('./vendor-policy-protocol');
const {
  AUTHORITY_DEFINITIONS,
  KEY_PURPOSES,
  parsePublicOnlyEd25519Key,
} = require('./vendor-signed-artifact');

const MAX_STEP_UP_AGE_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_POLICY_DELIVERY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_DELIVERY_ATTEMPTS = 8;
const MAX_ACKNOWLEDGEMENTS = 8;
const MAX_ACTIVE_AUDIT_EVENTS = 4096;
const MAX_ARCHIVED_KEYS = 18;
const POLICY_EXTERNAL_ASSURANCE = 'independent-exact-cas';
const POLICY_TEST_EXTERNAL_ASSURANCE = 'test-reference';
const POLICY_REFERENCE_PROFILE = 'test-reference';
const ZERO_DIGEST = '0'.repeat(64);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_ID_RE = /^[a-z0-9][a-z0-9_.:-]{0,127}$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PRIVATE_TX_RESULT = Symbol('vendor-policy-transaction-result');
const PRIVATE_COMMIT_RESULT = Symbol('vendor-policy-commit-result');
const FORBIDDEN_TREE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SENSITIVE_VALUE_PATTERNS = Object.freeze([
  /\b\d{3}-\d{2}-\d{4}\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /(?:prompt|sensitive|secret)[_-]?canary/i,
]);
const FORBIDDEN_METADATA_KEY_RE = /^(?:prompt|promptText|rawPrompt|rawContent|requestBody|responseBody)$/i;
const POLICY_KEY_ID_RE = /^rw-policy-[a-z0-9][a-z0-9_.-]{0,53}$/;
const POLICY_HISTORY_EPOCH_SIZE = 128;
const SUPPLEMENTAL_POLICY_AUTHORITY_TYPES = Object.freeze({
  policy_integrity: 'hmac_secret',
  policy_witness: 'hmac_secret',
  policy_approval: 'ed25519_public',
});
const AUTHORITY_IDENTITY_TYPES = new Set(Object.values(AUTHORITY_DEFINITIONS)
  .map((definition) => definition.identityType));

const INTEGRITY_DOMAINS = Object.freeze({
  GLOBAL_RELEASE: 'policy.global-release-record.v1',
  GLOBAL_HEAD: 'policy.global-head.v1',
  DISTRIBUTION: 'policy.distribution-record.v1',
  DEPLOYMENT_HEAD: 'policy.deployment-head.v1',
  EMERGENCY_HEAD: 'policy.emergency-deny-head.v1',
  ADOPTION: 'policy.adoption.v1',
  ACK_CLAIM: 'policy.ack-claim.v1',
  OPERATION: 'policy.operation-result.v1',
  AUDIT_EVENT: 'policy.audit-event.v1',
  AUDIT_HIGH_WATER: 'policy.audit-high-water.v1',
  AUDIT_ANCHOR: 'policy.audit-anchor.v1',
  PENDING: 'policy.pending-witness.v1',
});

const PURPOSE_ROLES = Object.freeze({
  policy_global_publish: new Set(['vendor_owner', 'vendor_security_admin']),
  policy_global_rollback: new Set(['vendor_owner', 'vendor_security_admin']),
  policy_deployment_rollback: new Set(['vendor_owner', 'vendor_security_admin']),
  policy_distribution_create: new Set(['vendor_owner', 'policy_publisher']),
  policy_distribution_deliver: new Set(['vendor_owner', 'policy_publisher']),
  policy_emergency_deny: new Set(['vendor_owner', 'vendor_security_admin']),
  policy_customer_ack: new Set(['customer_connector']),
  policy_distribution_status: new Set(['vendor_owner', 'policy_publisher', 'customer_security_admin']),
});

const GLOBAL_PURPOSES = new Set(['policy_global_publish', 'policy_global_rollback']);
const STEP_UP_PURPOSES = new Set([
  'policy_global_publish', 'policy_global_rollback', 'policy_distribution_create',
  'policy_distribution_deliver', 'policy_emergency_deny', 'policy_deployment_rollback',
]);
const CONFIRMATION_PURPOSES = new Set(STEP_UP_PURPOSES);
const AUTHORIZATION_KEYS = [
  'actorId', 'actorRole', 'authEventId', 'authenticatedAt', 'customerId', 'deploymentId',
  'expiresAt', 'purposes', 'schemaVersion', 'stepUpAt',
];
const CONFIRMATION_KEYS = [
  'authEventId', 'confirmationId', 'confirmedAt', 'expiresAt', 'operationDigest',
  'purpose', 'schemaVersion',
];
const DUAL_APPROVAL_KEYS = [
  'approvalId', 'approvedAt', 'approverAuthEventId', 'expiresAt', 'operationDigest',
  'purpose', 'schemaVersion',
];

function createVendorPolicyAuthority(options = {}) {
  if (referenceRuntimeProhibited(options)) {
    throw fault('policy_reference_constructor_unavailable');
  }
  if (!options.storage || typeof options.storage.transaction !== 'function') {
    throw fault('storage_contract_invalid');
  }
  if (!options.externalState || !['readPending', 'readAnchor', 'preparePending',
    'compareAndSetAnchor', 'clearPending'].every((method) => typeof options.externalState[method] === 'function')) {
    throw fault('policy_external_state_invalid');
  }
  if (options.allowTestExternalState !== true
      || options.externalState.assurance !== POLICY_TEST_EXTERNAL_ASSURANCE) {
    throw fault('policy_external_assurance_invalid');
  }
  const context = Object.freeze({
    storage: options.storage,
    external: options.externalState,
    clock: typeof options.clock === 'function' ? options.clock : Date.now,
    randomUUID: typeof options.randomUUID === 'function' ? options.randomUUID : crypto.randomUUID,
    integrity: createMacAuthority(options.policyIntegrityAuthority, 'integrity'),
    pending: createMacAuthority(options.policyWitnessAuthority, 'witness'),
    keyAuthority: createPolicyKeyAuthority(options.policySigningAuthority),
    ownerAuthority: createOwnerAuthorityProvider(options.authorityManifest),
    policyApprovalTrust: createTrustProvider(options.policyApprovalTrust, 'approval'),
    policyApprovalActiveKeyIds: createActiveKeyIdsProvider(options.policyApprovalActiveKeyIds),
    reservedExternalAuthorities: createReservedExternalAuthorityProvider(
      options.reservedExternalAuthorityFingerprints,
    ),
    runtimeProfile: POLICY_REFERENCE_PROFILE,
  });
  if (context.integrity.fingerprint === context.pending.fingerprint) {
    throw fault('policy_authority_identity_reused');
  }

  return Object.freeze({
    publishGlobalPolicy: (command) => publishGlobalPolicy(command, context),
    rollbackGlobalPolicy: (command) => rollbackGlobalPolicy(command, context),
    createDistribution: (command) => createDistribution(command, context),
    rollbackDeploymentPolicy: (command) => rollbackDeploymentPolicy(command, context),
    publishEmergencyDeny: (command) => publishEmergencyDeny(command, context),
    markDelivered: (command) => markDelivered(command, context),
    recordCustomerAcknowledgement: (command) => recordCustomerAcknowledgement(command, context),
    distributionStatus: (command) => distributionStatus(command, context),
    readiness: () => readiness(context),
    reconcileIntegrity: () => reconcileIntegrity(context),
  });
}

function referenceRuntimeProhibited(options) {
  const actualProduction = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
  if (actualProduction) return true;
  const requestedProduction = String(options?.env?.NODE_ENV || '')
    .trim().toLowerCase() === 'production';
  return requestedProduction || options?.production === true;
}

function createProductionVendorPolicyAuthority(options = {}) {
  const forbidden = [
    'allowTestExternalState', 'assurance', 'database', 'driver', 'env', 'environment',
    'externalState', 'managedPostgresAdapter', 'managedWitnessAdapter', 'nodeEnv', 'path',
    'runtimeProfile', 'storage',
  ];
  if (!plainRecord(options) || forbidden.some((key) => Object.hasOwn(options, key))) {
    throw fault('policy_production_options_invalid');
  }
  throw fault('policy_postgres_adapter_not_implemented');
}

function createTrustProvider(provider, purpose) {
  if (typeof provider !== 'function') throw fault(`policy_${purpose}_trust_invalid`);
  return Object.freeze({
    resolve() {
      const value = provider();
      if (!plainRecord(value)) throw fault(`policy_${purpose}_trust_invalid`);
      return value;
    },
  });
}

function createActiveKeyIdsProvider(provider) {
  if (typeof provider !== 'function') throw fault('policy_approval_active_keys_invalid');
  return Object.freeze({
    resolve() {
      let values;
      try { values = provider(); }
      catch { throw fault('policy_approval_active_keys_invalid'); }
      if (!Array.isArray(values) || values.length < 1 || values.length > 2
          || new Set(values).size !== values.length
          || !values.every((keyId) => typeof keyId === 'string')) {
        throw fault('policy_approval_active_keys_invalid');
      }
      return Object.freeze([...values]);
    },
  });
}

function createReservedExternalAuthorityProvider(provider) {
  if (provider !== undefined && typeof provider !== 'function') {
    throw fault('policy_reserved_authorities_invalid');
  }
  return Object.freeze({
    resolve() {
      if (provider === undefined) return Object.freeze([]);
      let values;
      try { values = provider(); }
      catch { throw fault('policy_reserved_authorities_invalid'); }
      return normalizeReservedExternalAuthorities(values);
    },
  });
}

function normalizeReservedExternalAuthorities(values) {
  if (!Array.isArray(values) || values.length > MAX_ARCHIVED_KEYS) {
    throw fault('policy_reserved_authorities_invalid');
  }
  const seen = { purposes: new Set(), keyIds: new Set(), fingerprints: new Set() };
  return Object.freeze(values.map((value) => {
    const record = normalizeReservedExternalAuthority(value);
    if (seen.purposes.has(record.purpose) || seen.keyIds.has(record.keyId)
        || seen.fingerprints.has(record.fingerprint)) {
      throw fault('policy_reserved_authorities_invalid');
    }
    seen.purposes.add(record.purpose);
    seen.keyIds.add(record.keyId);
    seen.fingerprints.add(record.fingerprint);
    return record;
  }));
}

function normalizeReservedExternalAuthority(value) {
  if (!plainRecord(value) || !exactKeys(value, [
    'fingerprint', 'identityType', 'keyId', 'purpose',
  ]) || !SAFE_ID_RE.test(String(value.purpose || ''))
      || Object.hasOwn(AUTHORITY_DEFINITIONS, value.purpose)
      || Object.hasOwn(SUPPLEMENTAL_POLICY_AUTHORITY_TYPES, value.purpose)
      || !AUTHORITY_IDENTITY_TYPES.has(value.identityType)
      || !SAFE_ID_RE.test(String(value.keyId || ''))
      || Buffer.byteLength(String(value.keyId || ''), 'utf8') > 96
      || !SHA256_RE.test(String(value.fingerprint || ''))) {
    throw fault('policy_reserved_authorities_invalid');
  }
  return Object.freeze({
    purpose: value.purpose,
    identityType: value.identityType,
    keyId: value.keyId,
    fingerprint: value.fingerprint,
  });
}

function createMacAuthority(value, purpose) {
  if (!plainRecord(value) || !exactKeys(value, ['keyId', 'secret'])
      || !SAFE_ID_RE.test(String(value.keyId || ''))
      || !value.keyId.includes('policy') || !value.keyId.includes(purpose)
      || !Buffer.isBuffer(value.secret) || value.secret.length !== 32) {
    throw fault(`policy_${purpose}_authority_invalid`);
  }
  const keyId = value.keyId;
  const secret = Buffer.from(value.secret);
  const fingerprint = digestBytes(secret);
  return Object.freeze({
    keyId,
    fingerprint,
    seal(domain, payload) {
      assertPlainTree(payload);
      assertNoSensitiveMetadata(payload);
      const snapshot = clone(payload);
      const mac = crypto.createHmac('sha256', secret)
        .update(integrityInput(domain, keyId, snapshot)).digest('hex');
      return deepFreeze({ integrityVersion: 1, keyId, domain, payload: snapshot, mac });
    },
    open(domain, wrapped) {
      if (!plainRecord(wrapped) || !exactKeys(wrapped, [
        'domain', 'integrityVersion', 'keyId', 'mac', 'payload',
      ]) || wrapped.integrityVersion !== 1 || wrapped.keyId !== keyId
          || wrapped.domain !== domain || !SHA256_RE.test(String(wrapped.mac || ''))) {
        throw fault('policy_integrity_state_invalid');
      }
      assertPlainTree(wrapped.payload);
      assertNoSensitiveMetadata(wrapped.payload);
      const expected = crypto.createHmac('sha256', secret)
        .update(integrityInput(domain, keyId, wrapped.payload)).digest();
      const supplied = Buffer.from(wrapped.mac, 'hex');
      if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
        throw fault('policy_integrity_state_invalid');
      }
      return clone(wrapped.payload);
    },
  });
}

function createPolicyKeyAuthority(provider) {
  if (typeof provider !== 'function') throw fault('policy_key_authority_invalid');
  return Object.freeze({
    resolve() {
      const raw = provider();
      if (!plainRecord(raw) || !exactKeys(raw, [
        'archivedPublicKeys', 'current', 'epoch', 'next',
      ])) throw fault('policy_key_authority_invalid');
      if (!Number.isSafeInteger(raw.epoch) || raw.epoch < 1) throw fault('policy_key_authority_invalid');
      const forbidden = new Set();
      const archived = normalizeArchivedKeys(raw.archivedPublicKeys, forbidden, raw.epoch);
      const current = normalizeSigningSlot(raw.current, 'current', archived, forbidden, raw.epoch);
      const next = raw.next === null ? null
        : normalizeSigningSlot(raw.next, 'next', archived, forbidden, raw.epoch);
      if (next && (next.keyId === current.keyId || next.fingerprint === current.fingerprint)) {
        throw fault('policy_key_identity_reused');
      }
      return Object.freeze({ current, next, archived, epoch: raw.epoch });
    },
  });
}

function createOwnerAuthorityProvider(value) {
  if (!value || typeof value.registry !== 'function') {
    throw fault('policy_owner_authority_manifest_invalid');
  }
  return Object.freeze({
    resolve() {
      let registry;
      try { registry = value.registry(); }
      catch { throw fault('policy_owner_authority_manifest_invalid'); }
      return normalizeOwnerAuthorityRegistry(registry);
    },
  });
}

function normalizeOwnerAuthorityRegistry(registry) {
  if (!registry || typeof registry.list !== 'function' || typeof registry.get !== 'function'
      || !Number.isSafeInteger(registry.generation) || registry.generation < 1) {
    throw fault('policy_owner_authority_manifest_invalid');
  }
  const identities = new Set();
  const keyIds = new Set();
  const records = new Map();
  const current = new Map();
  for (const [purpose, definition] of Object.entries(AUTHORITY_DEFINITIONS)) {
    let values;
    let currentValue;
    try {
      values = registry.list(purpose);
      currentValue = registry.get(purpose);
    } catch { throw fault('policy_owner_authority_manifest_invalid'); }
    if (!Array.isArray(values) || values.length < 1 || values.length > MAX_ARCHIVED_KEYS) {
      throw fault('policy_owner_authority_manifest_invalid');
    }
    const slots = values.map((record) => record?.slot);
    if (slots.filter((slot) => slot === 'current').length !== 1
        || slots.filter((slot) => slot === 'next').length > 1
        || slots.some((slot) => !['current', 'next', 'verifyOnly'].includes(slot))) {
      throw fault('policy_owner_authority_manifest_invalid');
    }
    const normalized = values.map((record) => normalizeOwnerAuthorityRecord(
      record, purpose, definition,
    ));
    for (const record of normalized) {
      if (identities.has(record.identity) || keyIds.has(record.keyId)) {
        throw fault('policy_owner_authority_identity_reused');
      }
      identities.add(record.identity);
      keyIds.add(record.keyId);
    }
    const selected = normalized.find((record) => record.slot === 'current');
    if (!currentValue || currentValue.keyId !== selected.keyId
        || currentValue.identity !== selected.identity) {
      throw fault('policy_owner_authority_manifest_invalid');
    }
    records.set(purpose, Object.freeze(normalized));
    current.set(purpose, selected);
  }
  if (records.size !== Object.keys(AUTHORITY_DEFINITIONS).length) {
    throw fault('policy_owner_authority_manifest_invalid');
  }
  return Object.freeze({
    generation: registry.generation,
    records,
    current,
    identities,
    keyIds,
    authorityRegistry: createNormalizedAuthorityRegistry(records),
  });
}

function normalizeOwnerAuthorityRecord(value, purpose, definition) {
  if (!plainRecord(value) || value.purpose !== purpose
      || value.identityType !== definition.identityType
      || !String(value.keyId || '').startsWith(definition.keyPrefix)
      || !SAFE_ID_RE.test(String(value.keyId || ''))
      || Buffer.byteLength(String(value.keyId || ''), 'utf8') > 96
      || !SHA256_RE.test(String(value.identity || ''))
      || !['current', 'next', 'verifyOnly'].includes(value.slot)) {
    throw fault('policy_owner_authority_manifest_invalid');
  }
  let publicKey = null;
  if (definition.identityType === 'ed25519_public') {
    publicKey = publicManifestEd25519(value.publicKeySpki);
    if (publicFingerprint(publicKey) !== value.identity) {
      throw fault('policy_owner_authority_manifest_invalid');
    }
  } else if (value.publicKeySpki !== undefined) {
    throw fault('policy_owner_authority_manifest_invalid');
  }
  return Object.freeze({
    purpose,
    identityType: definition.identityType,
    keyId: value.keyId,
    identity: value.identity,
    slot: value.slot,
    publicKey,
  });
}

function createNormalizedAuthorityRegistry(records) {
  const recordsFor = (purpose) => {
    const values = records.get(purpose);
    if (!values) throw fault('policy_owner_authority_manifest_invalid');
    return values;
  };
  const publicKeys = (purpose, includeHistorical, keyId = null) => {
    const selected = recordsFor(purpose).filter((record) => record.publicKey
      && (includeHistorical || ['current', 'next'].includes(record.slot))
      && (keyId === null || record.keyId === keyId));
    if (!selected.length || (keyId !== null && selected.length !== 1)) {
      throw fault('policy_owner_authority_manifest_invalid');
    }
    return new Map(selected.map((record) => [record.keyId, record.publicKey]));
  };
  const assertKey = (purpose, keyId, identity, includeHistorical) => {
    const match = recordsFor(purpose).find((record) => record.keyId === keyId
      && record.identity === identity && record.publicKey
      && (includeHistorical || ['current', 'next'].includes(record.slot)));
    if (!match) throw fault('policy_owner_authority_manifest_mismatch');
  };
  return Object.freeze({
    activePublicKeys: (purpose) => publicKeys(purpose, false),
    publicKeys: (purpose) => publicKeys(purpose, false),
    verificationPublicKey: (purpose, keyId) => publicKeys(purpose, true, keyId),
    assertPublicKey: (purpose, keyId, identity) => assertKey(purpose, keyId, identity, false),
    assertHistoricalPublicKey: (purpose, keyId, identity) => assertKey(
      purpose, keyId, identity, true,
    ),
  });
}

function normalizeArchivedKeys(value, forbidden, currentEpoch) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fault('policy_key_authority_invalid');
  }
  const entries = value instanceof Map ? [...value.entries()] : Object.entries(value);
  if (!entries.length || entries.length > MAX_ARCHIVED_KEYS) throw fault('policy_key_authority_invalid');
  const archived = new Map();
  const identities = new Set(forbidden);
  for (const [keyId, raw] of entries) {
    if (!POLICY_KEY_ID_RE.test(String(keyId || '')) || !plainRecord(raw)
        || !exactKeys(raw, ['publicKey', 'retireAfterEpoch', 'validFromEpoch'])
        || !Number.isSafeInteger(raw.validFromEpoch) || raw.validFromEpoch < 1
        || raw.validFromEpoch > currentEpoch + 1
        || (raw.retireAfterEpoch !== null && (!Number.isSafeInteger(raw.retireAfterEpoch)
          || raw.retireAfterEpoch < raw.validFromEpoch))) {
      throw fault('policy_key_purpose_mismatch');
    }
    const publicKey = publicEd25519(raw.publicKey);
    const fingerprint = publicFingerprint(publicKey);
    if (identities.has(fingerprint)) throw fault('policy_key_identity_reused');
    identities.add(fingerprint);
    archived.set(keyId, Object.freeze({
      publicKey,
      fingerprint,
      validFromEpoch: raw.validFromEpoch,
      retireAfterEpoch: raw.retireAfterEpoch,
    }));
  }
  return archived;
}

function normalizeSigningSlot(value, slot, archived, forbidden, currentEpoch) {
  if (!plainRecord(value) || !exactKeys(value, [
    'keyId', 'privateKey', 'retireAfterEpoch', 'validFromEpoch',
  ]) || !POLICY_KEY_ID_RE.test(String(value.keyId || ''))
      || !Number.isSafeInteger(value.validFromEpoch) || value.validFromEpoch < 1
      || value.validFromEpoch > currentEpoch + (slot === 'next' ? 1 : 0)
      || (value.retireAfterEpoch !== null && (!Number.isSafeInteger(value.retireAfterEpoch)
        || value.retireAfterEpoch < Math.max(currentEpoch, value.validFromEpoch)))) {
    throw fault('policy_key_authority_invalid');
  }
  const privateKey = privateEd25519(value.privateKey);
  const publicKey = crypto.createPublicKey(privateKey);
  const fingerprint = publicFingerprint(publicKey);
  const trusted = archived.get(value.keyId);
  if (!trusted || trusted.fingerprint !== fingerprint
      || trusted.validFromEpoch !== value.validFromEpoch
      || trusted.retireAfterEpoch !== value.retireAfterEpoch || forbidden.has(fingerprint)) {
    throw fault('policy_key_authority_invalid');
  }
  return Object.freeze({
    slot,
    keyId: value.keyId,
    privateKey,
    publicKey,
    fingerprint,
    validFromEpoch: value.validFromEpoch,
    retireAfterEpoch: value.retireAfterEpoch,
  });
}

async function transact(ctx, work) {
  let calls = 0;
  const token = Object.freeze({});
  const returned = await ctx.storage.transaction(async (tx) => {
    calls += 1;
    if (calls !== 1 || !tx || typeof tx !== 'object') throw fault('storage_contract_invalid');
    const value = await work(tx);
    return Object.freeze({ [PRIVATE_TX_RESULT]: token, value });
  });
  if (calls !== 1 || !returned || returned[PRIVATE_TX_RESULT] !== token) {
    throw fault('storage_contract_invalid');
  }
  const value = returned.value;
  if (value && value[PRIVATE_COMMIT_RESULT] === true) {
    await finalizeExternalCommit(value.finalization, ctx);
    return deepFreeze(clone(value.result));
  }
  return value;
}

function trustedNow(clock) {
  const ms = clock();
  if (!Number.isSafeInteger(ms) || ms < 0 || ms > 8_640_000_000_000_000 - MAX_POLICY_DELIVERY_TTL_MS) {
    throw fault('trusted_clock_invalid');
  }
  let iso;
  try { iso = new Date(ms).toISOString(); }
  catch { throw fault('trusted_clock_invalid'); }
  return Object.freeze({ ms, iso });
}

function exactCommand(value, keys, code) {
  if (!plainRecord(value) || !exactKeys(value, keys)) throw fault(code);
  assertPlainTree(value);
  assertNoSensitiveMetadata(value);
  return clone(value);
}

function operationDigest(value) {
  assertPlainTree(value);
  assertNoSensitiveMetadata(value);
  return digestCanonical(value);
}

async function authorize(tx, request, now) {
  const { authEventId, purpose, opDigest, scope = null } = request;
  if (!UUID_RE.test(String(authEventId || '')) || !PURPOSE_ROLES[purpose]) {
    throw fault('authorization_invalid');
  }
  const raw = await call(tx, 'resolveAuthorization', authEventId);
  const authorization = validateAuthorization(raw, purpose, scope, now);
  if (authorization.authEventId !== authEventId) throw fault('authorization_invalid');
  const claim = claimResult(await call(tx, 'claimAuthorization', authEventId, opDigest));
  if (claim === 'conflict') throw fault('authorization_reuse_conflict');
  if (!['claimed', 'replay'].includes(claim)) throw fault('storage_contract_invalid');
  return Object.freeze({
    authorization,
    claim,
    linkDigest: digestCanonical({
      authEventId,
      purpose,
      operationDigest: opDigest,
      authorizationDigest: digestCanonical(authorization),
      scopeDigest: digestCanonical(scope),
    }),
  });
}

function validateAuthorization(value, purpose, scope, now) {
  if (!plainRecord(value) || !exactKeys(value, AUTHORIZATION_KEYS)
      || value.schemaVersion !== 1 || !UUID_RE.test(String(value.authEventId || ''))
      || !SAFE_ID_RE.test(String(value.actorId || ''))
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
  if (GLOBAL_PURPOSES.has(purpose)) {
    if (value.customerId !== null || value.deploymentId !== null) {
      throw fault('authorization_scope_invalid');
    }
    return;
  }
  if (!scope) throw fault('authorization_scope_invalid');
  validateScope(scope.customerId, scope.deploymentId);
  const vendorRole = value.actorRole.startsWith('vendor_') || value.actorRole === 'policy_publisher';
  if (vendorRole && value.customerId === null && value.deploymentId === null) return;
  if (value.customerId !== scope.customerId || value.deploymentId !== scope.deploymentId) {
    throw fault('authorization_scope_invalid');
  }
}

async function confirmOperation(tx, request, authority, now) {
  if (!UUID_RE.test(String(request.confirmationId || ''))
      || !CONFIRMATION_PURPOSES.has(request.purpose)) throw fault('confirmation_invalid');
  const value = await call(tx, 'resolveConfirmation', request.confirmationId);
  if (!plainRecord(value) || !exactKeys(value, CONFIRMATION_KEYS)
      || value.schemaVersion !== 1 || value.confirmationId !== request.confirmationId
      || value.authEventId !== authority.authorization.authEventId
      || value.purpose !== request.purpose || value.operationDigest !== request.opDigest) {
    throw fault('confirmation_invalid');
  }
  const confirmedAt = parseIso(value.confirmedAt, 'confirmation_invalid');
  const expiresAt = parseIso(value.expiresAt, 'confirmation_invalid');
  if (confirmedAt > now.ms + MAX_CLOCK_SKEW_MS || now.ms - confirmedAt > MAX_STEP_UP_AGE_MS
      || expiresAt <= now.ms || expiresAt <= confirmedAt
      || expiresAt - confirmedAt > MAX_STEP_UP_AGE_MS) throw fault('confirmation_invalid');
  const claim = claimResult(await call(tx, 'claimConfirmation', request.confirmationId, request.opDigest));
  if (claim === 'conflict') throw fault('confirmation_reuse_conflict');
  if (!['claimed', 'replay'].includes(claim)) throw fault('storage_contract_invalid');
  return Object.freeze({
    claim,
    linkDigest: digestCanonical({
      confirmationId: request.confirmationId,
      operationDigest: request.opDigest,
      parentAuthorizationLinkDigest: authority.linkDigest,
      confirmationDigest: digestCanonical(value),
    }),
  });
}

async function approveDualControl(tx, request, authority, scope, now) {
  if (!UUID_RE.test(String(request.approvalId || ''))) throw fault('dual_control_invalid');
  const approval = await call(tx, 'resolveDualApproval', request.approvalId);
  if (!plainRecord(approval) || !exactKeys(approval, DUAL_APPROVAL_KEYS)
      || approval.schemaVersion !== 1 || approval.approvalId !== request.approvalId
      || approval.purpose !== request.purpose || approval.operationDigest !== request.opDigest) {
    throw fault('dual_control_invalid');
  }
  const approvedAt = parseIso(approval.approvedAt, 'dual_control_invalid');
  const expiresAt = parseIso(approval.expiresAt, 'dual_control_invalid');
  if (approvedAt > now.ms + MAX_CLOCK_SKEW_MS || now.ms - approvedAt > MAX_STEP_UP_AGE_MS
      || expiresAt <= now.ms || expiresAt <= approvedAt
      || expiresAt - approvedAt > MAX_STEP_UP_AGE_MS) throw fault('dual_control_invalid');
  const approverRaw = await call(tx, 'resolveAuthorization', approval.approverAuthEventId);
  const approver = validateAuthorization(approverRaw, request.purpose, scope, now);
  if (approver.authEventId !== approval.approverAuthEventId
      || approver.actorId === authority.authorization.actorId) throw fault('dual_control_invalid');
  const claim = claimResult(await call(tx, 'claimDualApproval', request.approvalId, request.opDigest));
  if (claim === 'conflict') throw fault('dual_control_reuse_conflict');
  if (!['claimed', 'replay'].includes(claim)) throw fault('storage_contract_invalid');
  return Object.freeze({
    claim,
    linkDigest: digestCanonical({
      approvalId: request.approvalId,
      operationDigest: request.opDigest,
      approverAuthorizationDigest: digestCanonical(approver),
      parentAuthorizationLinkDigest: authority.linkDigest,
    }),
  });
}

async function approveSignedOwner(tx, artifact, request, authority, now, ctx) {
  let verified;
  try {
    const keys = resolvePolicyKeys(ctx);
    verified = policyProtocol.verifyOwnerApproval(
      artifact,
      approvalTrustFor(keys.approval, keys.approval.activeKeyIds),
    );
  }
  catch { throw fault('owner_approval_invalid'); }
  const approval = verified.payload;
  if (approval.purpose !== request.purpose || approval.operationDigest !== request.operationDigest
      || approval.approverActorId === authority.authorization.actorId) {
    throw fault('owner_approval_invalid');
  }
  const approvedAt = Date.parse(approval.approvedAt);
  const expiresAt = Date.parse(approval.expiresAt);
  if (approvedAt > now.ms + MAX_CLOCK_SKEW_MS || now.ms - approvedAt > MAX_STEP_UP_AGE_MS
      || expiresAt <= now.ms || expiresAt <= approvedAt
      || expiresAt - approvedAt > MAX_STEP_UP_AGE_MS) throw fault('owner_approval_invalid');
  const claim = claimResult(await call(tx, 'claimDualApproval', approval.approvalId,
    request.operationDigest));
  if (claim === 'conflict') throw fault('owner_approval_reuse_conflict');
  if (!['claimed', 'replay'].includes(claim)) throw fault('storage_contract_invalid');
  return Object.freeze({
    artifact: clone(artifact),
    artifactDigest: verified.artifactDigest,
    linkDigest: digestCanonical({
      approvalArtifactDigest: verified.artifactDigest,
      operationDigest: request.operationDigest,
      parentAuthorizationLinkDigest: authority.linkDigest,
    }),
  });
}

function approvalOperationDigest(command) {
  const core = { ...command };
  delete core.ownerApprovalAttestation;
  return operationDigest(core);
}

async function publishGlobalPolicy(rawCommand, ctx) {
  const command = exactCommand(rawCommand, [
    'authEventId', 'confirmationId', 'expectedGlobalVersion', 'globalPolicy',
    'ownerApprovalAttestation',
  ], 'global_publish_command_invalid');
  if (!Number.isSafeInteger(command.expectedGlobalVersion) || command.expectedGlobalVersion < 0) {
    throw fault('global_publish_command_invalid');
  }
  const globalPolicy = policyState.normalizeVendorPolicy(command.globalPolicy);
  const normalizedCommand = { ...command, globalPolicy };
  const opDigest = operationDigest(normalizedCommand);
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    await assertNoPending(ctx);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'policy_global_publish', opDigest, scope: null,
    }, now);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose: 'policy_global_publish', opDigest,
    }, authority, now);
    const ownerApproval = await approveSignedOwner(tx, command.ownerApprovalAttestation, {
      purpose: 'policy_global_publish', operationDigest: approvalOperationDigest(normalizedCommand),
    }, authority, now, ctx);
    const replay = await readOperation(tx, opDigest, ctx);
    if (replay) return replay;
    return publishGlobalRelease(tx, {
      expectedGlobalVersion: command.expectedGlobalVersion,
      rollbackOfGlobalVersion: null,
      globalPolicy,
      operationDigest: opDigest,
      action: 'policy_global_published',
      authorizationDigest: authority.linkDigest,
      confirmationDigest: digestCanonical({
        confirmationDigest: confirmation.linkDigest,
        ownerApprovalDigest: ownerApproval.linkDigest,
      }),
      approvalAttestation: ownerApproval.artifact,
      approvalAttestationDigest: ownerApproval.artifactDigest,
      ownerApprovalDigest: ownerApproval.linkDigest,
    }, now, ctx);
  });
}

async function rollbackGlobalPolicy(rawCommand, ctx) {
  const command = exactCommand(rawCommand, [
    'authEventId', 'confirmationId', 'expectedGlobalVersion', 'ownerApprovalAttestation',
    'rollbackOfGlobalVersion',
  ], 'global_rollback_command_invalid');
  if (!Number.isSafeInteger(command.expectedGlobalVersion) || command.expectedGlobalVersion < 1
      || !Number.isSafeInteger(command.rollbackOfGlobalVersion)
      || command.rollbackOfGlobalVersion < 1
      || command.rollbackOfGlobalVersion >= command.expectedGlobalVersion) {
    throw fault('global_rollback_command_invalid');
  }
  const opDigest = operationDigest(command);
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    await assertNoPending(ctx);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'policy_global_rollback', opDigest, scope: null,
    }, now);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose: 'policy_global_rollback', opDigest,
    }, authority, now);
    const ownerApproval = await approveSignedOwner(tx, command.ownerApprovalAttestation, {
      purpose: 'policy_global_rollback', operationDigest: approvalOperationDigest(command),
    }, authority, now, ctx);
    const replay = await readOperation(tx, opDigest, ctx);
    if (replay) return replay;
    const target = await readGlobalRelease(tx, command.rollbackOfGlobalVersion, ctx);
    if (!target) throw fault('global_rollback_target_unknown');
    return publishGlobalRelease(tx, {
      expectedGlobalVersion: command.expectedGlobalVersion,
      rollbackOfGlobalVersion: command.rollbackOfGlobalVersion,
      globalPolicy: target.globalPolicy,
      operationDigest: opDigest,
      action: 'policy_global_rolled_back',
      authorizationDigest: authority.linkDigest,
      confirmationDigest: digestCanonical({
        confirmationDigest: confirmation.linkDigest,
        ownerApprovalDigest: ownerApproval.linkDigest,
      }),
      approvalAttestation: ownerApproval.artifact,
      approvalAttestationDigest: ownerApproval.artifactDigest,
      ownerApprovalDigest: ownerApproval.linkDigest,
    }, now, ctx);
  });
}

async function publishGlobalRelease(tx, input, now, ctx) {
  const head = await readGlobalHead(tx, ctx);
  if (head.globalVersion !== input.expectedGlobalVersion) throw fault('global_version_conflict');
  const globalVersion = head.globalVersion + 1;
  const keyset = resolvePolicyKeys(ctx);
  const globalReleaseId = ctx.randomUUID();
  if (!UUID_RE.test(String(globalReleaseId || ''))) throw fault('random_id_invalid');
  const globalPolicy = policyState.normalizeVendorPolicy(input.globalPolicy);
  const bundleDigest = policyState.digestPolicyDocument(globalPolicy);
  const payload = {
    schemaVersion: policyProtocol.POLICY_CONTROL_SCHEMA_VERSION,
    kind: policyProtocol.GLOBAL_POLICY_KIND,
    globalReleaseId,
    globalVersion,
    previousGlobalVersion: head.globalVersion,
    rollbackOfGlobalVersion: input.rollbackOfGlobalVersion,
    historyEpoch: Math.floor((globalVersion - 1) / POLICY_HISTORY_EPOCH_SIZE) + 1,
    keyEpoch: keyset.epoch,
    approvalAttestationDigest: input.approvalAttestationDigest,
    bundleDigest,
    mandatoryControlsDigest: policyState.MANDATORY_CONTROLS_DIGEST,
    issuedAt: now.iso,
  };
  const globalArtifact = policyProtocol.signGlobalPolicyRelease(payload, {
    keyId: keyset.current.keyId, privateKey: keyset.current.privateKey, keyEpoch: keyset.epoch,
  });
  const globalArtifactDigest = policyProtocol.policyGlobalArtifactDigest(globalArtifact);
  const releaseCore = {
    schemaVersion: 1,
    recordType: 'global_release',
    revision: globalVersion,
    globalVersion,
    previousGlobalVersion: head.globalVersion,
    rollbackOfGlobalVersion: input.rollbackOfGlobalVersion,
    globalReleaseId,
    globalArtifact,
    globalArtifactDigest,
    approvalAttestation: input.approvalAttestation,
    approvalAttestationDigest: input.approvalAttestationDigest,
    ownerApprovalDigest: input.ownerApprovalDigest,
    globalPolicy,
    bundleDigest,
    mandatoryControlsDigest: policyState.MANDATORY_CONTROLS_DIGEST,
    signingKeyId: keyset.current.keyId,
    signingKeyEpoch: keyset.epoch,
    historyEpoch: payload.historyEpoch,
    issuedAt: now.iso,
    authorizationDigest: input.authorizationDigest,
        confirmationDigest: input.confirmationDigest,
  };
  const releaseRecordDigest = operationDigest(releaseCore);
  const release = { ...releaseCore, recordDigest: releaseRecordDigest };
  const auditBody = auditBodyFor({
    action: input.action,
    operationDigest: input.operationDigest,
    scope: null,
    referenceDigest: globalArtifactDigest,
    authorizationDigest: input.authorizationDigest,
    confirmationDigest: input.confirmationDigest,
    recordedAt: now.iso,
  });
  return commitMutation(tx, {
    namespace: 'global',
    operationDigest: input.operationDigest,
    auditBody,
    prepare: async (audit) => {
      const nextHeadCore = {
        schemaVersion: 1,
        recordType: 'global_head',
        revision: globalVersion,
        globalVersion,
        globalReleaseId,
        globalArtifactDigest,
        releaseRecordDigest,
        auditSequence: audit.sequence + 1,
        auditIntentDigest: operationDigest(auditBody),
        updatedAt: now.iso,
      };
      const nextHead = { ...nextHeadCore, recordDigest: operationDigest(nextHeadCore) };
      const result = deepFreeze({
        globalVersion,
        previousGlobalVersion: head.globalVersion,
        rollbackOfGlobalVersion: input.rollbackOfGlobalVersion,
        globalReleaseId,
        globalArtifact,
        globalArtifactDigest,
        bundleDigest,
        mandatoryControlsDigest: policyState.MANDATORY_CONTROLS_DIGEST,
        signingKeyId: keyset.current.keyId,
        signingKeyEpoch: keyset.epoch,
        historyEpoch: payload.historyEpoch,
        approvalAttestationDigest: input.approvalAttestationDigest,
      });
      return {
        headRef: headReference('global_head', 'global', nextHead),
        apply: async () => {
          await insertExactRecord(tx, 'global_release', String(globalVersion), release,
            INTEGRITY_DOMAINS.GLOBAL_RELEASE, ctx);
          await compareAndSetRecord(tx, 'global_head', 'global', head.revision, nextHead,
            INTEGRITY_DOMAINS.GLOBAL_HEAD, ctx, 'global_version_conflict');
        },
        result,
      };
    },
  }, now, ctx);
}

async function createDistribution(rawCommand, ctx) {
  const command = exactCommand(rawCommand, [
    'authEventId', 'confirmationId', 'customerId', 'deploymentId', 'desiredOverlay',
    'expectedDistributionSequence', 'expiresAt', 'globalVersion', 'ownerApprovalAttestation',
    'rollbackOfDistributionSequence', 'rollout', 'supersession',
  ], 'distribution_command_invalid');
  validateScope(command.customerId, command.deploymentId);
  if (!Number.isSafeInteger(command.expectedDistributionSequence)
      || command.expectedDistributionSequence < 0
      || !Number.isSafeInteger(command.globalVersion) || command.globalVersion < 1
      || (command.rollbackOfDistributionSequence !== null
        && (!Number.isSafeInteger(command.rollbackOfDistributionSequence)
          || command.rollbackOfDistributionSequence < 1
          || command.rollbackOfDistributionSequence >= command.expectedDistributionSequence + 1))
      || (command.rollbackOfDistributionSequence === null) !== (command.ownerApprovalAttestation === null)
      || !['preview', 'staged', 'required'].includes(command.rollout)
      || !canonicalIso(command.expiresAt)) throw fault('distribution_command_invalid');
  const desiredOverlay = policyState.normalizePolicyOverlay(command.desiredOverlay);
  const normalizedCommand = { ...command, desiredOverlay };
  const opDigest = operationDigest(normalizedCommand);
  const purpose = command.rollbackOfDistributionSequence === null
    ? 'policy_distribution_create' : 'policy_deployment_rollback';
  const scope = { customerId: command.customerId, deploymentId: command.deploymentId };
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    const expiresAt = Date.parse(command.expiresAt);
    if (expiresAt <= now.ms || expiresAt - now.ms > MAX_POLICY_DELIVERY_TTL_MS) {
      throw fault('distribution_expiry_invalid');
    }
    await assertNoPending(ctx);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose, opDigest, scope,
    }, now);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose, opDigest,
    }, authority, now);
    const ownerApproval = command.ownerApprovalAttestation === null ? null
      : await approveSignedOwner(tx, command.ownerApprovalAttestation, {
        purpose, operationDigest: approvalOperationDigest(normalizedCommand),
      }, authority, now, ctx);
    const replay = await readOperation(tx, opDigest, ctx);
    if (replay) return replay;
    const globalHead = await readGlobalHead(tx, ctx);
    if (command.rollbackOfDistributionSequence === null
        && globalHead.globalVersion !== command.globalVersion) throw fault('global_release_not_current');
    const release = await readGlobalRelease(tx, command.globalVersion, ctx);
    if (!release || (command.rollbackOfDistributionSequence === null
      && release.globalArtifactDigest !== globalHead.globalArtifactDigest)) {
      throw fault('global_release_invalid');
    }
    const deploymentId = scopeRecordId(scope);
    const head = await readDeploymentHead(tx, deploymentId, scope, ctx);
    if (head.distributionSequence !== command.expectedDistributionSequence) {
      throw fault('distribution_sequence_conflict');
    }
    const emergency = await readEmergencyHead(tx, deploymentId, scope, ctx);
    let selectedDesiredOverlay = desiredOverlay;
    let emergencyOverlay = policyState.normalizePolicyOverlay(emergency.rules);
    let rollbackTarget = null;
    if (command.rollbackOfDistributionSequence !== null) {
      rollbackTarget = await readDistribution(tx,
        distributionRecordId(deploymentId, command.rollbackOfDistributionSequence), scope,
        command.rollbackOfDistributionSequence, ctx);
      if (!rollbackTarget) throw fault('deployment_rollback_target_unknown');
      const targetControl = policyProtocol.createPolicyControlEnvelope(
        rollbackTarget.vendorBundle.vendorControl,
      );
      selectedDesiredOverlay = policyState.normalizePolicyOverlay(targetControl.desiredOverlay);
      emergencyOverlay = policyState.normalizePolicyOverlay(targetControl.emergencyDenyOverlay);
      if (rollbackTarget.globalVersion !== release.globalVersion
          || rollbackTarget.globalArtifactDigest !== release.globalArtifactDigest) {
        throw fault('deployment_rollback_target_invalid');
      }
    }
    const combinedOverlay = policyState.mergePolicyOverlays(selectedDesiredOverlay, emergencyOverlay);
    const vendorPolicy = policyState.buildEffectivePolicy(release.globalPolicy, combinedOverlay).effectivePolicy;
    const distributionSequence = head.distributionSequence + 1;
    const messageId = ctx.randomUUID();
    if (!UUID_RE.test(String(messageId || ''))) throw fault('random_id_invalid');
    const globalPolicy = policyState.normalizeVendorPolicy(release.globalPolicy);
    const effectivePolicyDigest = policyState.digestPolicyDocument(vendorPolicy);
    const keyset = resolvePolicyKeys(ctx);
    const deliveryBinding = {
      schemaVersion: policyProtocol.POLICY_CONTROL_SCHEMA_VERSION,
      customerId: scope.customerId,
      deploymentId: scope.deploymentId,
      messageId,
      distributionSequence,
      previousDistributionSequence: head.distributionSequence,
      rollbackOfDistributionSequence: command.rollbackOfDistributionSequence,
      historyEpoch: Math.floor((distributionSequence - 1) / POLICY_HISTORY_EPOCH_SIZE) + 1,
      policyKeyEpoch: keyset.epoch,
      globalKeyEpoch: release.globalArtifact.payload.keyEpoch,
      globalReleaseId: release.globalReleaseId,
      globalVersion: release.globalVersion,
      globalArtifactDigest: release.globalArtifactDigest,
      globalBundleDigest: release.bundleDigest,
      desiredOverlayDigest: policyState.digestPolicyDocument(selectedDesiredOverlay),
      emergencyDenyDigest: policyState.digestPolicyDocument(emergencyOverlay),
      effectivePolicyDigest,
      mandatoryControlsDigest: policyState.MANDATORY_CONTROLS_DIGEST,
      rollout: command.rollout,
      supersession: command.supersession,
      issuedAt: now.iso,
      expiresAt: command.expiresAt,
    };
    const control = policyProtocol.createPolicyControlEnvelope({
      schemaVersion: policyProtocol.POLICY_CONTROL_SCHEMA_VERSION,
      globalArtifact: release.globalArtifact,
      globalPolicy,
      desiredOverlay: selectedDesiredOverlay,
      emergencyDenyOverlay: emergencyOverlay,
      deliveryBinding,
      deliveryDigest: policyProtocol.policyDeliveryDigest(deliveryBinding),
    });
    const vendorBundle = deepFreeze({ ...clone(vendorPolicy), vendorControl: control });
    const bundleDigest = policyState.digestPolicyDocument(vendorBundle);
    const payload = {
      schemaVersion: protocol.PROTOCOL_VERSION,
      messageId,
      customerId: scope.customerId,
      deploymentId: scope.deploymentId,
      kind: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
      policyVersion: distributionSequence,
      previousVersion: head.distributionSequence,
      rollbackOfVersion: command.rollbackOfDistributionSequence,
      bundleDigest,
      mandatoryControlsDigest: policyState.MANDATORY_CONTROLS_DIGEST,
      issuedAt: now.iso,
      expiresAt: command.expiresAt,
      rollout: command.rollout,
    };
    const artifact = signDesiredState(payload, keyset.current);
    const targetDigest = protocol.payloadDigest(payload, protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE);
    const distributionCore = {
      schemaVersion: 1,
      recordType: 'distribution',
      revision: distributionSequence,
      customerId: scope.customerId,
      deploymentId: scope.deploymentId,
      distributionSequence,
      previousDistributionSequence: head.distributionSequence,
      rollbackOfDistributionSequence: command.rollbackOfDistributionSequence,
      historyEpoch: deliveryBinding.historyEpoch,
      policyKeyEpoch: keyset.epoch,
      globalKeyEpoch: deliveryBinding.globalKeyEpoch,
      supersession: command.supersession,
      globalVersion: release.globalVersion,
      globalReleaseId: release.globalReleaseId,
      globalArtifactDigest: release.globalArtifactDigest,
      desiredOverlayDigest: deliveryBinding.desiredOverlayDigest,
      emergencyDenyDigest: deliveryBinding.emergencyDenyDigest,
      effectivePolicyDigest,
      deliveryDigest: control.deliveryDigest,
      bundleDigest,
      targetDigest,
      rollout: command.rollout,
      artifact,
      vendorBundle,
      signingKeyId: keyset.current.keyId,
      ownerApprovalDigest: ownerApproval?.linkDigest || null,
      issuedAt: now.iso,
      expiresAt: command.expiresAt,
      authorizationDigest: authority.linkDigest,
      confirmationDigest: ownerApproval ? digestCanonical({
        confirmationDigest: confirmation.linkDigest,
        ownerApprovalDigest: ownerApproval.linkDigest,
      }) : confirmation.linkDigest,
    };
    const distribution = { ...distributionCore, recordDigest: operationDigest(distributionCore) };
    const recordId = distributionRecordId(deploymentId, distributionSequence);
    const adoptionCore = {
      schemaVersion: 1,
      recordType: 'adoption',
      revision: 1,
      customerId: scope.customerId,
      deploymentId: scope.deploymentId,
      distributionSequence,
      targetDigest,
      deliveryDigest: control.deliveryDigest,
      stage: 'published',
      deliveryAttempts: 0,
      acknowledgementCount: 0,
      lastReasonCode: null,
      lastAcknowledgementDigest: null,
      auditSequence: null,
      auditIntentDigest: null,
      updatedAt: now.iso,
    };
    const adoption = { ...adoptionCore, recordDigest: operationDigest(adoptionCore) };
    const auditBody = auditBodyFor({
      action: command.rollbackOfDistributionSequence === null
        ? 'policy_distribution_created' : 'policy_deployment_rolled_back',
      operationDigest: opDigest,
      scope,
      referenceDigest: targetDigest,
      authorizationDigest: authority.linkDigest,
      confirmationDigest: distribution.confirmationDigest,
      recordedAt: now.iso,
    });
    return commitMutation(tx, {
      namespace: `deployment:${deploymentId}`,
      operationDigest: opDigest,
      auditBody,
      prepare: async (audit) => {
        adoption.auditSequence = audit.sequence + 1;
        adoption.auditIntentDigest = operationDigest(auditBody);
        adoption.recordDigest = operationDigest(withoutRecordDigest(adoption));
        const nextHeadCore = {
          schemaVersion: 1,
          recordType: 'deployment_head',
          revision: distributionSequence,
          customerId: scope.customerId,
          deploymentId: scope.deploymentId,
          distributionSequence,
          distributionRecordDigest: distribution.recordDigest,
          targetDigest,
          deliveryDigest: control.deliveryDigest,
          auditSequence: audit.sequence + 1,
          auditIntentDigest: operationDigest(auditBody),
          updatedAt: now.iso,
        };
        const nextHead = { ...nextHeadCore, recordDigest: operationDigest(nextHeadCore) };
        const result = deepFreeze({
          customerId: scope.customerId,
          deploymentId: scope.deploymentId,
          distributionSequence,
          globalVersion: release.globalVersion,
          globalReleaseId: release.globalReleaseId,
          rollbackOfDistributionSequence: command.rollbackOfDistributionSequence,
          targetDigest,
          deliveryDigest: control.deliveryDigest,
          bundleDigest,
          rollout: command.rollout,
          signingKeyEpoch: keyset.epoch,
          artifact,
          vendorBundle,
          stage: 'published',
        });
        return {
          headRef: headReference('deployment_head', deploymentId, nextHead),
          apply: async () => {
            await insertExactRecord(tx, 'distribution', recordId, distribution,
              INTEGRITY_DOMAINS.DISTRIBUTION, ctx);
            await insertExactRecord(tx, 'adoption', recordId, adoption,
              INTEGRITY_DOMAINS.ADOPTION, ctx);
            await compareAndSetRecord(tx, 'deployment_head', deploymentId, head.revision,
              nextHead, INTEGRITY_DOMAINS.DEPLOYMENT_HEAD, ctx, 'distribution_sequence_conflict');
          },
          result,
        };
      },
    }, now, ctx);
  });
}

async function rollbackDeploymentPolicy(command, ctx) {
  if (!command || command.rollbackOfDistributionSequence === null
      || command.rollbackOfDistributionSequence === undefined) {
    throw fault('deployment_rollback_command_invalid');
  }
  return createDistribution(command, ctx);
}

async function publishEmergencyDeny(rawCommand, ctx) {
  const command = exactCommand(rawCommand, [
    'approvalId', 'authEventId', 'confirmationId', 'customerId', 'deploymentId',
    'expectedRevision', 'rules',
  ], 'emergency_deny_command_invalid');
  validateScope(command.customerId, command.deploymentId);
  if (!Number.isSafeInteger(command.expectedRevision) || command.expectedRevision < 0) {
    throw fault('emergency_deny_command_invalid');
  }
  const rules = normalizeEmergencyRules(command.rules);
  const normalizedCommand = { ...command, rules };
  const opDigest = operationDigest(normalizedCommand);
  const scope = { customerId: command.customerId, deploymentId: command.deploymentId };
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    await assertNoPending(ctx);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'policy_emergency_deny', opDigest, scope,
    }, now);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose: 'policy_emergency_deny', opDigest,
    }, authority, now);
    const dualControl = await approveDualControl(tx, {
      approvalId: command.approvalId, purpose: 'policy_emergency_deny', opDigest,
    }, authority, scope, now);
    const replay = await readOperation(tx, opDigest, ctx);
    if (replay) return replay;
    const deploymentId = scopeRecordId(scope);
    const current = await readEmergencyHead(tx, deploymentId, scope, ctx);
    if (current.revision !== command.expectedRevision) throw fault('emergency_revision_conflict');
    assertEmergencyAdditive(current.rules, rules);
    const revision = current.revision + 1;
    const rulesDigest = policyState.digestPolicyDocument(rules);
    const auditBody = auditBodyFor({
      action: 'policy_emergency_deny_published',
      operationDigest: opDigest,
      scope,
      referenceDigest: rulesDigest,
      authorizationDigest: authority.linkDigest,
      confirmationDigest: digestCanonical({
        confirmationDigest: confirmation.linkDigest,
        dualControlDigest: dualControl.linkDigest,
      }),
      recordedAt: now.iso,
    });
    return commitMutation(tx, {
      namespace: `emergency:${deploymentId}`,
      operationDigest: opDigest,
      auditBody,
      prepare: async (audit) => {
        const nextCore = {
          schemaVersion: 1,
          recordType: 'emergency_head',
          revision,
          customerId: scope.customerId,
          deploymentId: scope.deploymentId,
          rules,
          rulesDigest,
          authorizationDigest: authority.linkDigest,
          confirmationDigest: confirmation.linkDigest,
          dualControlDigest: dualControl.linkDigest,
          auditSequence: audit.sequence + 1,
          auditIntentDigest: operationDigest(auditBody),
          updatedAt: now.iso,
        };
        const next = { ...nextCore, recordDigest: operationDigest(nextCore) };
        return {
          headRef: headReference('emergency_head', deploymentId, next),
          apply: () => compareAndSetRecord(tx, 'emergency_head', deploymentId, current.revision,
            next, INTEGRITY_DOMAINS.EMERGENCY_HEAD, ctx, 'emergency_revision_conflict'),
          result: deepFreeze({
            customerId: scope.customerId,
            deploymentId: scope.deploymentId,
            revision,
            rulesDigest,
            rules,
          }),
        };
      },
    }, now, ctx);
  });
}

async function markDelivered(rawCommand, ctx) {
  const command = exactCommand(rawCommand, [
    'authEventId', 'confirmationId', 'customerId', 'deploymentId',
    'distributionSequence', 'expectedRevision', 'targetDigest',
  ], 'delivery_command_invalid');
  validateScope(command.customerId, command.deploymentId);
  if (!Number.isSafeInteger(command.distributionSequence) || command.distributionSequence < 1
      || !Number.isSafeInteger(command.expectedRevision) || command.expectedRevision < 1
      || !SHA256_RE.test(String(command.targetDigest || ''))) throw fault('delivery_command_invalid');
  const opDigest = operationDigest(command);
  const scope = { customerId: command.customerId, deploymentId: command.deploymentId };
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    await assertNoPending(ctx);
    const authority = await authorize(tx, {
      authEventId: command.authEventId, purpose: 'policy_distribution_deliver', opDigest, scope,
    }, now);
    const confirmation = await confirmOperation(tx, {
      confirmationId: command.confirmationId, purpose: 'policy_distribution_deliver', opDigest,
    }, authority, now);
    const replay = await readOperation(tx, opDigest, ctx);
    if (replay) return replay;
    const deploymentId = scopeRecordId(scope);
    const recordId = distributionRecordId(deploymentId, command.distributionSequence);
    const distribution = await readDistribution(tx, recordId, scope, command.distributionSequence, ctx);
    if (!distribution || distribution.targetDigest !== command.targetDigest) {
      throw fault('delivery_target_mismatch');
    }
    const adoption = await readAdoption(tx, recordId, scope, command.distributionSequence, ctx);
    if (!adoption || adoption.revision !== command.expectedRevision) throw fault('adoption_revision_conflict');
    if (!['published', 'rejected'].includes(adoption.stage)) throw fault('adoption_stage_conflict');
    if (adoption.deliveryAttempts >= MAX_DELIVERY_ATTEMPTS) throw fault('delivery_attempts_exhausted');
    const nextCore = {
      ...withoutRecordDigest(adoption),
      revision: adoption.revision + 1,
      stage: 'delivered',
      deliveryAttempts: adoption.deliveryAttempts + 1,
      updatedAt: now.iso,
    };
    const next = { ...nextCore, recordDigest: operationDigest(nextCore) };
    const auditBody = auditBodyFor({
      action: 'policy_distribution_delivered',
      operationDigest: opDigest,
      scope,
      referenceDigest: command.targetDigest,
      authorizationDigest: authority.linkDigest,
      confirmationDigest: confirmation.linkDigest,
      recordedAt: now.iso,
    });
    return commitMutation(tx, {
      namespace: `adoption:${recordId}`,
      operationDigest: opDigest,
      auditBody,
      prepare: async (audit) => {
        next.auditSequence = audit.sequence + 1;
        next.auditIntentDigest = operationDigest(auditBody);
        const finalizedCore = withoutRecordDigest(next);
        next.recordDigest = operationDigest(finalizedCore);
        return {
          headRef: headReference('adoption', recordId, next),
          apply: () => compareAndSetRecord(tx, 'adoption', recordId, adoption.revision,
            next, INTEGRITY_DOMAINS.ADOPTION, ctx, 'adoption_revision_conflict'),
          result: deepFreeze(adoptionResult(next)),
        };
      },
    }, now, ctx);
  });
}

async function recordCustomerAcknowledgement(rawCommand, ctx) {
  const command = exactCommand(rawCommand, [
    'acknowledgement', 'channelAuthEventId',
  ], 'acknowledgement_command_invalid');
  let acknowledgement;
  try {
    acknowledgement = protocol.assertChannel(
      command.acknowledgement,
      protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    );
  } catch { throw fault('acknowledgement_invalid'); }
  if (acknowledgement.targetKind !== protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE
      || acknowledgement.lifecycleStage !== 'applied') throw fault('acknowledgement_invalid');
  const scope = {
    customerId: acknowledgement.customerId,
    deploymentId: acknowledgement.deploymentId,
  };
  validateScope(scope.customerId, scope.deploymentId);
  const ackDigest = operationDigest(acknowledgement);
  const opDigest = operationDigest({ channelAuthEventId: command.channelAuthEventId, acknowledgement });
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    const acknowledgementTime = Date.parse(acknowledgement.recordedAt);
    if (acknowledgementTime > now.ms + MAX_CLOCK_SKEW_MS
        || now.ms - acknowledgementTime > MAX_POLICY_DELIVERY_TTL_MS) {
      throw fault('acknowledgement_time_invalid');
    }
    await assertNoPending(ctx);
    const authority = await authorize(tx, {
      authEventId: command.channelAuthEventId, purpose: 'policy_customer_ack', opDigest, scope,
    }, now);
    const deploymentId = scopeRecordId(scope);
    const recordId = distributionRecordId(deploymentId, acknowledgement.targetVersion);
    const distribution = await readDistribution(tx, recordId, scope, acknowledgement.targetVersion, ctx);
    if (!distribution || distribution.targetDigest !== acknowledgement.targetDigest) {
      throw fault('acknowledgement_target_mismatch');
    }
    if (acknowledgementTime + MAX_CLOCK_SKEW_MS < Date.parse(distribution.issuedAt)) {
      throw fault('acknowledgement_time_invalid');
    }
    const claimId = ackMessageClaimId(scope, acknowledgement.messageId);
    const existingClaim = await readRecord(tx, 'ack_claim', claimId, INTEGRITY_DOMAINS.ACK_CLAIM, ctx);
    if (existingClaim) {
      validateAckClaim(existingClaim, scope, acknowledgement.targetVersion,
        acknowledgement.targetDigest, acknowledgement.messageId);
      if (existingClaim.acknowledgementDigest !== ackDigest) throw fault('acknowledgement_conflict');
      return deepFreeze(clone(existingClaim.result));
    }
    const adoption = await readAdoption(tx, recordId, scope, acknowledgement.targetVersion, ctx);
    if (!adoption) throw fault('adoption_state_missing');
    if (adoption.acknowledgementCount >= MAX_ACKNOWLEDGEMENTS) {
      throw fault('acknowledgement_capacity_exhausted');
    }
    if (acknowledgement.outcome === 'success' && adoption.stage !== 'delivered') {
      throw fault('acknowledgement_before_delivery');
    }
    if (acknowledgement.outcome === 'rejected'
        && !['published', 'delivered', 'rejected'].includes(adoption.stage)) {
      throw fault('adoption_stage_conflict');
    }
    const stage = acknowledgement.outcome === 'success' ? 'applied' : 'rejected';
    const nextCore = {
      ...withoutRecordDigest(adoption),
      revision: adoption.revision + 1,
      stage,
      acknowledgementCount: adoption.acknowledgementCount + 1,
      lastReasonCode: acknowledgement.reasonCode,
      lastAcknowledgementDigest: ackDigest,
      updatedAt: now.iso,
    };
    const result = deepFreeze({
      customerId: scope.customerId,
      deploymentId: scope.deploymentId,
      distributionSequence: acknowledgement.targetVersion,
      messageId: acknowledgement.messageId,
      targetDigest: acknowledgement.targetDigest,
      deliveryDigest: distribution.deliveryDigest,
      stage,
      outcome: acknowledgement.outcome,
      reasonCode: acknowledgement.reasonCode,
      acknowledgementDigest: ackDigest,
      revision: nextCore.revision,
    });
    const claimCore = {
      schemaVersion: 1,
      recordType: 'ack_claim',
      revision: 1,
      customerId: scope.customerId,
      deploymentId: scope.deploymentId,
      distributionSequence: acknowledgement.targetVersion,
      messageId: acknowledgement.messageId,
      targetDigest: acknowledgement.targetDigest,
      acknowledgementDigest: ackDigest,
      result,
      authorizationDigest: authority.linkDigest,
      recordedAt: now.iso,
    };
    const claim = { ...claimCore, recordDigest: operationDigest(claimCore) };
    const auditBody = auditBodyFor({
      action: acknowledgement.outcome === 'success'
        ? 'policy_distribution_applied' : 'policy_distribution_rejected',
      operationDigest: opDigest,
      scope,
      referenceDigest: acknowledgement.targetDigest,
      authorizationDigest: authority.linkDigest,
      confirmationDigest: null,
      recordedAt: now.iso,
    });
    return commitMutation(tx, {
      namespace: `adoption:${recordId}`,
      operationDigest: opDigest,
      auditBody,
      prepare: async (audit) => {
        nextCore.auditSequence = audit.sequence + 1;
        nextCore.auditIntentDigest = operationDigest(auditBody);
        const next = { ...nextCore, recordDigest: operationDigest(nextCore) };
        return {
          headRef: headReference('adoption', recordId, next),
          apply: async () => {
            await insertExactRecord(tx, 'ack_claim', claimId, claim,
              INTEGRITY_DOMAINS.ACK_CLAIM, ctx);
            await compareAndSetRecord(tx, 'adoption', recordId, adoption.revision,
              next, INTEGRITY_DOMAINS.ADOPTION, ctx, 'adoption_revision_conflict');
          },
          result,
        };
      },
    }, now, ctx);
  });
}

async function distributionStatus(rawCommand, ctx) {
  const command = exactCommand(rawCommand, [
    'authEventId', 'customerId', 'deploymentId', 'distributionSequence',
  ], 'distribution_status_command_invalid');
  validateScope(command.customerId, command.deploymentId);
  if (!Number.isSafeInteger(command.distributionSequence) || command.distributionSequence < 1) {
    throw fault('distribution_status_command_invalid');
  }
  const scope = { customerId: command.customerId, deploymentId: command.deploymentId };
  const opDigest = operationDigest(command);
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    await assertNoPending(ctx);
    await readAuditState(tx, now, ctx);
    await authorize(tx, {
      authEventId: command.authEventId, purpose: 'policy_distribution_status', opDigest, scope,
    }, now);
    const recordId = distributionRecordId(scopeRecordId(scope), command.distributionSequence);
    const distribution = await readDistribution(tx, recordId, scope, command.distributionSequence, ctx);
    const adoption = await readAdoption(tx, recordId, scope, command.distributionSequence, ctx);
    if (!distribution || !adoption) return null;
    return deepFreeze({
      customerId: scope.customerId,
      deploymentId: scope.deploymentId,
      distributionSequence: command.distributionSequence,
      globalVersion: distribution.globalVersion,
      globalReleaseId: distribution.globalReleaseId,
      targetDigest: distribution.targetDigest,
      deliveryDigest: distribution.deliveryDigest,
      rollout: distribution.rollout,
      ...adoptionResult(adoption),
    });
  });
}

async function commitMutation(tx, input, now, ctx) {
  await assertNoPending(ctx);
  const audit = await readAuditState(tx, now, ctx);
  const prepared = await input.prepare(audit);
  if (!prepared || typeof prepared.apply !== 'function' || !plainRecord(prepared.headRef)) {
    throw fault('storage_contract_invalid');
  }
  const auditIntentDigest = operationDigest(input.auditBody);
  const result = deepFreeze(clone(prepared.result));
  const targetAnchor = {
    schemaVersion: 1,
    sequence: audit.sequence + 1,
    count: audit.count + 1,
    headDigest: operationDigest({
      schemaVersion: 1,
      sequence: audit.sequence + 1,
      previousDigest: audit.headDigest,
      action: input.auditBody.action,
      outcome: input.auditBody.outcome,
      operationDigest: input.auditBody.operationDigest,
      scopeDigest: input.auditBody.scopeDigest,
      referenceDigest: input.auditBody.referenceDigest,
      authorizationDigest: input.auditBody.authorizationDigest,
      confirmationDigest: input.auditBody.confirmationDigest,
      recordedAt: input.auditBody.recordedAt,
    }),
  };
  const witness = {
    schemaVersion: 2,
    namespace: input.namespace,
    operationDigest: input.operationDigest,
    auditBody: input.auditBody,
    auditIntentDigest,
    auditBodyDigest: operationDigest(input.auditBody),
    expectedAuditSequence: audit.sequence,
    targetAuditSequence: audit.sequence + 1,
    headType: prepared.headRef.type,
    headId: prepared.headRef.id,
    headRevision: prepared.headRef.revision,
    previousHeadRevision: prepared.headRef.revision - 1,
    headRecordDigest: prepared.headRef.recordDigest,
    result,
    resultDigest: operationDigest(result),
    targetAnchor,
    preparedAt: now.iso,
  };
  const wrappedWitness = ctx.pending.seal(INTEGRITY_DOMAINS.PENDING, witness);
  const witnessDigest = operationDigest(wrappedWitness);
  if (await call(ctx.external, 'preparePending', wrappedWitness) !== witnessDigest) {
    throw fault('policy_pending_conflict');
  }
  await prepared.apply();
  const appended = await appendAudit(tx, input.auditBody, audit, now, ctx);
  if (appended.sequence !== witness.targetAuditSequence
      || appended.auditIntentDigest !== auditIntentDigest) throw fault('policy_audit_conflict');
  await insertOperation(tx, input.operationDigest, prepared.result, ctx);
  return Object.freeze({
    [PRIVATE_COMMIT_RESULT]: true,
    result,
    finalization: Object.freeze({
      expectedAuditSequence: audit.sequence,
      targetAnchor,
      witnessDigest,
    }),
  });
}

async function finalizeExternalCommit(value, ctx) {
  try {
    const wrappedAnchor = ctx.integrity.seal(INTEGRITY_DOMAINS.AUDIT_ANCHOR, value.targetAnchor);
    await ensureExternalAnchor(value.expectedAuditSequence, wrappedAnchor, ctx);
    await ensurePendingCleared(value.witnessDigest, ctx);
  } catch (error) {
    if (error?.code === 'policy_commit_uncertain') throw error;
    throw fault('policy_commit_uncertain');
  }
}

async function ensureExternalAnchor(expectedSequence, wrappedAnchor, ctx) {
  let advanced = null;
  try { advanced = await call(ctx.external, 'compareAndSetAnchor', expectedSequence, wrappedAnchor); }
  catch {}
  if (advanced !== null && advanced !== true && advanced !== false) {
    throw fault('policy_commit_uncertain');
  }
  const raw = await call(ctx.external, 'readAnchor');
  const anchor = raw ? ctx.integrity.open(INTEGRITY_DOMAINS.AUDIT_ANCHOR, raw) : null;
  if (!anchor || operationDigest(anchor) !== operationDigest(wrappedAnchor.payload)) {
    throw fault('policy_commit_uncertain');
  }
}

async function ensurePendingCleared(expectedDigest, ctx) {
  const before = await call(ctx.external, 'readPending');
  if (before === null) return;
  ctx.pending.open(INTEGRITY_DOMAINS.PENDING, before);
  if (operationDigest(before) !== expectedDigest) throw fault('policy_commit_uncertain');
  let cleared = null;
  try { cleared = await call(ctx.external, 'clearPending', expectedDigest); }
  catch {}
  if (cleared === true) return;
  if ((cleared !== null && cleared !== false)
      || await call(ctx.external, 'readPending') !== null) {
    throw fault('policy_commit_uncertain');
  }
}

async function readAuditState(tx, now, ctx, pendingWitness = null) {
  const rawHighWater = await call(tx, 'readPolicyAuditHighWater');
  const rawAnchor = await call(ctx.external, 'readAnchor');
  if (!rawHighWater && !rawAnchor) {
    return Object.freeze({
      sequence: 0,
      count: 0,
      headDigest: ZERO_DIGEST,
      checkpointSequence: 0,
    });
  }
  if (!rawHighWater || (!rawAnchor
      && !(pendingWitness && pendingWitness.expectedAuditSequence === 0))) {
    throw fault('policy_audit_high_water_invalid');
  }
  const highWater = ctx.integrity.open(INTEGRITY_DOMAINS.AUDIT_HIGH_WATER, rawHighWater);
  const anchor = rawAnchor
    ? ctx.integrity.open(INTEGRITY_DOMAINS.AUDIT_ANCHOR, rawAnchor)
    : { schemaVersion: 1, sequence: 0, count: 0, headDigest: ZERO_DIGEST };
  validateAuditHighWater(highWater, now);
  if (anchor.sequence > 0) validateAuditAnchor(anchor);
  const anchorMatches = anchor.sequence === highWater.sequence && anchor.count === highWater.count
    && anchor.headDigest === highWater.headDigest;
  const pendingCommitMatches = pendingWitness
    && anchor.sequence === pendingWitness.expectedAuditSequence
    && highWater.sequence === pendingWitness.targetAuditSequence
    && highWater.count === pendingWitness.targetAnchor.count
    && highWater.headDigest === pendingWitness.targetAnchor.headDigest;
  if (!anchorMatches && !pendingCommitMatches) throw fault('policy_audit_anchor_invalid');
  let previousDigest = ZERO_DIGEST;
  for (let sequence = 1; sequence <= highWater.sequence; sequence += 1) {
    const rawEvent = await call(tx, 'readPolicyAuditEvent', sequence);
    if (!rawEvent) throw fault('policy_audit_chain_invalid');
    const event = ctx.integrity.open(INTEGRITY_DOMAINS.AUDIT_EVENT, rawEvent);
    validateAuditEvent(event, sequence, previousDigest);
    previousDigest = event.eventDigest;
  }
  if (previousDigest !== highWater.headDigest || highWater.count !== highWater.sequence) {
    throw fault('policy_audit_chain_invalid');
  }
  return Object.freeze({ ...highWater, checkpointSequence: 0 });
}

async function appendAudit(tx, body, current, now, ctx) {
  if (operationDigest(body) !== operationDigest(auditBodyFor(body))) {
    throw fault('policy_audit_event_invalid');
  }
  const sequence = current.sequence + 1;
  const eventCore = {
    schemaVersion: 1,
    sequence,
    previousDigest: current.headDigest,
    action: body.action,
    outcome: body.outcome,
    operationDigest: body.operationDigest,
    scopeDigest: body.scopeDigest,
    referenceDigest: body.referenceDigest,
    authorizationDigest: body.authorizationDigest,
    confirmationDigest: body.confirmationDigest,
    recordedAt: body.recordedAt,
  };
  const eventDigest = operationDigest(eventCore);
  const event = { ...eventCore, eventDigest };
  const wrappedEvent = ctx.integrity.seal(INTEGRITY_DOMAINS.AUDIT_EVENT, event);
  if (await call(tx, 'appendPolicyAuditEvent', sequence, eventDigest, wrappedEvent) !== true) {
    throw fault('policy_audit_append_failed');
  }
  const highWater = {
    schemaVersion: 1,
    sequence,
    count: current.count + 1,
    headDigest: eventDigest,
    recordedAt: now.iso,
  };
  const wrappedHighWater = ctx.integrity.seal(INTEGRITY_DOMAINS.AUDIT_HIGH_WATER, highWater);
  if (await call(tx, 'compareAndSetPolicyAuditHighWater', current.sequence, wrappedHighWater) !== true) {
    throw fault('policy_audit_high_water_conflict');
  }
  return Object.freeze({
    ...highWater,
    auditIntentDigest: operationDigest(body),
  });
}

function auditBodyFor(value) {
  const body = {
    action: value.action,
    outcome: value.outcome || 'success',
    operationDigest: value.operationDigest,
    scopeDigest: value.scopeDigest || digestCanonical(value.scope),
    referenceDigest: value.referenceDigest,
    authorizationDigest: value.authorizationDigest,
    confirmationDigest: value.confirmationDigest === undefined ? null : value.confirmationDigest,
    recordedAt: value.recordedAt,
  };
  if (!SAFE_ID_RE.test(String(body.action || '')) || !['success', 'rejected'].includes(body.outcome)
      || ![body.operationDigest, body.scopeDigest, body.referenceDigest, body.authorizationDigest]
        .every((item) => SHA256_RE.test(String(item || '')))
      || (body.confirmationDigest !== null && !SHA256_RE.test(String(body.confirmationDigest || '')))
      || !canonicalIso(body.recordedAt)) throw fault('policy_audit_event_invalid');
  return deepFreeze(body);
}

function validateAuditHighWater(value, now) {
  if (!plainRecord(value) || !exactKeys(value, [
    'count', 'headDigest', 'recordedAt', 'schemaVersion', 'sequence',
  ]) || value.schemaVersion !== 1 || !Number.isSafeInteger(value.sequence) || value.sequence < 1
      || value.count !== value.sequence
      || !SHA256_RE.test(String(value.headDigest || '')) || !canonicalIso(value.recordedAt)
      || Date.parse(value.recordedAt) > now.ms + MAX_CLOCK_SKEW_MS) {
    throw fault('policy_audit_high_water_invalid');
  }
}

function validateAuditAnchor(value) {
  if (!plainRecord(value) || !exactKeys(value, [
    'count', 'headDigest', 'schemaVersion', 'sequence',
  ]) || value.schemaVersion !== 1 || !Number.isSafeInteger(value.sequence) || value.sequence < 1
      || value.count !== value.sequence || !SHA256_RE.test(String(value.headDigest || ''))) {
    throw fault('policy_audit_anchor_invalid');
  }
}

function validateAuditEvent(value, sequence, previousDigest) {
  if (!plainRecord(value) || !exactKeys(value, [
    'action', 'authorizationDigest', 'confirmationDigest', 'eventDigest', 'operationDigest',
    'outcome', 'previousDigest', 'recordedAt', 'referenceDigest', 'schemaVersion',
    'scopeDigest', 'sequence',
  ]) || value.schemaVersion !== 1 || value.sequence !== sequence
      || value.previousDigest !== previousDigest || !SAFE_ID_RE.test(String(value.action || ''))
      || !['success', 'rejected'].includes(value.outcome) || !canonicalIso(value.recordedAt)) {
    throw fault('policy_audit_event_invalid');
  }
  const digestFields = [
    value.authorizationDigest, value.eventDigest, value.operationDigest,
    value.previousDigest, value.referenceDigest, value.scopeDigest,
  ];
  if (!digestFields.every((item) => SHA256_RE.test(String(item || '')))
      || (value.confirmationDigest !== null
        && !SHA256_RE.test(String(value.confirmationDigest || '')))) {
    throw fault('policy_audit_event_invalid');
  }
  const core = { ...value };
  delete core.eventDigest;
  if (operationDigest(core) !== value.eventDigest) throw fault('policy_audit_event_invalid');
}

async function assertNoPending(ctx) {
  const pending = await call(ctx.external, 'readPending');
  if (pending) throw fault('control_plane_readiness_frozen');
}

async function readiness(ctx) {
  return transact(ctx, async (tx) => {
    const now = trustedNow(ctx.clock);
    const keys = resolvePolicyKeys(ctx);
    await assertNoPending(ctx);
    const audit = await readAuditState(tx, now, ctx);
    return deepFreeze({
      ready: true,
      auditSequence: audit.sequence,
      currentSigningKeyId: keys.current.keyId,
      nextSigningKeyId: keys.next?.keyId || null,
      integrityKeyId: ctx.integrity.keyId,
      policyWitnessKeyId: ctx.pending.keyId,
      externalStateAssurance: ctx.external.assurance,
      productionReady: false,
      runtimeProfile: ctx.runtimeProfile,
      signingEpoch: keys.epoch,
      historyEpoch: Math.floor(Math.max(0, audit.sequence - 1) / MAX_ACTIVE_AUDIT_EVENTS) + 1,
    });
  });
}

async function reconcileIntegrity(ctx) {
  const now = trustedNow(ctx.clock);
  const raw = await call(ctx.external, 'readPending');
  if (!raw) return transact(ctx, async (tx) => {
    const audit = await readAuditState(tx, now, ctx);
    return { reconciled: 0, auditSequence: audit.sequence };
  });
  const witness = ctx.pending.open(INTEGRITY_DOMAINS.PENDING, raw);
  validatePendingWitness(witness, now);
  const witnessDigest = operationDigest(raw);
  const outcome = await transact(ctx, async (tx) => {
    const audit = await readAuditState(tx, now, ctx, witness);
    const head = await readAnyHead(tx, witness.headType, witness.headId, ctx);
    const headMatches = !!head && head.revision === witness.headRevision
      && head.recordDigest === witness.headRecordDigest;
    if (audit.sequence === witness.targetAuditSequence) {
      const rawEvent = await call(tx, 'readPolicyAuditEvent', witness.targetAuditSequence);
      if (!headMatches || !rawEvent) throw fault('policy_pending_invalid');
      const event = ctx.integrity.open(INTEGRITY_DOMAINS.AUDIT_EVENT, rawEvent);
      const eventBody = auditBodyFor(event);
      if (event.operationDigest !== witness.operationDigest
          || operationDigest(eventBody) !== witness.auditBodyDigest
          || protocol.canonicalJson(eventBody) !== protocol.canonicalJson(witness.auditBody)) {
        throw fault('policy_pending_invalid');
      }
      const operation = await readOperation(tx, witness.operationDigest, ctx);
      if (operation && operationDigest(operation) !== witness.resultDigest) {
        throw fault('policy_pending_invalid');
      }
      if (!operation) await insertOperation(tx, witness.operationDigest, witness.result, ctx);
      return { status: 'committed', auditSequence: audit.sequence };
    }
    if (audit.sequence !== witness.expectedAuditSequence
        || (head && head.revision !== witness.previousHeadRevision)) {
      throw fault('policy_pending_invalid');
    }
    const operation = await readOperation(tx, witness.operationDigest, ctx);
    const rawEvent = await call(tx, 'readPolicyAuditEvent', witness.targetAuditSequence);
    if (operation || rawEvent || headMatches) throw fault('policy_pending_invalid');
    return { status: 'rolled_back', auditSequence: audit.sequence };
  });
  if (outcome.status === 'committed') {
    await finalizeExternalCommit({
      expectedAuditSequence: witness.expectedAuditSequence,
      targetAnchor: witness.targetAnchor,
      witnessDigest,
    }, ctx);
  } else if (await call(ctx.external, 'clearPending', witnessDigest) !== true) {
    throw fault('policy_pending_clear_failed');
  }
  return { reconciled: 1, auditSequence: outcome.auditSequence, outcome: outcome.status };
}

function validatePendingWitness(value, now) {
  if (!plainRecord(value) || !exactKeys(value, [
    'auditBody', 'auditBodyDigest', 'auditIntentDigest', 'expectedAuditSequence', 'headId',
    'headRecordDigest', 'headRevision', 'headType', 'namespace', 'operationDigest',
    'preparedAt', 'previousHeadRevision', 'result', 'resultDigest', 'schemaVersion',
    'targetAnchor', 'targetAuditSequence',
  ]) || value.schemaVersion !== 2 || !SAFE_ID_RE.test(String(value.namespace || ''))
      || !SAFE_ID_RE.test(String(value.headType || '')) || !SAFE_ID_RE.test(String(value.headId || ''))
      || !Number.isSafeInteger(value.headRevision) || value.headRevision < 1
      || !Number.isSafeInteger(value.previousHeadRevision) || value.previousHeadRevision < 0
      || value.previousHeadRevision !== value.headRevision - 1
      || !Number.isSafeInteger(value.expectedAuditSequence) || value.expectedAuditSequence < 0
      || value.targetAuditSequence !== value.expectedAuditSequence + 1
      || ![value.operationDigest, value.auditIntentDigest, value.auditBodyDigest,
        value.headRecordDigest, value.resultDigest]
        .every((item) => SHA256_RE.test(String(item || '')))
      || !canonicalIso(value.preparedAt)
      || Date.parse(value.preparedAt) > now.ms + MAX_CLOCK_SKEW_MS
      || operationDigest(auditBodyFor(value.auditBody)) !== value.auditIntentDigest
      || operationDigest(value.auditBody) !== value.auditBodyDigest
      || operationDigest(value.result) !== value.resultDigest) {
    throw fault('policy_pending_invalid');
  }
  validateAuditAnchor(value.targetAnchor);
  if (value.targetAnchor.sequence !== value.targetAuditSequence
      || value.targetAnchor.count !== value.targetAuditSequence) throw fault('policy_pending_invalid');
}

async function readGlobalHead(tx, ctx) {
  const value = await readRecord(tx, 'global_head', 'global', INTEGRITY_DOMAINS.GLOBAL_HEAD, ctx);
  if (!value) return Object.freeze({ revision: 0, globalVersion: 0 });
  const keys = [
    'auditIntentDigest', 'auditSequence', 'globalArtifactDigest', 'globalReleaseId',
    'globalVersion', 'recordDigest', 'recordType', 'releaseRecordDigest', 'revision',
    'schemaVersion', 'updatedAt',
  ];
  if (!exactRecord(value, keys, 'global_head') || value.globalVersion !== value.revision
      || !UUID_RE.test(String(value.globalReleaseId || '')) || !canonicalIso(value.updatedAt)
      || !Number.isSafeInteger(value.auditSequence) || value.auditSequence < 1) {
    throw fault('global_head_invalid');
  }
  assertDigestFields(value, [
    'auditIntentDigest', 'globalArtifactDigest', 'recordDigest', 'releaseRecordDigest',
  ], 'global_head_invalid');
  assertRecordDigest(value, 'global_head_invalid');
  return value;
}

async function readGlobalRelease(tx, version, ctx) {
  const value = await readRecord(tx, 'global_release', String(version),
    INTEGRITY_DOMAINS.GLOBAL_RELEASE, ctx);
  if (!value) return null;
  const keys = [
    'approvalAttestation', 'approvalAttestationDigest', 'authorizationDigest', 'bundleDigest',
    'confirmationDigest', 'globalArtifact', 'globalArtifactDigest', 'globalPolicy',
    'globalReleaseId', 'globalVersion', 'historyEpoch', 'issuedAt', 'mandatoryControlsDigest',
    'ownerApprovalDigest', 'previousGlobalVersion', 'recordDigest', 'recordType', 'revision',
    'rollbackOfGlobalVersion', 'schemaVersion', 'signingKeyEpoch', 'signingKeyId',
  ];
  if (!exactRecord(value, keys, 'global_release') || value.globalVersion !== version
      || value.revision !== version || value.previousGlobalVersion !== version - 1
      || !UUID_RE.test(String(value.globalReleaseId || '')) || !canonicalIso(value.issuedAt)
      || value.mandatoryControlsDigest !== policyState.MANDATORY_CONTROLS_DIGEST
      || !POLICY_KEY_ID_RE.test(String(value.signingKeyId || ''))
      || !Number.isSafeInteger(value.signingKeyEpoch) || value.signingKeyEpoch < 1
      || value.historyEpoch !== Math.floor((version - 1) / POLICY_HISTORY_EPOCH_SIZE) + 1
      || (value.rollbackOfGlobalVersion !== null
        && (!Number.isSafeInteger(value.rollbackOfGlobalVersion)
          || value.rollbackOfGlobalVersion < 1 || value.rollbackOfGlobalVersion >= version))) {
    throw fault('global_release_invalid');
  }
  assertDigestFields(value, [
    'approvalAttestationDigest', 'authorizationDigest', 'bundleDigest', 'confirmationDigest',
    'globalArtifactDigest', 'mandatoryControlsDigest', 'ownerApprovalDigest', 'recordDigest',
  ], 'global_release_invalid');
  assertRecordDigest(value, 'global_release_invalid');
  let verifiedGlobal;
  let verifiedApproval;
  try {
    const keys = resolvePolicyKeys(ctx);
    verifiedGlobal = policyProtocol.verifyPersistedGlobalPolicyRelease(
      value.globalArtifact,
      policyTrustFor(keys),
    );
    verifiedApproval = policyProtocol.verifyPersistedOwnerApproval(
      value.approvalAttestation,
      approvalTrustFor(keys.approval, [value.approvalAttestation.keyId]),
    );
  } catch { throw fault('global_release_invalid'); }
  if (policyState.digestPolicyDocument(value.globalPolicy) !== value.bundleDigest
      || verifiedGlobal.artifactDigest !== value.globalArtifactDigest
      || verifiedApproval.artifactDigest !== value.approvalAttestationDigest
      || verifiedApproval.payload.purpose !== (value.rollbackOfGlobalVersion === null
        ? 'policy_global_publish' : 'policy_global_rollback')
      || value.globalArtifact.payload.globalVersion !== version
      || value.globalArtifact.payload.bundleDigest !== value.bundleDigest
      || value.globalArtifact.payload.globalReleaseId !== value.globalReleaseId
      || value.globalArtifact.payload.keyEpoch !== value.signingKeyEpoch
      || value.globalArtifact.payload.approvalAttestationDigest !== value.approvalAttestationDigest) {
    throw fault('global_release_invalid');
  }
  return value;
}

async function readDeploymentHead(tx, id, scope, ctx) {
  const value = await readRecord(tx, 'deployment_head', id,
    INTEGRITY_DOMAINS.DEPLOYMENT_HEAD, ctx);
  if (!value) return Object.freeze({ revision: 0, distributionSequence: 0 });
  const keys = [
    'auditIntentDigest', 'auditSequence', 'customerId', 'deliveryDigest', 'deploymentId',
    'distributionRecordDigest', 'distributionSequence', 'recordDigest', 'recordType',
    'revision', 'schemaVersion', 'targetDigest', 'updatedAt',
  ];
  if (!exactRecord(value, keys, 'deployment_head')
      || value.customerId !== scope.customerId || value.deploymentId !== scope.deploymentId
      || value.distributionSequence !== value.revision || !canonicalIso(value.updatedAt)
      || !Number.isSafeInteger(value.auditSequence) || value.auditSequence < 1) {
    throw fault('deployment_head_invalid');
  }
  assertDigestFields(value, [
    'auditIntentDigest', 'deliveryDigest', 'distributionRecordDigest', 'recordDigest', 'targetDigest',
  ], 'deployment_head_invalid');
  assertRecordDigest(value, 'deployment_head_invalid');
  return value;
}

async function readEmergencyHead(tx, id, scope, ctx) {
  const value = await readRecord(tx, 'emergency_head', id,
    INTEGRITY_DOMAINS.EMERGENCY_HEAD, ctx);
  if (!value) return Object.freeze({ revision: 0, rules: deepFreeze({}) });
  const keys = [
    'auditIntentDigest', 'auditSequence', 'authorizationDigest', 'confirmationDigest',
    'customerId', 'deploymentId', 'dualControlDigest', 'recordDigest', 'recordType',
    'revision', 'rules', 'rulesDigest', 'schemaVersion', 'updatedAt',
  ];
  if (!exactRecord(value, keys, 'emergency_head')
      || value.customerId !== scope.customerId || value.deploymentId !== scope.deploymentId
      || !canonicalIso(value.updatedAt) || !Number.isSafeInteger(value.auditSequence)
      || value.auditSequence < 1 || value.revision < 1) throw fault('emergency_head_invalid');
  assertDigestFields(value, [
    'auditIntentDigest', 'authorizationDigest', 'confirmationDigest', 'dualControlDigest',
    'recordDigest', 'rulesDigest',
  ], 'emergency_head_invalid');
  assertRecordDigest(value, 'emergency_head_invalid');
  const rules = normalizeEmergencyRules(value.rules);
  if (policyState.digestPolicyDocument(rules) !== value.rulesDigest) throw fault('emergency_head_invalid');
  return { ...value, rules };
}

async function readDistribution(tx, id, scope, sequence, ctx) {
  const value = await readRecord(tx, 'distribution', id,
    INTEGRITY_DOMAINS.DISTRIBUTION, ctx);
  if (!value) return null;
  const keys = [
    'artifact', 'authorizationDigest', 'bundleDigest', 'confirmationDigest', 'customerId',
    'deliveryDigest', 'deploymentId', 'desiredOverlayDigest', 'distributionSequence',
    'effectivePolicyDigest', 'emergencyDenyDigest', 'expiresAt', 'globalArtifactDigest',
    'globalKeyEpoch', 'globalReleaseId', 'globalVersion', 'historyEpoch', 'issuedAt',
    'ownerApprovalDigest', 'policyKeyEpoch', 'previousDistributionSequence', 'recordDigest',
    'recordType', 'revision', 'rollbackOfDistributionSequence', 'rollout', 'schemaVersion',
    'signingKeyId', 'supersession', 'targetDigest', 'vendorBundle',
  ];
  if (!exactRecord(value, keys, 'distribution')
      || value.customerId !== scope.customerId || value.deploymentId !== scope.deploymentId
      || value.distributionSequence !== sequence || value.revision !== sequence
      || value.previousDistributionSequence !== sequence - 1
      || !Number.isSafeInteger(value.globalVersion) || value.globalVersion < 1
      || !UUID_RE.test(String(value.globalReleaseId || ''))
      || !['preview', 'staged', 'required'].includes(value.rollout)
      || !canonicalIso(value.issuedAt) || !canonicalIso(value.expiresAt)
      || !POLICY_KEY_ID_RE.test(String(value.signingKeyId || ''))
      || !Number.isSafeInteger(value.policyKeyEpoch) || value.policyKeyEpoch < 1
      || !Number.isSafeInteger(value.globalKeyEpoch) || value.globalKeyEpoch < 1
      || value.historyEpoch !== Math.floor((sequence - 1) / POLICY_HISTORY_EPOCH_SIZE) + 1
      || (value.rollbackOfDistributionSequence !== null
        && (!Number.isSafeInteger(value.rollbackOfDistributionSequence)
          || value.rollbackOfDistributionSequence < 1
          || value.rollbackOfDistributionSequence >= sequence))
      || (value.rollbackOfDistributionSequence === null) !== (value.ownerApprovalDigest === null)) {
    throw fault('distribution_record_invalid');
  }
  assertDigestFields(value, [
    'authorizationDigest', 'bundleDigest', 'confirmationDigest', 'deliveryDigest',
    'desiredOverlayDigest', 'effectivePolicyDigest', 'emergencyDenyDigest',
    'globalArtifactDigest', 'recordDigest', 'targetDigest',
  ], 'distribution_record_invalid');
  assertRecordDigest(value, 'distribution_record_invalid');
  let verified;
  try {
    const trust = policyTrustFor(resolvePolicyKeys(ctx));
    verified = policyState.verifyPersistedPolicyArtifact(value.artifact, trust);
    policyState.resolveVendorPolicyBundle(value.vendorBundle, verified.payload, trust, {
      persisted: true,
    });
  } catch { throw fault('distribution_record_invalid'); }
  if (value.ownerApprovalDigest !== null
      && !SHA256_RE.test(String(value.ownerApprovalDigest || ''))) {
    throw fault('distribution_record_invalid');
  }
  if (policyState.digestPolicyDocument(value.vendorBundle) !== value.bundleDigest
      || verified.payloadDigest !== value.targetDigest
      || value.artifact.keyId !== value.signingKeyId
      || value.vendorBundle.vendorControl.deliveryBinding.policyKeyEpoch !== value.policyKeyEpoch
      || value.vendorBundle.vendorControl.deliveryBinding.globalKeyEpoch !== value.globalKeyEpoch
      || value.vendorBundle.vendorControl.deliveryBinding.rollbackOfDistributionSequence
        !== value.rollbackOfDistributionSequence
      || value.artifact.payload.customerId !== scope.customerId
      || value.artifact.payload.deploymentId !== scope.deploymentId
      || value.artifact.payload.policyVersion !== sequence
      || value.artifact.payload.bundleDigest !== value.bundleDigest) {
    throw fault('distribution_record_invalid');
  }
  return value;
}

async function readAdoption(tx, id, scope, sequence, ctx) {
  const value = await readRecord(tx, 'adoption', id, INTEGRITY_DOMAINS.ADOPTION, ctx);
  if (!value) return null;
  const keys = [
    'acknowledgementCount', 'auditIntentDigest', 'auditSequence', 'customerId',
    'deliveryAttempts', 'deliveryDigest', 'deploymentId', 'distributionSequence',
    'lastAcknowledgementDigest', 'lastReasonCode', 'recordDigest', 'recordType', 'revision',
    'schemaVersion', 'stage', 'targetDigest', 'updatedAt',
  ];
  if (!exactRecord(value, keys, 'adoption')
      || value.customerId !== scope.customerId || value.deploymentId !== scope.deploymentId
      || value.distributionSequence !== sequence || value.revision < 1
      || !['published', 'delivered', 'applied', 'rejected'].includes(value.stage)
      || !Number.isSafeInteger(value.deliveryAttempts) || value.deliveryAttempts < 0
      || value.deliveryAttempts > MAX_DELIVERY_ATTEMPTS
      || !Number.isSafeInteger(value.acknowledgementCount) || value.acknowledgementCount < 0
      || value.acknowledgementCount > MAX_ACKNOWLEDGEMENTS || !canonicalIso(value.updatedAt)
      || !Number.isSafeInteger(value.auditSequence) || value.auditSequence < 1
      || !SHA256_RE.test(String(value.auditIntentDigest || ''))) throw fault('adoption_state_invalid');
  assertDigestFields(value, ['deliveryDigest', 'recordDigest', 'targetDigest'], 'adoption_state_invalid');
  if ((value.lastAcknowledgementDigest === null) !== (value.lastReasonCode === null)
      || (value.lastAcknowledgementDigest !== null
        && !SHA256_RE.test(String(value.lastAcknowledgementDigest || '')))) {
    throw fault('adoption_state_invalid');
  }
  assertRecordDigest(value, 'adoption_state_invalid');
  return value;
}

function validateAckClaim(value, scope, sequence, targetDigest, messageId) {
  const keys = [
    'acknowledgementDigest', 'authorizationDigest', 'customerId', 'deploymentId',
    'distributionSequence', 'messageId', 'recordDigest', 'recordType', 'recordedAt', 'result',
    'revision', 'schemaVersion', 'targetDigest',
  ];
  if (!exactRecord(value, keys, 'ack_claim') || value.revision !== 1
      || value.customerId !== scope.customerId || value.deploymentId !== scope.deploymentId
      || value.distributionSequence !== sequence || value.targetDigest !== targetDigest
      || value.messageId !== messageId || !UUID_RE.test(String(value.messageId || ''))
      || !canonicalIso(value.recordedAt)) throw fault('acknowledgement_claim_invalid');
  assertDigestFields(value, [
    'acknowledgementDigest', 'authorizationDigest', 'recordDigest', 'targetDigest',
  ], 'acknowledgement_claim_invalid');
  assertRecordDigest(value, 'acknowledgement_claim_invalid');
}

async function readRecord(tx, type, id, domain, ctx) {
  const raw = await call(tx, 'readPolicyRecord', type, id);
  if (!raw) return null;
  return ctx.integrity.open(domain, raw);
}

async function insertExactRecord(tx, type, id, value, domain, ctx) {
  const existing = await readRecord(tx, type, id, domain, ctx);
  if (existing) {
    if (operationDigest(existing) !== operationDigest(value)) throw fault('policy_record_conflict');
    return 'replay';
  }
  const wrapped = ctx.integrity.seal(domain, value);
  if (await call(tx, 'insertPolicyRecord', type, id, wrapped) !== true) {
    throw fault('policy_record_conflict');
  }
  return 'inserted';
}

async function compareAndSetRecord(tx, type, id, expectedRevision, value, domain, ctx, code) {
  const wrapped = ctx.integrity.seal(domain, value);
  if (await call(tx, 'compareAndSetPolicyRecord', type, id, expectedRevision, wrapped) !== true) {
    throw fault(code);
  }
}

async function readOperation(tx, opDigest, ctx) {
  const raw = await call(tx, 'readPolicyOperation', opDigest);
  if (!raw) return null;
  const value = ctx.integrity.open(INTEGRITY_DOMAINS.OPERATION, raw);
  if (!plainRecord(value) || !exactKeys(value, [
    'operationDigest', 'result', 'resultDigest', 'schemaVersion',
  ]) || value.schemaVersion !== 1 || value.operationDigest !== opDigest
      || value.resultDigest !== operationDigest(value.result)) throw fault('policy_operation_invalid');
  return deepFreeze(clone(value.result));
}

async function insertOperation(tx, opDigest, result, ctx) {
  const value = {
    schemaVersion: 1,
    operationDigest: opDigest,
    result: clone(result),
    resultDigest: operationDigest(result),
  };
  const existing = await readOperation(tx, opDigest, ctx);
  if (existing) {
    if (operationDigest(existing) !== value.resultDigest) throw fault('policy_operation_conflict');
    return;
  }
  const wrapped = ctx.integrity.seal(INTEGRITY_DOMAINS.OPERATION, value);
  if (await call(tx, 'insertPolicyOperation', opDigest, wrapped) !== true) {
    throw fault('policy_operation_conflict');
  }
}

async function readAnyHead(tx, type, id, ctx) {
  const domains = {
    global_head: INTEGRITY_DOMAINS.GLOBAL_HEAD,
    deployment_head: INTEGRITY_DOMAINS.DEPLOYMENT_HEAD,
    emergency_head: INTEGRITY_DOMAINS.EMERGENCY_HEAD,
    adoption: INTEGRITY_DOMAINS.ADOPTION,
  };
  if (!domains[type]) throw fault('policy_pending_invalid');
  const value = await readRecord(tx, type, id, domains[type], ctx);
  if (!value) return null;
  assertRecordDigest(value, 'policy_pending_invalid');
  return value;
}

function resolvePolicyKeys(ctx) {
  const keys = ctx.keyAuthority.resolve();
  const owner = ctx.ownerAuthority.resolve();
  const approval = normalizePolicyApprovalAuthority(ctx.policyApprovalTrust.resolve());
  const reservedExternal = ctx.reservedExternalAuthorities.resolve();
  const policyRecords = owner.records.get(KEY_PURPOSES.POLICY);
  if (!policyRecords || policyRecords.length !== keys.archived.size
      || owner.current.get(KEY_PURPOSES.POLICY)?.keyId !== keys.current.keyId
      || policyRecords.find((record) => record.slot === 'next')?.keyId
        !== (keys.next?.keyId || undefined)) {
    throw fault('policy_owner_authority_manifest_mismatch');
  }
  for (const record of policyRecords) {
    const trusted = keys.archived.get(record.keyId);
    if (!trusted || trusted.fingerprint !== record.identity) {
      throw fault('policy_owner_authority_manifest_mismatch');
    }
  }
  const supplementalRecords = [
    {
      purpose: 'policy_integrity',
      identityType: SUPPLEMENTAL_POLICY_AUTHORITY_TYPES.policy_integrity,
      keyId: ctx.integrity.keyId, identity: ctx.integrity.fingerprint,
    },
    {
      purpose: 'policy_witness',
      identityType: SUPPLEMENTAL_POLICY_AUTHORITY_TYPES.policy_witness,
      keyId: ctx.pending.keyId, identity: ctx.pending.fingerprint,
    },
    ...approval.records,
  ];
  const reservedIdentities = new Set(owner.identities);
  const reservedKeyIds = new Set(owner.keyIds);
  for (const record of supplementalRecords) {
    if (reservedIdentities.has(record.identity) || reservedKeyIds.has(record.keyId)) {
      throw fault('policy_authority_identity_reused');
    }
    reservedIdentities.add(record.identity);
    reservedKeyIds.add(record.keyId);
  }
  for (const record of reservedExternal) {
    if (reservedIdentities.has(record.fingerprint) || reservedKeyIds.has(record.keyId)) {
      throw fault('policy_authority_identity_reused');
    }
    reservedIdentities.add(record.fingerprint);
    reservedKeyIds.add(record.keyId);
  }
  const offline = owner.current.get(KEY_PURPOSES.OFFLINE_LICENSE)?.identity;
  const expectedApprovalForbidden = new Set([
    ...owner.identities,
    ctx.integrity.fingerprint,
    ctx.pending.fingerprint,
    ...reservedExternal.map((record) => record.fingerprint),
  ]);
  expectedApprovalForbidden.delete(offline);
  if (approval.offlineKeyFingerprint !== offline
      || !sameStringSet(approval.forbiddenPublicKeyFingerprints, expectedApprovalForbidden)) {
    throw fault('policy_approval_trust_incomplete');
  }
  const approvalActiveKeyIds = ctx.policyApprovalActiveKeyIds.resolve();
  if (approvalActiveKeyIds.some((keyId) => !approval.publicKeys.has(keyId))) {
    throw fault('policy_approval_active_keys_invalid');
  }
  return Object.freeze({
    ...keys,
    owner,
    approval: Object.freeze({ ...approval, activeKeyIds: approvalActiveKeyIds }),
    supplementalIdentities: new Set([
      ...supplementalRecords.map((record) => record.identity),
      ...reservedExternal.map((record) => record.fingerprint),
    ]),
  });
}

function policyTrustFor(keys) {
  const publicKeys = keys.owner.authorityRegistry.activePublicKeys(KEY_PURPOSES.POLICY);
  const keyEpochs = {};
  for (const [keyId, value] of keys.archived) {
    keyEpochs[keyId] = {
      validFromEpoch: value.validFromEpoch,
      retireAfterEpoch: value.retireAfterEpoch,
    };
  }
  const offlineKeyFingerprint = keys.owner.current.get(KEY_PURPOSES.OFFLINE_LICENSE).identity;
  const policyIdentities = new Set(keys.owner.records.get(KEY_PURPOSES.POLICY)
    .map((record) => record.identity));
  const forbiddenPublicKeyFingerprints = [
    ...[...keys.owner.identities].filter((identity) => identity !== offlineKeyFingerprint
      && !policyIdentities.has(identity)),
    ...keys.supplementalIdentities,
  ];
  return {
    currentEpoch: keys.epoch,
    publicKeys,
    keyEpochs,
    authorityRegistry: keys.owner.authorityRegistry,
    offlineKeyFingerprint,
    forbiddenPublicKeyFingerprints,
  };
}

function normalizePolicyApprovalAuthority(value) {
  if (!plainRecord(value) || !exactKeys(value, [
    'currentEpoch', 'forbiddenPublicKeyFingerprints', 'keyEpochs',
    'offlineKeyFingerprint', 'publicKeys',
  ]) || !Number.isSafeInteger(value.currentEpoch) || value.currentEpoch < 1
      || !SHA256_RE.test(String(value.offlineKeyFingerprint || ''))
      || !Array.isArray(value.forbiddenPublicKeyFingerprints)
      || !value.forbiddenPublicKeyFingerprints.every((item) => SHA256_RE.test(String(item || '')))
      || new Set([value.offlineKeyFingerprint, ...value.forbiddenPublicKeyFingerprints]).size
        !== value.forbiddenPublicKeyFingerprints.length + 1
      || !plainRecord(value.keyEpochs)) {
    throw fault('policy_approval_trust_invalid');
  }
  const entries = value.publicKeys instanceof Map ? [...value.publicKeys.entries()]
    : plainRecord(value.publicKeys) ? Object.entries(value.publicKeys) : [];
  if (!entries.length || entries.length > MAX_ARCHIVED_KEYS
      || Object.keys(value.keyEpochs).sort().join(',')
        !== entries.map(([keyId]) => keyId).sort().join(',')) {
    throw fault('policy_approval_trust_invalid');
  }
  const identities = new Set();
  const records = [];
  const publicKeys = new Map();
  const keyEpochs = {};
  for (const [keyId, rawKey] of entries) {
    const epoch = value.keyEpochs[keyId];
    if (!/^rw-owner-policy-approval-[a-z0-9][a-z0-9_.-]{0,54}$/.test(String(keyId || ''))
        || !plainRecord(epoch) || !exactKeys(epoch, ['retireAfterEpoch', 'validFromEpoch'])
        || !Number.isSafeInteger(epoch.validFromEpoch) || epoch.validFromEpoch < 1
        || epoch.validFromEpoch > value.currentEpoch + 1
        || (epoch.retireAfterEpoch !== null && (!Number.isSafeInteger(epoch.retireAfterEpoch)
          || epoch.retireAfterEpoch < epoch.validFromEpoch))) {
      throw fault('policy_approval_trust_invalid');
    }
    const identity = publicFingerprint(publicEd25519(rawKey));
    if (identities.has(identity)) throw fault('policy_authority_identity_reused');
    identities.add(identity);
    publicKeys.set(keyId, publicEd25519(rawKey));
    keyEpochs[keyId] = {
      validFromEpoch: epoch.validFromEpoch,
      retireAfterEpoch: epoch.retireAfterEpoch,
    };
    records.push(Object.freeze({
      purpose: 'policy_approval',
      identityType: SUPPLEMENTAL_POLICY_AUTHORITY_TYPES.policy_approval,
      keyId,
      identity,
    }));
  }
  return Object.freeze({
    records: Object.freeze(records),
    currentEpoch: value.currentEpoch,
    publicKeys,
    keyEpochs: Object.freeze(keyEpochs),
    offlineKeyFingerprint: value.offlineKeyFingerprint,
    forbiddenPublicKeyFingerprints: Object.freeze([...value.forbiddenPublicKeyFingerprints]),
  });
}

function approvalTrustFor(approval, keyIds) {
  const publicKeys = {};
  const keyEpochs = {};
  for (const keyId of keyIds) {
    const key = approval.publicKeys.get(keyId);
    const epoch = approval.keyEpochs[keyId];
    if (!key || !epoch) throw fault('policy_approval_active_keys_invalid');
    publicKeys[keyId] = key;
    keyEpochs[keyId] = epoch;
  }
  return {
    currentEpoch: approval.currentEpoch,
    publicKeys,
    keyEpochs,
    offlineKeyFingerprint: approval.offlineKeyFingerprint,
    forbiddenPublicKeyFingerprints: approval.forbiddenPublicKeyFingerprints,
  };
}

function sameStringSet(values, expected) {
  return values.length === expected.size && values.every((value) => expected.has(value));
}

function signDesiredState(payload, slot) {
  const checked = protocol.assertChannel(payload, protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE);
  return deepFreeze({
    keyId: slot.keyId,
    payload: checked,
    signature: crypto.sign(null, protocol.signingInput(checked, slot.keyId), slot.privateKey).toString('base64'),
  });
}

function normalizeEmergencyRules(value) {
  const allowed = new Set([
    'alwaysBlockAdd', 'blockMinSeverity', 'blockRiskScore', 'blockUnapprovedAiDestinations',
    'blockedDestinationsAdd', 'blockedFileUploadDestinationsAdd', 'enforcementMode',
    'mcpBlockedToolsAdd', 'responseScanMode', 'unmanagedInstalls',
  ]);
  if (!plainRecord(value) || Object.keys(value).some((key) => !allowed.has(key))) {
    throw fault('emergency_deny_rules_invalid');
  }
  let normalized;
  try { normalized = policyState.normalizePolicyOverlay(value); }
  catch { throw fault('emergency_deny_rules_invalid'); }
  if (!Object.keys(normalized).length
      || (normalized.enforcementMode !== undefined && normalized.enforcementMode !== 'block')
      || (normalized.responseScanMode !== undefined && normalized.responseScanMode !== 'block')
      || (normalized.unmanagedInstalls !== undefined && normalized.unmanagedInstalls !== 'block')
      || (normalized.blockUnapprovedAiDestinations !== undefined
        && normalized.blockUnapprovedAiDestinations !== true)) {
    throw fault('emergency_deny_rules_invalid');
  }
  return normalized;
}

function assertEmergencyAdditive(currentValue, nextValue) {
  const current = policyState.normalizePolicyOverlay(currentValue || {});
  const next = policyState.normalizePolicyOverlay(nextValue || {});
  const listFields = [
    'alwaysBlockAdd', 'blockedDestinationsAdd', 'blockedFileUploadDestinationsAdd',
    'mcpBlockedToolsAdd',
  ];
  for (const field of listFields) {
    const candidate = new Set(next[field] || []);
    if ((current[field] || []).some((item) => !candidate.has(item))) {
      throw fault('emergency_deny_not_additive');
    }
  }
  for (const field of ['enforcementMode', 'responseScanMode', 'unmanagedInstalls']) {
    if (current[field] !== undefined && next[field] !== current[field]) {
      throw fault('emergency_deny_not_additive');
    }
  }
  for (const field of ['blockMinSeverity', 'blockRiskScore']) {
    if (current[field] !== undefined
        && (next[field] === undefined || next[field] > current[field])) {
      throw fault('emergency_deny_not_additive');
    }
  }
  if (current.blockUnapprovedAiDestinations === true
      && next.blockUnapprovedAiDestinations !== true) {
    throw fault('emergency_deny_not_additive');
  }
}

function adoptionResult(value) {
  return {
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    distributionSequence: value.distributionSequence,
    targetDigest: value.targetDigest,
    deliveryDigest: value.deliveryDigest,
    stage: value.stage,
    revision: value.revision,
    deliveryAttempts: value.deliveryAttempts,
    acknowledgementCount: value.acknowledgementCount,
    lastReasonCode: value.lastReasonCode,
    lastAcknowledgementDigest: value.lastAcknowledgementDigest,
    updatedAt: value.updatedAt,
  };
}

function exactRecord(value, keys, recordType) {
  return plainRecord(value) && exactKeys(value, keys)
    && value.schemaVersion === 1 && value.recordType === recordType
    && Number.isSafeInteger(value.revision) && value.revision >= 1;
}

function assertDigestFields(value, keys, code) {
  if (keys.some((key) => !SHA256_RE.test(String(value[key] || '')))) throw fault(code);
}

function assertRecordDigest(value, code) {
  if (!SHA256_RE.test(String(value.recordDigest || ''))) throw fault(code);
  const core = withoutRecordDigest(value);
  if (operationDigest(core) !== value.recordDigest) throw fault(code);
}

function withoutRecordDigest(value) {
  const copy = clone(value);
  delete copy.recordDigest;
  return copy;
}

function headReference(type, id, value) {
  return {
    type,
    id,
    revision: value.revision,
    recordDigest: value.recordDigest,
  };
}

function scopeRecordId(scope) {
  validateScope(scope.customerId, scope.deploymentId);
  return digestCanonical(scope);
}

function distributionRecordId(scopeId, sequence) {
  if (!SHA256_RE.test(String(scopeId || '')) || !Number.isSafeInteger(sequence) || sequence < 1) {
    throw fault('distribution_record_id_invalid');
  }
  return `d:${scopeId.slice(0, 48)}:${sequence}`;
}

function ackMessageClaimId(scope, messageId) {
  return `a:${digestCanonical({ scope, messageId }).slice(0, 64)}`;
}

function validateScope(customerId, deploymentId) {
  if (!CUSTOMER_ID_RE.test(String(customerId || ''))
      || !isDeploymentId(deploymentId)) throw fault('scope_invalid');
}

function assertNullableScope(customerId, deploymentId) {
  if (customerId === null && deploymentId === null) return;
  validateScope(customerId, deploymentId);
}

function validateStepUp(value, now) {
  if (value === null) throw fault('step_up_required');
  const stepUpAt = parseIso(value, 'step_up_required');
  if (stepUpAt > now.ms + MAX_CLOCK_SKEW_MS || now.ms - stepUpAt > MAX_STEP_UP_AGE_MS) {
    throw fault('step_up_required');
  }
}

function parseIso(value, code) {
  if (!canonicalIso(value)) throw fault(code);
  return Date.parse(value);
}

function canonicalIso(value) {
  if (typeof value !== 'string' || !ISO_MS_RE.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function claimResult(value) {
  const result = typeof value === 'string' ? value
    : (plainRecord(value) && typeof value.status === 'string' ? value.status : '');
  return ['claimed', 'replay', 'conflict'].includes(result) ? result : '';
}

function publicEd25519(value) {
  let key;
  try { key = parsePublicOnlyEd25519Key(value); }
  catch { throw fault('policy_key_authority_invalid'); }
  return key;
}

function publicManifestEd25519(value) {
  if (typeof value !== 'string') throw fault('policy_owner_authority_manifest_invalid');
  let der;
  try {
    der = Buffer.from(value, 'base64');
    if (!der.length || der.toString('base64') !== value) throw new Error('noncanonical');
    return parsePublicOnlyEd25519Key({ key: der, format: 'der', type: 'spki' });
  } catch { throw fault('policy_owner_authority_manifest_invalid'); }
}

function privateEd25519(value) {
  let key;
  try { key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value); }
  catch { throw fault('policy_key_authority_invalid'); }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw fault('policy_key_authority_invalid');
  }
  return key;
}

function publicFingerprint(key) {
  const der = key.export({ type: 'spki', format: 'der' });
  return digestBytes(der);
}

function integrityInput(domain, keyId, payload) {
  return Buffer.from(`${domain}\0${keyId}\0${protocol.canonicalJson(payload)}`, 'utf8');
}

function digestCanonical(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function digestBytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function assertNoSensitiveMetadata(value, seen = new Set(), depth = 0) {
  if (depth > 64) throw fault('sensitive_metadata_rejected');
  if (typeof value === 'string') {
    if (SENSITIVE_VALUE_PATTERNS.some((pattern) => pattern.test(value))) {
      throw fault('sensitive_metadata_rejected');
    }
    return;
  }
  if (!value || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (FORBIDDEN_METADATA_KEY_RE.test(key)) throw fault('sensitive_metadata_rejected');
    if (Object.hasOwn(descriptor, 'value')) assertNoSensitiveMetadata(descriptor.value, seen, depth + 1);
  }
  seen.delete(value);
}

function assertPlainTree(value, seen = new Set(), depth = 0) {
  if (depth > 64) throw fault('plain_data_required');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value) && !Object.is(value, -0)) return;
  if (!value || typeof value !== 'object' || seen.has(value)) throw fault('plain_data_required');
  seen.add(value);
  if (Array.isArray(value)) {
    const names = Object.getOwnPropertyNames(value);
    if (Object.getOwnPropertySymbols(value).length || names.length !== value.length + 1) {
      throw fault('plain_data_required');
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw fault('plain_data_required');
      }
      assertPlainTree(descriptor.value, seen, depth + 1);
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if ((prototype !== Object.prototype && prototype !== null)
        || Object.getOwnPropertySymbols(value).length) throw fault('plain_data_required');
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (FORBIDDEN_TREE_KEYS.has(key) || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw fault('plain_data_required');
      }
      assertPlainTree(descriptor.value, seen, depth + 1);
    }
  }
  seen.delete(value);
}

function sortedStrings(values) {
  return values.every((value, index) => index === 0 || values[index - 1].localeCompare(value) < 0);
}

function exactKeys(value, keys) {
  return Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function clone(value) {
  return JSON.parse(protocol.canonicalJson(value));
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}

async function call(target, method, ...args) {
  if (!target || typeof target[method] !== 'function') throw fault('storage_contract_invalid');
  return target[method](...args);
}

function fault(code) {
  const error = new Error('vendor policy authority operation rejected');
  error.code = code;
  return error;
}

module.exports = {
  INTEGRITY_DOMAINS,
  MAX_ACKNOWLEDGEMENTS,
  MAX_ACTIVE_AUDIT_EVENTS,
  MAX_ARCHIVED_KEYS,
  MAX_DELIVERY_ATTEMPTS,
  MAX_POLICY_DELIVERY_TTL_MS,
  MAX_STEP_UP_AGE_MS,
  POLICY_EXTERNAL_ASSURANCE,
  POLICY_REFERENCE_PROFILE,
  POLICY_TEST_EXTERNAL_ASSURANCE,
  SUPPLEMENTAL_POLICY_AUTHORITY_TYPES,
  createProductionVendorPolicyAuthority,
  createVendorPolicyAuthority,
};
