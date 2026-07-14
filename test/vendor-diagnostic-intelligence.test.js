'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const protocol = require('../server/vendor-control-protocol');
const {
  AUTHORIZATION_DOMAIN,
  AUDIT_DOMAIN,
  CAPABILITY_DOMAIN,
  CONSENT_DOMAIN,
  CUSTOMER_GRANT_DOMAIN,
  DELETION_INTENT_DOMAIN,
  OWNER_AUTH_ASSERTION_DOMAIN,
  IDEMPOTENCY_HORIZON_MS,
  MAX_DOCUMENT_BYTES,
  QUOTA_DOMAIN,
  STORAGE_CONTRACT_VERSION,
  createVendorDiagnosticIntelligence,
} = require('../server/vendor-diagnostic-intelligence');
const {
  createCustomerDeletionIntentKeyRegistry,
  deletionIntentSigningInput,
} = require('../server/vendor-diagnostic-customer-key-registry');
const {
  ReferenceDiagnosticStorage,
  authenticate,
  canonical,
  digest,
  hmacAuthority,
  quotaReference,
  scopeKey,
  stateAudit,
} = require('./support/vendor-diagnostic-reference-adapter');

const NOW = Date.parse('2026-07-12T12:00:00.000Z');
const DAY_MS = 24 * 60 * 60 * 1000;
const GENERIC_ERROR = 'vendor diagnostic intelligence operation rejected';
const CUSTOMER_A = 'cu-diagnostic-a';
const CUSTOMER_B = 'cu-diagnostic-b';
const DEPLOYMENT_A = 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DEPLOYMENT_B = 'dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const EXPORT_SUPPORT_CASE = '24000000-0000-4000-8000-000000000001';
const EXPORT_APPROVAL = '25000000-0000-4000-8000-000000000001';

const CONNECTOR_A = Object.freeze({
  principalId: '10000000-0000-4000-8000-000000000001',
  principalType: 'connector',
  sessionId: '11000000-0000-4000-8000-000000000001',
});
const CONNECTOR_B = Object.freeze({
  principalId: '10000000-0000-4000-8000-000000000002',
  principalType: 'connector',
  sessionId: '11000000-0000-4000-8000-000000000002',
});
const VENDOR = Object.freeze({
  principalId: '20000000-0000-4000-8000-000000000001',
  principalType: 'vendor',
  sessionId: '21000000-0000-4000-8000-000000000001',
});
const SCHEDULER = Object.freeze({
  principalId: '30000000-0000-4000-8000-000000000001',
  principalType: 'scheduler',
  sessionId: '31000000-0000-4000-8000-000000000001',
});

function createHarness(options = {}) {
  let nowMs = options.nowMs === undefined ? NOW : options.nowMs;
  let principal = CONNECTOR_A;
  const storage = options.storage || new ReferenceDiagnosticStorage({ databaseTimeMs: nowMs });
  storage.setDatabaseTime(nowMs);
  const authorities = options.authorities || authorityBundle();
  const fingerprints = fingerprintBundle(authorities);
  const deletionKeys = options.deletionKeys || customerDeletionKeys(nowMs);

  for (const identity of [CONNECTOR_A, CONNECTOR_B, VENDOR, SCHEDULER]) {
    installAuthorization(storage, authorities, identity, nowMs);
  }
  installGrantAndConsent(storage, authorities, CUSTOMER_A, DEPLOYMENT_A, nowMs);
  installGrantAndConsent(storage, authorities, CUSTOMER_B, DEPLOYMENT_B, nowMs);

  const intelligence = createVendorDiagnosticIntelligence({
    storage,
    integrityAuthority: authorities.integrity,
    accessAuthority: authorities.access,
    auditAuthority: authorities.audit,
    customerGrantAuthority: authorities.customerGrant,
    cursorAuthority: authorities.cursor,
    ownerAuthAuthority: authorities.ownerAuth,
    deletionIntentKeyRegistry: deletionKeys.registry,
    authorityFingerprints: fingerprints,
    currentPrincipal: () => principal,
    retentionDays: options.retentionDays === undefined ? 30 : options.retentionDays,
    dailyEventLimit: options.dailyEventLimit === undefined ? 100_000 : options.dailyEventLimit,
  });

  return {
    authorities,
    fingerprints,
    intelligence,
    storage,
    deletionKeys,
    now: () => nowMs,
    setNow(value) { nowMs = value; storage.setDatabaseTime(value); },
    setPrincipal(value) { principal = value; },
    capability(purpose, overrides = {}) {
      const identity = overrides.principal || principal;
      const authorization = storage.data.authorizations.get(identity.principalId);
      const defaults = capabilityScope(identity, purpose);
      const sensitive = purpose === 'diagnostics:export'
        || purpose.startsWith('diagnostics:delete:')
        || purpose === 'diagnostics:clock:recover';
      const ownerAuthAssertion = identity.principalType === 'vendor'
        ? authenticate(authorities.ownerAuth, OWNER_AUTH_ASSERTION_DOMAIN, {
          schemaVersion: 1,
          recordType: 'owner_auth_assertion',
          assertionId: crypto.randomUUID(),
          principalId: identity.principalId,
          sessionId: identity.sessionId,
          ownerAuthEventId: authorization.ownerAuthEventId,
          mfaEventId: crypto.randomUUID(),
          issuer: authorization.issuer,
          credentialVersion: authorization.credentialVersion,
          authenticatedAt: new Date(nowMs).toISOString(),
          mfaAt: new Date(nowMs).toISOString(),
          expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
        }) : null;
      const core = {
        schemaVersion: 1,
        recordType: 'capability',
        capabilityId: crypto.randomUUID(),
        principalId: identity.principalId,
        sessionId: identity.sessionId,
        principalType: identity.principalType,
        purpose,
        customerIds: defaults.customerIds,
        deploymentId: defaults.deploymentId,
        ownerAuthEventId: authorization.ownerAuthEventId,
        ownerAuthAssertion,
        issuer: authorization.issuer,
        credentialPurpose: authorization.credentialPurpose,
        credentialVersion: authorization.credentialVersion,
        authorizationRevision: authorization.revision,
        issuedAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
        stepUpAt: sensitive
          ? new Date(nowMs).toISOString() : null,
        supportCaseId: purpose === 'diagnostics:export' ? EXPORT_SUPPORT_CASE : null,
        approvalId: ['diagnostics:delete:approve', 'diagnostics:delete:execute',
          'diagnostics:clock:recover'].includes(purpose)
          ? crypto.randomUUID() : purpose === 'diagnostics:export' ? EXPORT_APPROVAL : null,
        ...withoutPrincipal(overrides),
      };
      return authenticate(authorities.access, CAPABILITY_DOMAIN, core);
    },
    replaceAuthorization(identity, overrides = {}) {
      return installAuthorization(storage, authorities, identity, nowMs, overrides, true);
    },
    replaceConsent(customerId, deploymentId, overrides = {}) {
      return installConsent(storage, authorities, customerId, deploymentId, nowMs, overrides, true);
    },
  };
}

function authorityBundle() {
  const diagnosticIntegrity = hmacAuthority('diagnostic-integrity');
  return {
    access: hmacAuthority('diagnostic-access'),
    audit: hmacAuthority('diagnostic-audit'),
    customerGrant: hmacAuthority('diagnostic-customer-grant'),
    cursor: hmacAuthority('diagnostic-cursor'),
    integrity: hmacAuthority('diagnostic-integrity', {
      keyId: `rw-diagnostic-integrity-${diagnosticIntegrity.fingerprint}`,
    }),
    ownerAuth: hmacAuthority('diagnostic-owner-auth'),
  };
}

function customerDeletionKeys(nowMs) {
  const privateKeys = new Map();
  const entries = [[CUSTOMER_A, DEPLOYMENT_A], [CUSTOMER_B, DEPLOYMENT_B]].map(
    ([customerId, deploymentId], index) => {
      const pair = crypto.generateKeyPairSync('ed25519');
      const keyId = `customer-delete-${index + 1}`;
      privateKeys.set(`${customerId}\0${deploymentId}`, { keyId, key: pair.privateKey });
      return {
        customerId,
        deploymentId,
        current: {
          keyId,
          publicKey: pair.publicKey.export({ format: 'pem', type: 'spki' }),
          validFrom: new Date(nowMs - DAY_MS).toISOString(),
        },
        verifyOnly: [],
      };
    },
  );
  return {
    privateKeys,
    registry: createCustomerDeletionIntentKeyRegistry({ entries, now: () => nowMs }),
  };
}

function signDeletionIntent(deletionKeys, core) {
  const identity = deletionKeys.privateKeys.get(`${core.customerId}\0${core.deploymentId}`);
  const message = canonical(core);
  return deepFreezeForTest({
    ...core,
    keyId: identity.keyId,
    recordDigest: digest(core),
    signature: crypto.sign(
      null,
      deletionIntentSigningInput(DELETION_INTENT_DOMAIN, identity.keyId, message),
      identity.key,
    ).toString('base64'),
  });
}

function customerDeletionIntent(harness, overrides = {}) {
  const grant = harness.storage.data.customerGrants.get(scopeKey({
    customerId: CUSTOMER_A, deploymentId: DEPLOYMENT_A,
  }));
  const core = {
    schemaVersion: 1,
    recordType: 'deletion_intent',
    intentId: crypto.randomUUID(),
    customerId: CUSTOMER_A,
    deploymentId: DEPLOYMENT_A,
    channel: 'diagnostics',
    customerGrantId: grant.grantId,
    customerGrantDigest: grant.recordDigest,
    customerGrantRevision: grant.revision,
    scopeRevision: grant.revision,
    subjectDigest: digest({ subject: 'customer-privacy-officer' }),
    reasonCode: 'privacy_request',
    issuedAt: new Date(harness.now()).toISOString(),
    expiresAt: new Date(harness.now() + 60 * 60 * 1000).toISOString(),
    ...overrides,
  };
  return signDeletionIntent(harness.deletionKeys, core);
}

function deepFreezeForTest(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreezeForTest(child);
  return value;
}

function fingerprintBundle(authorities) {
  return {
    diagnosticAccess: authorities.access.fingerprint,
    diagnosticAudit: authorities.audit.fingerprint,
    diagnosticCursor: authorities.cursor.fingerprint,
    diagnosticCustomerGrant: authorities.customerGrant.fingerprint,
    diagnosticIntegrity: authorities.integrity.fingerprint,
    diagnosticOwnerAuth: authorities.ownerAuth.fingerprint,
    diagnosticWitness: digest({ authority: 'diagnostic-witness' }),
    acknowledgement_credential: digest({ authority: 'acknowledgement-credential' }),
    audit_request: digest({ authority: 'audit-request' }),
    catalog_distribution: digest({ authority: 'catalog-distribution' }),
    catalog_global: digest({ authority: 'catalog-global' }),
    command_idempotency: digest({ authority: 'command-idempotency' }),
    diagnostic_credential: digest({ authority: 'diagnostic-credential' }),
    diagnostic_integrity: authorities.integrity.fingerprint,
    entitlement: digest({ authority: 'entitlement' }),
    heartbeat_credential: digest({ authority: 'heartbeat-credential' }),
    license_registry_integrity: digest({ authority: 'license-registry-integrity' }),
    lifecycle: digest({ authority: 'lifecycle' }),
    offline_license: digest({ authority: 'offline-license' }),
    online_verdict: digest({ authority: 'online-verdict' }),
    owner_attestation: digest({ authority: 'owner-attestation' }),
    pagination_cursor: digest({ authority: 'pagination-cursor' }),
    platform_audit: digest({ authority: 'platform-audit' }),
    policy: digest({ authority: 'policy' }),
    recovery: digest({ authority: 'recovery' }),
    shadow_candidate_credential: digest({ authority: 'shadow-candidate-credential' }),
    witness_integrity: digest({ authority: 'witness-integrity' }),
  };
}

function serviceConfiguration(overrides = {}) {
  const authorities = overrides.authorities || authorityBundle();
  const storage = overrides.storage || new ReferenceDiagnosticStorage();
  const configuration = {
    storage,
    integrityAuthority: authorities.integrity,
    accessAuthority: authorities.access,
    authorityFingerprints: fingerprintBundle(authorities),
    currentPrincipal: () => CONNECTOR_A,
    auditAuthority: authorities.audit,
    customerGrantAuthority: authorities.customerGrant,
    cursorAuthority: authorities.cursor,
    ownerAuthAuthority: authorities.ownerAuth,
    deletionIntentKeyRegistry: overrides.deletionIntentKeyRegistry
      || customerDeletionKeys(NOW).registry,
    ...overrides,
  };
  delete configuration.authorities;
  return configuration;
}

function signedAudit(authority, descriptor) {
  return authenticate(authority, AUDIT_DOMAIN, descriptor);
}

function installAuthorization(storage, authorities, principal, nowMs, overrides = {}, replace = false) {
  const prior = storage.data.authorizations.get(principal.principalId);
  const revision = overrides.revision === undefined
    ? (replace && prior ? prior.revision + 1 : 1) : overrides.revision;
  const core = {
    schemaVersion: 1,
    recordType: 'authorization_state',
    principalId: principal.principalId,
    principalType: principal.principalType,
    revision,
    ownerAuthEventId: crypto.randomUUID(),
    issuer: 'owner-platform',
    credentialPurpose: principal.principalType === 'connector'
      ? 'connector_credential' : principal.principalType === 'scheduler'
        ? 'scheduler_job' : 'owner_session',
    credentialVersion: replace && prior ? prior.credentialVersion + 1 : 1,
    revocationRevision: 0,
    status: 'active',
    updatedAt: new Date(nowMs - 1_000).toISOString(),
    expiresAt: new Date(NOW + 200 * DAY_MS).toISOString(),
    auditEventId: crypto.randomUUID(),
    ...overrides,
  };
  const record = authenticate(authorities.access, AUTHORIZATION_DOMAIN, core);
  const audit = signedAudit(authorities.audit, stateAudit(record, 'diagnostic_authorization_state', {
    customerId: null,
    deploymentId: null,
    referenceId: record.principalId,
  }));
  storage.data.authorizations.set(principal.principalId, structuredClone(record));
  storage.data.audits.push(structuredClone(audit));
  return record;
}

function installConsent(
  storage, authorities, customerId, deploymentId, nowMs, overrides = {}, replace = false,
) {
  const prior = storage.data.consents.get(scopeKey({ customerId, deploymentId }));
  const grant = storage.data.customerGrants.get(scopeKey({ customerId, deploymentId }));
  const revision = overrides.revision === undefined
    ? (replace && prior ? prior.revision + 1 : 1) : overrides.revision;
  const core = {
    schemaVersion: 1,
    recordType: 'consent_state',
    channel: 'diagnostics',
    consentId: prior ? prior.consentId : crypto.randomUUID(),
    customerId,
    deploymentId,
    enabled: true,
    expiresAt: new Date(NOW + 200 * DAY_MS).toISOString(),
    retentionDays: 1,
    revision,
    revocationRevision: 0,
    updatedAt: new Date(nowMs - 1_000).toISOString(),
    usePolicy: 'support_security_only',
    customerGrantId: grant.grantId,
    customerGrantDigest: grant.recordDigest,
    customerGrantRevision: grant.revision,
    customerGrantRevocationRevision: grant.revocationRevision,
    auditEventId: crypto.randomUUID(),
    ...overrides,
  };
  const record = authenticate(authorities.integrity, CONSENT_DOMAIN, core);
  const audit = signedAudit(authorities.audit, stateAudit(record, 'diagnostic_consent_state', {
    customerId,
    deploymentId,
    referenceId: digest({
      kind: 'vendor_diagnostic_consent', customerId, deploymentId, channel: 'diagnostics',
    }),
  }));
  storage.data.consents.set(scopeKey(record), structuredClone(record));
  storage.data.audits.push(structuredClone(audit));
  return record;
}

function installGrantAndConsent(storage, authorities, customerId, deploymentId, nowMs) {
  const core = {
    schemaVersion: 1,
    recordType: 'customer_grant',
    channel: 'diagnostics',
    grantId: crypto.randomUUID(),
    customerId,
    deploymentId,
    enabled: true,
    revision: 1,
    revocationRevision: 0,
    issuedAt: new Date(nowMs - 1_000).toISOString(),
    expiresAt: new Date(NOW + 200 * DAY_MS).toISOString(),
    auditEventId: crypto.randomUUID(),
  };
  const grant = authenticate(authorities.customerGrant, CUSTOMER_GRANT_DOMAIN, core);
  const audit = signedAudit(authorities.audit, stateAudit(grant, 'diagnostic_customer_grant_state', {
    customerId,
    deploymentId,
    referenceId: digest({
      kind: 'vendor_diagnostic_consent', customerId, deploymentId, channel: 'diagnostics',
    }),
  }));
  storage.seedCustomerGrant(grant, audit);
  return installConsent(storage, authorities, customerId, deploymentId, nowMs);
}

function withoutPrincipal(value) {
  const copy = { ...value };
  delete copy.principal;
  return copy;
}

function capabilityScope(principal, purpose) {
  if (purpose === 'diagnostic:ingest') {
    return principal.principalId === CONNECTOR_B.principalId
      ? { customerIds: [CUSTOMER_B], deploymentId: DEPLOYMENT_B }
      : { customerIds: [CUSTOMER_A], deploymentId: DEPLOYMENT_A };
  }
  if (purpose === 'diagnostics:compact:global') {
    return { customerIds: '*', deploymentId: null };
  }
  if (purpose === 'diagnostics:clock:recover') {
    return { customerIds: '*', deploymentId: null };
  }
  return { customerIds: [CUSTOMER_A], deploymentId: null };
}

function diagnostic(harness, customerId = CUSTOMER_A, deploymentId = DEPLOYMENT_A, overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: crypto.randomUUID(),
    customerId,
    deploymentId,
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
    componentVersion: '1.2.3',
    occurredAt: new Date(harness.now()).toISOString(),
    ...overrides,
  };
}

function ingestCommand(harness, payload, capability) {
  return {
    capability: capability || harness.capability('diagnostic:ingest'),
    payload,
  };
}

function searchCommand(harness, mode = 'view', overrides = {}) {
  const purpose = mode === 'export' ? 'diagnostics:export' : 'diagnostics:view';
  return {
    capability: harness.capability(purpose, { customerIds: [CUSTOMER_A, CUSTOMER_B] }),
    cursor: null,
    filters: {},
    limit: 100,
    mode,
    ...overrides,
  };
}

function compactCommand(harness, global = false, overrides = {}) {
  return {
    capability: harness.capability(
      global ? 'diagnostics:compact:global' : 'diagnostics:compact',
    ),
    limit: 100,
    ...overrides,
  };
}

async function expectRejected(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.message, GENERIC_ERROR);
    if (code) assert.equal(error.code, code);
    assert.doesNotMatch(error.message, /CANARY|123-45-6789|storage/i);
    return true;
  });
}

test('connected diagnostics ingest uses signed current authority, consent, time, quota, and replay-safe claims', async () => {
  const harness = createHarness();
  const payload = diagnostic(harness);
  const result = await harness.intelligence.ingest(ingestCommand(harness, payload));

  assert.deepEqual(result, {
    messageId: payload.messageId,
    payloadDigest: protocol.payloadDigest(payload, payload.kind),
    receivedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + DAY_MS).toISOString(),
    state: 'retained',
    duplicate: false,
  });
  const [record] = harness.storage.records();
  assert.equal(record.recordType, 'event');
  assert.deepEqual(record.payload, payload);
  assert.equal(record.authorizationPrincipalId, CONNECTOR_A.principalId);
  assert.equal(record.consentRevision, 1);
  assert.equal(harness.storage.data.time.recordType, 'time_state');
  assert.equal([...harness.storage.data.quotas.values()][0].count, 1);
  for (const action of [
    'diagnostic_clock_advanced', 'diagnostic_capability_used',
    'diagnostic_quota_claimed', 'diagnostic_ingested',
  ]) assert.equal(harness.storage.audits(action).length, 1);

  const duplicate = await harness.intelligence.ingest(ingestCommand(harness, payload));
  assert.equal(duplicate.duplicate, true);
  assert.equal([...harness.storage.data.quotas.values()][0].count, 1);

  const before = harness.storage.snapshot();
  await expectRejected(harness.intelligence.ingest({
    capability: harness.capability('diagnostic:ingest'),
    connectorAuthEventId: crypto.randomUUID(),
    payload: diagnostic(harness),
  }), 'diagnostic_command_invalid');
  assert.equal(harness.storage.snapshot(), before);
});

test('descriptor-only bounded snapshots never invoke raw getters and dependency failures stay generic', async () => {
  const harness = createHarness();
  let getterCalls = 0;
  const accessorPayload = diagnostic(harness);
  Object.defineProperty(accessorPayload, 'prompt', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'CANARY-RAW-PROMPT-123-45-6789';
    },
  });
  const callsBefore = harness.storage.transactionCalls;
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, accessorPayload)),
    'diagnostic_command_invalid',
  );
  assert.equal(getterCalls, 0);
  assert.equal(harness.storage.transactionCalls, callsBefore);

  let proxyGets = 0;
  const proxied = new Proxy(diagnostic(harness), {
    get() {
      proxyGets += 1;
      throw new Error('CANARY-PROXY-RAW-123-45-6789');
    },
  });
  const proxyResult = await harness.intelligence.ingest(ingestCommand(harness, proxied));
  assert.equal(proxyResult.state, 'retained');
  assert.equal(proxyGets, 0);

  const huge = diagnostic(harness, CUSTOMER_A, DEPLOYMENT_A, {
    componentVersion: `1.${'9'.repeat(MAX_DOCUMENT_BYTES + 1)}.3`,
  });
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, huge)),
    'diagnostic_command_invalid',
  );

  const tooManyNodes = diagnostic(harness);
  tooManyNodes.untrusted = Array.from({ length: 5_001 }, () => null);
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, tooManyNodes)),
    'diagnostic_command_invalid',
  );

  const tooManyBytes = diagnostic(harness);
  tooManyBytes.untrusted = Array.from({ length: 40 }, () => 'x'.repeat(14_000));
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, tooManyBytes)),
    'diagnostic_command_invalid',
  );

  const deep = diagnostic(harness);
  let nested = {};
  for (let index = 0; index < 20; index += 1) nested = { nested };
  deep.untrusted = nested;
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, deep)),
    'diagnostic_command_invalid',
  );

  const rawHarness = createHarness();
  rawHarness.storage.setTransactionFault('raw');
  const before = rawHarness.storage.snapshot();
  await expectRejected(
    rawHarness.intelligence.ingest(ingestCommand(rawHarness, diagnostic(rawHarness))),
    'diagnostic_dependency_failed',
  );
  assert.equal(rawHarness.storage.snapshot(), before);
});

test('construction maps Owner diagnostic integrity and keeps every other authority distinct', () => {
  const valid = serviceConfiguration();
  assert.equal(valid.storage.contractVersion, STORAGE_CONTRACT_VERSION);
  assert.doesNotThrow(() => createVendorDiagnosticIntelligence(valid));
  assert.equal(valid.integrityAuthority.keyId.length, 88);

  const boundaryAuthorities = authorityBundle();
  boundaryAuthorities.access = hmacAuthority('diagnostic-access-boundary', {
    keyId: `a${'b'.repeat(95)}`,
  });
  assert.doesNotThrow(() => createVendorDiagnosticIntelligence(serviceConfiguration({
    authorities: boundaryAuthorities,
  })));

  const overlongAuthorities = authorityBundle();
  overlongAuthorities.integrity = hmacAuthority('diagnostic-integrity-overlong', {
    keyId: `r${'w'.repeat(95)}x`,
  });
  assert.throws(() => createVendorDiagnosticIntelligence(serviceConfiguration({
    authorities: overlongAuthorities,
  })), (error) => (
    error.message === GENERIC_ERROR && error.code === 'integrity_authority_invalid'
  ));

  const mappedMismatch = serviceConfiguration();
  mappedMismatch.authorityFingerprints.diagnostic_integrity = digest({
    authority: 'owner-diagnostic-integrity-mismatch',
  });
  assert.throws(() => createVendorDiagnosticIntelligence(mappedMismatch), (error) => (
    error.message === GENERIC_ERROR && error.code === 'authority_fingerprints_invalid'
  ));

  const collision = serviceConfiguration();
  collision.authorityFingerprints.platformAudit = collision.authorityFingerprints.diagnosticAccess;
  assert.throws(() => createVendorDiagnosticIntelligence(collision), (error) => (
    error.message === GENERIC_ERROR && error.code === 'authority_fingerprints_invalid'
  ));

  const alwaysTrue = serviceConfiguration();
  alwaysTrue.accessAuthority = {
    ...alwaysTrue.accessAuthority,
    verify: () => true,
  };
  assert.throws(() => createVendorDiagnosticIntelligence(alwaysTrue), (error) => (
    error.message === GENERIC_ERROR && error.code === 'integrity_authority_invalid'
  ));

  const ignoresKeyId = serviceConfiguration();
  const real = ignoresKeyId.accessAuthority;
  ignoresKeyId.accessAuthority = {
    ...real,
    verify(domain, message, proof) {
      return real.verify(domain, message, { ...proof, keyId: real.keyId });
    },
  };
  assert.throws(() => createVendorDiagnosticIntelligence(ignoresKeyId), (error) => (
    error.message === GENERIC_ERROR && error.code === 'integrity_authority_invalid'
  ));

  const ignoresDomain = serviceConfiguration();
  const key = crypto.randomBytes(32);
  const keyId = 'domain-blind-key';
  const fingerprint = crypto.createHash('sha256').update(key).digest('hex');
  ignoresDomain.accessAuthority = {
    keyId,
    fingerprint,
    sign(_domain, message) {
      return { keyId, mac: crypto.createHmac('sha256', key).update(message).digest('base64') };
    },
    verify(_domain, message, proof) {
      if (proof.keyId !== keyId) return false;
      return proof.mac === crypto.createHmac('sha256', key).update(message).digest('base64');
    },
  };
  ignoresDomain.authorityFingerprints.diagnosticAccess = fingerprint;
  assert.throws(() => createVendorDiagnosticIntelligence(ignoresDomain), (error) => (
    error.message === GENERIC_ERROR && error.code === 'integrity_authority_invalid'
  ));

  const wrongFingerprint = serviceConfiguration();
  wrongFingerprint.authorityFingerprints.diagnosticAccess = digest({ authority: 'wrong-key' });
  assert.throws(() => createVendorDiagnosticIntelligence(wrongFingerprint), (error) => (
    error.message === GENERIC_ERROR && error.code === 'integrity_authority_invalid'
  ));

  const poisonedDependency = serviceConfiguration();
  Object.defineProperty(poisonedDependency.accessAuthority, 'sign', {
    enumerable: true,
    get() { throw new Error('CANARY-CONSTRUCTION-123-45-6789'); },
  });
  assert.throws(() => createVendorDiagnosticIntelligence(poisonedDependency), (error) => (
    error.message === GENERIC_ERROR
      && error.code === 'diagnostic_dependency_failed'
      && !error.message.includes('CANARY')
  ));
});

test('reference intelligence refuses production with a preopened store and spoofed caller env', () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    const configuration = serviceConfiguration({ env: { NODE_ENV: 'test' } });
    configuration.storage = Object.freeze({
      contractVersion: STORAGE_CONTRACT_VERSION,
      productionReady: true,
      transaction: configuration.storage.transaction.bind(configuration.storage),
    });
    assert.throws(
      () => createVendorDiagnosticIntelligence(configuration),
      (error) => error.message === GENERIC_ERROR
        && error.code === 'vendor_diagnostic_reference_runtime_forbidden',
    );
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});

test('validated storage and authority methods are bound against later dependency substitution', async () => {
  const harness = createHarness();
  harness.storage.transaction = async () => {
    throw new Error('CANARY-SUBSTITUTED-STORAGE-123-45-6789');
  };
  harness.authorities.access.verify = () => true;
  harness.authorities.integrity.verify = () => true;
  const result = await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  assert.equal(result.state, 'retained');
  assert.equal(harness.storage.records().length, 1);
});

test('capabilities bind the current principal, purpose, one use, and latest signed authorization revision', async () => {
  const harness = createHarness();
  const payload = diagnostic(harness);
  const capability = harness.capability('diagnostic:ingest');
  harness.setPrincipal(VENDOR);
  const beforeMismatch = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, payload, capability)),
    'capability_principal_mismatch',
  );
  assert.equal(harness.storage.snapshot(), beforeMismatch);

  harness.setPrincipal(CONNECTOR_A);
  await harness.intelligence.ingest(ingestCommand(harness, payload, capability));
  const beforeReplay = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, payload, capability)),
    'capability_replayed',
  );
  assert.equal(harness.storage.snapshot(), beforeReplay);

  const staleCapability = harness.capability('diagnostic:ingest');
  harness.replaceAuthorization(CONNECTOR_A, { revocationRevision: 1 });
  const beforeRevocation = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness), staleCapability)),
    'capability_revoked',
  );
  assert.equal(harness.storage.snapshot(), beforeRevocation);

  const viewCapability = harness.capability('diagnostics:view', {
    principal: VENDOR, customerIds: [CUSTOMER_A],
  });
  harness.setPrincipal(VENDOR);
  const beforePurpose = harness.storage.snapshot();
  await expectRejected(harness.intelligence.search({
    capability: viewCapability,
    cursor: null,
    filters: {},
    limit: 10,
    mode: 'export',
  }), 'capability_purpose_denied');
  assert.equal(harness.storage.snapshot(), beforePurpose);
});

test('vendor capability cannot self-assert Owner authentication or MFA with the access key', async () => {
  const harness = createHarness();
  harness.setPrincipal(VENDOR);
  const valid = harness.capability('diagnostics:export');
  const {
    integrityProof: ignoredProof,
    recordDigest: ignoredDigest,
    ...core
  } = structuredClone(valid);
  core.ownerAuthAssertion = {
    ...core.ownerAuthAssertion,
    mfaEventId: crypto.randomUUID(),
    recordDigest: digest({ forged: true }),
  };
  const forged = authenticate(harness.authorities.access, CAPABILITY_DOMAIN, core);
  await expectRejected(harness.intelligence.search({
    capability: forged,
    cursor: null,
    filters: {},
    limit: 10,
    mode: 'export',
  }), 'owner_auth_assertion_invalid');
});

test('latest signed authorization and consent audits reject stale, revoked, and tampered state', async () => {
  const staleAuth = createHarness();
  const oldAuthorization = structuredClone(
    staleAuth.storage.data.authorizations.get(CONNECTOR_A.principalId),
  );
  staleAuth.replaceAuthorization(CONNECTOR_A, { revocationRevision: 1 });
  staleAuth.storage.data.authorizations.set(CONNECTOR_A.principalId, oldAuthorization);
  const beforeAuth = staleAuth.storage.snapshot();
  await expectRejected(
    staleAuth.intelligence.ingest(ingestCommand(staleAuth, diagnostic(staleAuth))),
    'diagnostic_state_audit_invalid',
  );
  assert.equal(staleAuth.storage.snapshot(), beforeAuth);

  const revokedConsent = createHarness();
  revokedConsent.replaceConsent(CUSTOMER_A, DEPLOYMENT_A, {
    enabled: false,
    revocationRevision: 1,
  });
  const beforeConsent = revokedConsent.storage.snapshot();
  await expectRejected(
    revokedConsent.intelligence.ingest(ingestCommand(revokedConsent, diagnostic(revokedConsent))),
    'diagnostic_consent_invalid',
  );
  assert.equal(revokedConsent.storage.snapshot(), beforeConsent);

  const tamperedConsent = createHarness();
  const consentKey = scopeKey({ customerId: CUSTOMER_A, deploymentId: DEPLOYMENT_A });
  const changed = structuredClone(tamperedConsent.storage.data.consents.get(consentKey));
  changed.retentionDays = 90;
  tamperedConsent.storage.data.consents.set(consentKey, changed);
  const beforeTamper = tamperedConsent.storage.snapshot();
  await expectRejected(
    tamperedConsent.intelligence.ingest(ingestCommand(tamperedConsent, diagnostic(tamperedConsent))),
    'diagnostic_consent_invalid',
  );
  assert.equal(tamperedConsent.storage.snapshot(), beforeTamper);
});

test('trusted-now expiry is included in the query and rechecked after storage returns records', async () => {
  const harness = createHarness({ retentionDays: 1 });
  const payload = diagnostic(harness);
  await harness.intelligence.ingest(ingestCommand(harness, payload));
  const event = harness.storage.records()[0];
  harness.setNow(Date.parse(event.expiresAt) + 1);
  harness.setPrincipal(VENDOR);
  harness.storage.hooks.searchDiagnostics = ({ run }) => {
    run();
    return { items: [event] };
  };
  const before = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.search(searchCommand(harness)),
    'diagnostic_record_expired',
  );
  assert.equal(
    harness.storage.lastSearchQuery.expiresAfter,
    new Date(harness.now()).toISOString(),
  );
  assert.equal(harness.storage.snapshot(), before);
  assert.equal(harness.storage.audits('diagnostics_viewed').length, 0);
});

test('malformed filters and cursors fail before a transaction with stable public errors', async () => {
  const harness = createHarness();
  harness.setPrincipal(VENDOR);
  const calls = harness.storage.transactionCalls;
  await expectRejected(harness.intelligence.search(searchCommand(harness, 'view', {
    filters: null,
  })), 'diagnostic_query_invalid');
  await expectRejected(harness.intelligence.search(searchCommand(harness, 'view', {
    cursor: 12,
  })), 'diagnostic_query_invalid');
  assert.equal(harness.storage.transactionCalls, calls);
});

test('view and export audits bind ordered result digests and cursor while postvalidation enforces silo scope', async () => {
  const harness = createHarness();
  const payloadA = diagnostic(harness, CUSTOMER_A, DEPLOYMENT_A);
  await harness.intelligence.ingest(ingestCommand(harness, payloadA));
  harness.setPrincipal(CONNECTOR_B);
  const payloadB = diagnostic(harness, CUSTOMER_B, DEPLOYMENT_B);
  await harness.intelligence.ingest(ingestCommand(harness, payloadB));

  harness.setPrincipal(VENDOR);
  const view = await harness.intelligence.search(searchCommand(harness, 'view', {
    limit: 1,
  }));
  assert.equal(view.items.length, 1);
  assert.equal(typeof view.nextCursor, 'string');
  const ordered = harness.storage.records().sort((left, right) => (
    left.receivedAt.localeCompare(right.receivedAt)
      || left.messageId.localeCompare(right.messageId)
  ));
  const viewAudit = harness.storage.audits('diagnostics_viewed').at(-1);
  assert.equal(viewAudit.operationDigest, digest(harness.storage.lastSearchQuery));
  assert.equal(viewAudit.resultDigest, view.accessManifest.recordDigest);
  assert.deepEqual(view.accessManifest.pageCounts, [
    { customerId: CUSTOMER_A, count: ordered[0].customerId === CUSTOMER_A ? 1 : 0 },
    { customerId: CUSTOMER_B, count: ordered[0].customerId === CUSTOMER_B ? 1 : 0 },
  ]);
  assert.equal(view.accessManifest.pageItems.length, 1);
  assert.equal(view.accessManifest.pageItems[0].ordinal, 0);
  assert.equal(view.accessManifest.pageItems[0].recordDigest, ordered[0].recordDigest);
  assert.match(view.accessManifest.principalRef, /^[a-f0-9]{64}$/);
  assert.match(view.accessManifest.sessionRef, /^[a-f0-9]{64}$/);
  assert.equal(Object.hasOwn(view.accessManifest, 'principalId'), false);
  assert.equal(Object.hasOwn(view.accessManifest, 'sessionId'), false);
  assert.equal(canonical(view.accessManifest).includes(VENDOR.principalId), false);
  assert.equal(canonical(view.accessManifest).includes(VENDOR.sessionId), false);
  assert.equal(view.accessManifest.customerManifests.length, 2);
  assert.equal(view.accessManifest.customerManifests.some((item) => (
    item.pageResultCount === 0 && item.items.length === 0
  )), true);

  const exported = await harness.intelligence.search(searchCommand(harness, 'export', {
    filters: { customerId: CUSTOMER_A },
  }));
  assert.equal(exported.items.length, 1);
  const exportAudit = harness.storage.audits('diagnostics_exported').at(-1);
  assert.equal(exportAudit.resultDigest, exported.accessManifest.recordDigest);
  assert.deepEqual(exported.accessManifest.pageCounts, [{ customerId: CUSTOMER_A, count: 1 }]);

  const customerBRecord = ordered.find((record) => record.customerId === CUSTOMER_B);
  harness.storage.hooks.searchDiagnostics = () => ({ items: [customerBRecord] });
  const before = harness.storage.snapshot();
  await expectRejected(harness.intelligence.search(searchCommand(harness, 'view', {
    capability: harness.capability('diagnostics:view', { customerIds: [CUSTOMER_A] }),
  })), 'diagnostic_customer_scope_denied');
  assert.equal(harness.storage.snapshot(), before);
});

test('zero-result access emits an exact customer attempt manifest without staff identity', async () => {
  const harness = createHarness();
  harness.setPrincipal(VENDOR);
  await expectRejected(harness.intelligence.search(searchCommand(harness, 'view', {
    capability: harness.capability('diagnostics:view', { customerIds: '*' }),
  })), 'diagnostic_customer_scope_required');
  const result = await harness.intelligence.search(searchCommand(harness, 'view', {
    capability: harness.capability('diagnostics:view', { customerIds: [CUSTOMER_A] }),
    filters: { customerId: CUSTOMER_A },
  }));
  assert.deepEqual(result.items, []);
  assert.deepEqual(result.accessManifest.pageItems, []);
  assert.deepEqual(result.accessManifest.pageCounts, [{ customerId: CUSTOMER_A, count: 0 }]);
  assert.equal(result.accessManifest.customerManifests.length, 1);
  assert.equal(result.accessManifest.customerManifests[0].customerId, CUSTOMER_A);
  assert.equal(result.accessManifest.customerManifests[0].pageResultCount, 0);
  assert.deepEqual(result.accessManifest.customerManifests[0].items, []);
  assert.equal(canonical(result.accessManifest).includes(VENDOR.principalId), false);
  assert.equal(canonical(result.accessManifest).includes(VENDOR.sessionId), false);
});

test('scoped compaction cannot cross customers and global compaction requires scheduler authority', async () => {
  const harness = createHarness({ retentionDays: 1 });
  await harness.intelligence.ingest(ingestCommand(
    harness, diagnostic(harness, CUSTOMER_A, DEPLOYMENT_A),
  ));
  harness.setPrincipal(CONNECTOR_B);
  await harness.intelligence.ingest(ingestCommand(
    harness, diagnostic(harness, CUSTOMER_B, DEPLOYMENT_B),
  ));
  harness.setNow(NOW + DAY_MS + 1);
  harness.setPrincipal(VENDOR);

  const scoped = await harness.intelligence.compact(compactCommand(harness));
  assert.deepEqual(scoped, { compacted: 1, tombstonesDeleted: 0, replayIndexesDeleted: 0 });
  assert.equal(
    harness.storage.records().find((record) => record.customerId === CUSTOMER_A).recordType,
    'tombstone',
  );
  assert.equal(
    harness.storage.records().find((record) => record.customerId === CUSTOMER_B).recordType,
    'event',
  );
  assert.ok(harness.storage.lastCompactionQueries.every(({ query }) => (
    canonical(query.allowedCustomerIds) === canonical([CUSTOMER_A])
  )));

  const customerBRecord = harness.storage.records().find((record) => record.customerId === CUSTOMER_B);
  harness.storage.hooks.listExpiredDiagnostics = () => [customerBRecord];
  const beforeScopeAttack = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.compact(compactCommand(harness)),
    'diagnostic_customer_scope_denied',
  );
  assert.equal(harness.storage.snapshot(), beforeScopeAttack);
  delete harness.storage.hooks.listExpiredDiagnostics;

  const vendorWildcard = harness.capability('diagnostics:compact', { customerIds: '*' });
  const beforeVendorGlobal = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.compact({ capability: vendorWildcard, limit: 100 }),
    'capability_invalid',
  );
  assert.equal(harness.storage.snapshot(), beforeVendorGlobal);

  harness.setPrincipal(SCHEDULER);
  const global = await harness.intelligence.compact(compactCommand(harness, true));
  assert.equal(global.compacted, 1);
  assert.equal(
    harness.storage.records().find((record) => record.customerId === CUSTOMER_B).recordType,
    'tombstone',
  );
});

test('authenticated replay index preserves idempotency through the full horizon and then permits a fresh event', async () => {
  const harness = createHarness({ retentionDays: 1 });
  const original = diagnostic(harness);
  await harness.intelligence.ingest(ingestCommand(harness, original));
  let record = harness.storage.records()[0];

  harness.setNow(Date.parse(record.expiresAt));
  harness.setPrincipal(VENDOR);
  await harness.intelligence.compact(compactCommand(harness));
  record = harness.storage.records()[0];
  assert.equal(record.recordType, 'tombstone');

  harness.setNow(Date.parse(record.deleteAfter));
  await harness.intelligence.compact(compactCommand(harness));
  record = harness.storage.records()[0];
  assert.equal(record.recordType, 'replay');
  assert.equal(Date.parse(record.idempotencyUntil), NOW + IDEMPOTENCY_HORIZON_MS);

  harness.setPrincipal(CONNECTOR_A);
  const duplicate = await harness.intelligence.ingest(ingestCommand(harness, original));
  assert.deepEqual(duplicate, { accepted: true, duplicate: true });

  const changed = diagnostic(harness, CUSTOMER_A, DEPLOYMENT_A, {
    messageId: original.messageId,
    occurredAt: new Date(harness.now()).toISOString(),
    code: 'QUEUE_BACKLOG',
  });
  const beforeConflict = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, changed)),
    'diagnostic_idempotency_conflict',
  );
  assert.equal(harness.storage.snapshot(), beforeConflict);

  harness.setNow(Date.parse(record.idempotencyUntil));
  harness.setPrincipal(VENDOR);
  await harness.intelligence.recoverClock({
    capability: harness.capability('diagnostics:clock:recover'),
    reasonCode: 'operator_time_attestation',
  });
  const deleted = await harness.intelligence.compact(compactCommand(harness));
  assert.equal(deleted.replayIndexesDeleted, 1);
  assert.equal(harness.storage.records().length, 0);

  harness.setPrincipal(CONNECTOR_A);
  changed.occurredAt = new Date(harness.now()).toISOString();
  const fresh = await harness.intelligence.ingest(ingestCommand(harness, changed));
  assert.equal(fresh.duplicate, false);
  assert.equal(fresh.state, 'retained');
});

test('time and quota MAC, latest audit, exact audit return, and CAS failures roll back atomically', async () => {
  const timeTamper = createHarness();
  await timeTamper.intelligence.ingest(ingestCommand(timeTamper, diagnostic(timeTamper)));
  const changedTime = structuredClone(timeTamper.storage.data.time);
  changedTime.timeMs += 1;
  timeTamper.storage.data.time = changedTime;
  const beforeTime = timeTamper.storage.snapshot();
  await expectRejected(
    timeTamper.intelligence.ingest(ingestCommand(timeTamper, diagnostic(timeTamper))),
    'diagnostic_clock_integrity_failed',
  );
  assert.equal(timeTamper.storage.snapshot(), beforeTime);

  const staleTime = createHarness();
  await staleTime.intelligence.ingest(ingestCommand(staleTime, diagnostic(staleTime)));
  const oldSignedTime = structuredClone(staleTime.storage.data.time);
  staleTime.setNow(NOW + 1_000);
  staleTime.setPrincipal(VENDOR);
  await staleTime.intelligence.search(searchCommand(staleTime));
  staleTime.storage.data.time = oldSignedTime;
  staleTime.setPrincipal(CONNECTOR_A);
  const beforeStaleTime = staleTime.storage.snapshot();
  await expectRejected(
    staleTime.intelligence.ingest(ingestCommand(staleTime, diagnostic(staleTime))),
    'diagnostic_state_audit_invalid',
  );
  assert.equal(staleTime.storage.snapshot(), beforeStaleTime);

  const quotaTamper = createHarness();
  await quotaTamper.intelligence.ingest(ingestCommand(quotaTamper, diagnostic(quotaTamper)));
  const [key, quota] = [...quotaTamper.storage.data.quotas.entries()][0];
  const changedQuota = structuredClone(quota);
  changedQuota.count += 1;
  quotaTamper.storage.data.quotas.set(key, changedQuota);
  const beforeQuota = quotaTamper.storage.snapshot();
  await expectRejected(
    quotaTamper.intelligence.ingest(ingestCommand(quotaTamper, diagnostic(quotaTamper))),
    'diagnostic_quota_integrity_failed',
  );
  assert.equal(quotaTamper.storage.snapshot(), beforeQuota);

  const wrongQuotaScope = createHarness();
  await wrongQuotaScope.intelligence.ingest(ingestCommand(
    wrongQuotaScope, diagnostic(wrongQuotaScope),
  ));
  const signedQuotaA = structuredClone([...wrongQuotaScope.storage.data.quotas.values()][0]);
  const day = new Date(NOW).toISOString().slice(0, 10);
  wrongQuotaScope.storage.data.quotas.set(
    `${scopeKey({ customerId: CUSTOMER_B, deploymentId: DEPLOYMENT_B })}\0${day}`,
    signedQuotaA,
  );
  wrongQuotaScope.setPrincipal(CONNECTOR_B);
  const beforeWrongScope = wrongQuotaScope.storage.snapshot();
  await expectRejected(
    wrongQuotaScope.intelligence.ingest(ingestCommand(
      wrongQuotaScope, diagnostic(wrongQuotaScope, CUSTOMER_B, DEPLOYMENT_B),
    )),
    'diagnostic_quota_integrity_failed',
  );
  assert.equal(wrongQuotaScope.storage.snapshot(), beforeWrongScope);

  const exactAudit = createHarness();
  exactAudit.storage.hooks.appendAudit = ({ run }) => {
    const appended = run();
    return { ...appended, resultCount: appended.resultCount + 1 };
  };
  const beforeAudit = exactAudit.storage.snapshot();
  await expectRejected(
    exactAudit.intelligence.ingest(ingestCommand(exactAudit, diagnostic(exactAudit))),
    'diagnostic_audit_append_failed',
  );
  assert.equal(exactAudit.storage.snapshot(), beforeAudit);

  const quotaCas = createHarness();
  quotaCas.storage.hooks.compareAndSwapDiagnosticQuota = ({ run }) => {
    run();
    return null;
  };
  const beforeCas = quotaCas.storage.snapshot();
  await expectRejected(
    quotaCas.intelligence.ingest(ingestCommand(quotaCas, diagnostic(quotaCas))),
    'diagnostic_quota_conflict',
  );
  assert.equal(quotaCas.storage.snapshot(), beforeCas);
});

test('daily quota is enforced from a signed audit-anchored state', async () => {
  const harness = createHarness({ dailyEventLimit: 100 });
  const payload = diagnostic(harness);
  const day = new Date(NOW).toISOString().slice(0, 10);
  const core = {
    schemaVersion: 1,
    recordType: 'quota_state',
    customerId: CUSTOMER_A,
    deploymentId: DEPLOYMENT_A,
    day,
    count: 100,
    limit: 100,
    revision: 1,
    updatedAt: new Date(NOW).toISOString(),
    auditEventId: crypto.randomUUID(),
  };
  const quota = authenticate(harness.authorities.integrity, QUOTA_DOMAIN, core);
  harness.storage.data.quotas.set(`${scopeKey(payload)}\0${day}`, structuredClone(quota));
  harness.storage.data.audits.push(structuredClone(signedAudit(
    harness.authorities.audit,
    stateAudit(
    quota,
    'diagnostic_quota_claimed',
    {
      customerId: CUSTOMER_A,
      deploymentId: DEPLOYMENT_A,
      referenceId: quotaReference(CUSTOMER_A, DEPLOYMENT_A, day),
    },
  ))));
  const before = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, payload)),
    'diagnostic_rate_limited',
  );
  assert.equal(harness.storage.snapshot(), before);
});

test('transaction omission, double invocation, result substitution, and swallowed callback failure make zero durable changes', async () => {
  for (const fault of ['omit', 'double', 'substitute', 'swallowed-double']) {
    const harness = createHarness();
    harness.storage.setTransactionFault(fault);
    const before = harness.storage.snapshot();
    await expectRejected(
      harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness))),
      'storage_invalid',
    );
    assert.equal(harness.storage.snapshot(), before, fault);
  }
});

test('reference transactions serialize concurrent capabilities, quotas, and idempotency claims', async () => {
  const harness = createHarness();
  const first = diagnostic(harness);
  const second = diagnostic(harness);
  const results = await Promise.all([
    harness.intelligence.ingest(ingestCommand(harness, first)),
    harness.intelligence.ingest(ingestCommand(harness, second)),
  ]);
  assert.deepEqual(results.map((value) => value.duplicate), [false, false]);
  assert.equal(harness.storage.records().length, 2);
  assert.equal([...harness.storage.data.quotas.values()][0].count, 2);

  const same = diagnostic(harness);
  const duplicateResults = await Promise.all([
    harness.intelligence.ingest(ingestCommand(harness, same)),
    harness.intelligence.ingest(ingestCommand(harness, same)),
  ]);
  assert.deepEqual(duplicateResults.map((value) => value.duplicate).sort(), [false, true]);
  assert.equal(harness.storage.records().length, 3);
  assert.equal([...harness.storage.data.quotas.values()][0].count, 3);
});

test('compaction requires exact delete identity and rolls back an altered adapter result', async () => {
  const harness = createHarness({ retentionDays: 1 });
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  let record = harness.storage.records()[0];
  harness.setNow(Date.parse(record.expiresAt));
  harness.setPrincipal(VENDOR);
  await harness.intelligence.compact(compactCommand(harness));
  record = harness.storage.records()[0];
  harness.setNow(Date.parse(record.deleteAfter));
  await harness.intelligence.compact(compactCommand(harness));
  record = harness.storage.records()[0];
  harness.setNow(Date.parse(record.idempotencyUntil));
  await harness.intelligence.recoverClock({
    capability: harness.capability('diagnostics:clock:recover'),
    reasonCode: 'operator_time_attestation',
  });
  harness.storage.hooks.deleteDiagnosticReplayIndex = ({ run }) => {
    const removed = run();
    return { ...removed, messageId: crypto.randomUUID() };
  };
  const before = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.compact(compactCommand(harness)),
    'compaction_conflict',
  );
  assert.equal(harness.storage.snapshot(), before);
});

test('deleted capability claims remain unusable from signed audit evidence after service reconstruction', async () => {
  const harness = createHarness();
  const payload = diagnostic(harness);
  const capability = harness.capability('diagnostic:ingest');
  await harness.intelligence.ingest(ingestCommand(harness, payload, capability));
  harness.storage.data.capabilityClaims.delete(capability.capabilityId);
  const reconstructed = createVendorDiagnosticIntelligence({
    storage: harness.storage,
    integrityAuthority: harness.authorities.integrity,
    accessAuthority: harness.authorities.access,
    auditAuthority: harness.authorities.audit,
    customerGrantAuthority: harness.authorities.customerGrant,
    cursorAuthority: harness.authorities.cursor,
    ownerAuthAuthority: harness.authorities.ownerAuth,
    deletionIntentKeyRegistry: harness.deletionKeys.registry,
    authorityFingerprints: harness.fingerprints,
    currentPrincipal: () => CONNECTOR_A,
  });
  const before = harness.storage.snapshot();
  await expectRejected(
    reconstructed.ingest(ingestCommand(harness, payload, capability)),
    'capability_claim_missing',
  );
  assert.equal(harness.storage.snapshot(), before);
});

test('stable customer scope high-water rejects a consent ID replacement that rolls revision back', async () => {
  const harness = createHarness();
  harness.replaceConsent(CUSTOMER_A, DEPLOYMENT_A, {
    consentId: crypto.randomUUID(),
    revision: 2,
  });
  installConsent(
    harness.storage, harness.authorities, CUSTOMER_A, DEPLOYMENT_A, harness.now(),
    { consentId: crypto.randomUUID(), revision: 1 }, true,
  );
  const before = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness))),
    'diagnostic_state_revision_rollback',
  );
  assert.equal(harness.storage.snapshot(), before);
});

test('MACed keyset cursor freezes the export snapshot and emits completion evidence', async () => {
  const harness = createHarness();
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  harness.setPrincipal(VENDOR);
  const first = await harness.intelligence.search(searchCommand(harness, 'export', { limit: 1 }));
  assert.equal(first.items.length, 1);
  assert.equal(typeof first.nextCursor, 'string');
  assert.equal(first.accessManifest.pageNumber, 1);
  assert.equal(first.accessManifest.cumulativeResultCount, 1);
  assert.equal(first.accessManifest.completed, false);
  assert.equal(first.accessManifest.supportCaseId, EXPORT_SUPPORT_CASE);
  assert.equal(first.accessManifest.approvalId, EXPORT_APPROVAL);

  harness.setPrincipal(CONNECTOR_A);
  const afterSnapshot = diagnostic(harness);
  await harness.intelligence.ingest(ingestCommand(harness, afterSnapshot));
  harness.setPrincipal(VENDOR);
  const secondCommand = searchCommand(harness, 'export', {
    cursor: first.nextCursor,
    limit: 100,
  });
  const second = await harness.intelligence.search(secondCommand);
  assert.equal(second.items.length, 1);
  assert.equal(second.nextCursor, null);
  assert.equal(second.accessManifest.pageNumber, 2);
  assert.equal(second.accessManifest.cumulativeResultCount, 2);
  assert.equal(second.accessManifest.completed, true);
  assert.equal(second.accessManifest.priorManifestDigest, first.accessManifest.recordDigest);
  assert.equal(second.items.some((item) => item.payload.messageId === afterSnapshot.messageId), false);
  const completion = harness.storage.audits('diagnostics_export_completed');
  assert.equal(completion.length, 1);
  assert.equal(completion[0].resultCount, 2);
  assert.equal(completion[0].resultDigest, second.accessManifest.recordDigest);
  assert.equal(second.accessManifest.customerManifests.length, 2);
  assert.equal(second.accessManifest.customerManifests.every((item) => (
    item.pageAuditEventId === second.accessManifest.pageAuditEventId
  )), true);
  assert.equal(harness.storage.data.accessEvidence.size, 2);

  for (const evidence of harness.storage.data.accessEvidence.values()) {
    assert.equal(Object.hasOwn(evidence, 'response'), false);
    assert.match(evidence.responseDigest, /^[a-f0-9]{64}$/);
    assert.equal(canonical(evidence).includes('CONNECTOR_TIMEOUT'), false);
    assert.equal(canonical(evidence).includes('"payload"'), false);
  }

  const replayed = await harness.intelligence.search(secondCommand);
  assert.deepEqual(replayed, second);
  assert.equal(harness.storage.audits('diagnostic_access_replayed').length, 1);

  for (const [key, record] of harness.storage.data.claims) {
    if (record.recordType === 'event') harness.storage.data.claims.delete(key);
  }
  const reconstructed = createVendorDiagnosticIntelligence({
    storage: harness.storage,
    integrityAuthority: harness.authorities.integrity,
    accessAuthority: harness.authorities.access,
    auditAuthority: harness.authorities.audit,
    customerGrantAuthority: harness.authorities.customerGrant,
    cursorAuthority: harness.authorities.cursor,
    ownerAuthAuthority: harness.authorities.ownerAuth,
    deletionIntentKeyRegistry: harness.deletionKeys.registry,
    authorityFingerprints: harness.fingerprints,
    currentPrincipal: () => VENDOR,
  });
  await expectRejected(
    reconstructed.search(secondCommand), 'diagnostic_access_evidence_invalid',
  );
  assert.equal(harness.storage.audits('diagnostic_access_replayed').length, 1);

  const changed = `${first.nextCursor.slice(0, -1)}${first.nextCursor.endsWith('A') ? 'B' : 'A'}`;
  const before = harness.storage.snapshot();
  await expectRejected(harness.intelligence.search(searchCommand(harness, 'export', {
    cursor: changed,
  })), 'diagnostic_cursor_invalid');
  assert.equal(harness.storage.snapshot(), before);
});

test('destructive forward jumps require an audited stepped-up clock recovery', async () => {
  const harness = createHarness({ retentionDays: 1 });
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  harness.setNow(NOW + 8 * DAY_MS);
  harness.setPrincipal(VENDOR);
  const before = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.compact(compactCommand(harness)),
    'diagnostic_clock_recovery_required',
  );
  assert.equal(harness.storage.snapshot(), before);
  const recovered = await harness.intelligence.recoverClock({
    capability: harness.capability('diagnostics:clock:recover'),
    reasonCode: 'database_clock_corrected',
  });
  assert.equal(recovered.recovered, true);
  assert.equal(harness.storage.audits('diagnostic_clock_recovered').length, 1);
  const compacted = await harness.intelligence.compact(compactCommand(harness));
  assert.equal(compacted.compacted, 1);

  harness.setNow(NOW);
  const rollbackBefore = harness.storage.snapshot();
  await expectRejected(
    harness.intelligence.search(searchCommand(harness)),
    'diagnostic_clock_rollback',
  );
  assert.equal(harness.storage.snapshot(), rollbackBefore);
});

test('one active deletion intent reserves a scope and compaction cannot interleave across batches', async () => {
  const harness = createHarness({ retentionDays: 1 });
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  harness.setNow(NOW + 2 * DAY_MS);
  harness.setPrincipal(VENDOR);
  await harness.intelligence.recoverClock({
    capability: harness.capability('diagnostics:clock:recover'),
    reasonCode: 'operator_time_attestation',
  });
  const firstIntent = customerDeletionIntent(harness);
  await harness.intelligence.submitDeletionIntent({ intent: firstIntent });
  await expectRejected(
    harness.intelligence.submitDeletionIntent({ intent: customerDeletionIntent(harness) }),
    'diagnostic_deletion_scope_reserved',
  );
  const supportCaseId = crypto.randomUUID();
  const approvalId = crypto.randomUUID();
  await harness.intelligence.previewDeletion({
    capability: harness.capability('diagnostics:delete:preview', { supportCaseId }),
    jobId: firstIntent.intentId,
  });
  await harness.intelligence.approveDeletion({
    capability: harness.capability('diagnostics:delete:approve', {
      supportCaseId, approvalId,
    }),
    jobId: firstIntent.intentId,
  });
  const partial = await harness.intelligence.executeDeletion({
    capability: harness.capability('diagnostics:delete:execute', {
      supportCaseId, approvalId,
    }),
    jobId: firstIntent.intentId,
    limit: 1,
  });
  assert.equal(partial.status, 'running');
  assert.deepEqual(await harness.intelligence.compact(compactCommand(harness)), {
    compacted: 0, tombstonesDeleted: 0, replayIndexesDeleted: 0,
  });
  const complete = await harness.intelligence.executeDeletion({
    capability: harness.capability('diagnostics:delete:execute', {
      supportCaseId, approvalId,
    }),
    jobId: firstIntent.intentId,
    limit: 10,
  });
  assert.equal(complete.status, 'completed');
  const nextIntent = customerDeletionIntent(harness);
  assert.deepEqual(await harness.intelligence.submitDeletionIntent({ intent: nextIntent }), {
    accepted: true, jobId: nextIntent.intentId,
  });
});

test('bounded deletion leases expire with audited release so compaction can resume', async () => {
  const harness = createHarness({ retentionDays: 1 });
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  const intent = customerDeletionIntent(harness);
  await harness.intelligence.submitDeletionIntent({ intent });

  const reservationKey = scopeKey({ customerId: CUSTOMER_A, deploymentId: DEPLOYMENT_A });
  const reserved = harness.storage.data.deletionReservations.get(reservationKey);
  assert.equal(reserved.active, true);
  assert.equal(
    Date.parse(reserved.leaseExpiresAt) - Date.parse(reserved.updatedAt),
    15 * 60 * 1000,
  );

  harness.setNow(NOW + DAY_MS + 1);
  harness.setPrincipal(VENDOR);
  assert.deepEqual(await harness.intelligence.compact(compactCommand(harness)), {
    compacted: 1, tombstonesDeleted: 0, replayIndexesDeleted: 0,
  });

  const released = harness.storage.data.deletionReservations.get(reservationKey);
  const job = harness.storage.data.deletionJobs.get(intent.intentId);
  assert.equal(released.active, false);
  assert.equal(released.leaseExpiresAt, null);
  assert.equal(released.releaseReason, 'expired');
  assert.equal(job.status, 'expired');
  assert.equal(job.terminalReasonCode, 'lease_expired');
  const releaseAudits = harness.storage.audits('diagnostic_deletion_reservation_released');
  assert.equal(releaseAudits.length, 1);
  assert.equal(releaseAudits[0].referenceId, intent.intentId);
  assert.equal(releaseAudits[0].operationDigest, reserved.recordDigest);
  assert.equal(releaseAudits[0].resultDigest, released.recordDigest);
});

test('vendor terminal deletion states release the scope through audited CAS', async () => {
  const harness = createHarness();
  for (const status of ['rejected', 'canceled', 'failed']) {
    const intent = customerDeletionIntent(harness);
    await harness.intelligence.submitDeletionIntent({ intent });
    harness.setPrincipal(VENDOR);
    const result = await harness.intelligence.terminateDeletion({
      capability: harness.capability('diagnostics:delete:approve'),
      jobId: intent.intentId,
      status,
    });
    assert.equal(result.status, status);
    const reservation = harness.storage.data.deletionReservations.get(scopeKey({
      customerId: CUSTOMER_A, deploymentId: DEPLOYMENT_A,
    }));
    const job = harness.storage.data.deletionJobs.get(intent.intentId);
    assert.equal(reservation.active, false);
    assert.equal(reservation.releaseReason, status);
    assert.equal(job.terminalReasonCode, `vendor_${status}`);
    harness.setPrincipal(CONNECTOR_A);
  }
  assert.equal(
    harness.storage.audits('diagnostic_deletion_reservation_released').length, 3,
  );
});

test('governed deletion is customer-authenticated, previewed, approved, batched, resumable, and acknowledged', async () => {
  const harness = createHarness();
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  await harness.intelligence.ingest(ingestCommand(harness, diagnostic(harness)));
  const grant = harness.storage.data.customerGrants.get(scopeKey({
    customerId: CUSTOMER_A, deploymentId: DEPLOYMENT_A,
  }));
  const intentCore = {
    schemaVersion: 1,
    recordType: 'deletion_intent',
    intentId: crypto.randomUUID(),
    customerId: CUSTOMER_A,
    deploymentId: DEPLOYMENT_A,
    channel: 'diagnostics',
    customerGrantId: grant.grantId,
    customerGrantDigest: grant.recordDigest,
    customerGrantRevision: grant.revision,
    scopeRevision: grant.revision,
    subjectDigest: digest({ subject: 'customer-privacy-officer' }),
    reasonCode: 'privacy_request',
    issuedAt: new Date(harness.now()).toISOString(),
    expiresAt: new Date(harness.now() + 60 * 60 * 1000).toISOString(),
  };
  const intent = signDeletionIntent(harness.deletionKeys, intentCore);
  const receipt = await harness.intelligence.submitDeletionIntent({ intent });
  assert.deepEqual(receipt, { accepted: true, jobId: intentCore.intentId });

  harness.setPrincipal(VENDOR);
  const supportCaseId = crypto.randomUUID();
  const approvalId = crypto.randomUUID();
  const preview = await harness.intelligence.previewDeletion({
    capability: harness.capability('diagnostics:delete:preview', { supportCaseId }),
    jobId: intentCore.intentId,
  });
  assert.equal(preview.count, 2);
  await harness.intelligence.approveDeletion({
    capability: harness.capability('diagnostics:delete:approve', {
      approvalId, supportCaseId,
    }),
    jobId: intentCore.intentId,
  });
  const first = await harness.intelligence.executeDeletion({
    capability: harness.capability('diagnostics:delete:execute', {
      approvalId, supportCaseId,
    }),
    jobId: intentCore.intentId,
    limit: 1,
  });
  assert.equal(first.status, 'running');
  assert.equal(first.nextBatchRequired, true);
  assert.equal(harness.storage.records().length, 1);
  const completed = await harness.intelligence.executeDeletion({
    capability: harness.capability('diagnostics:delete:execute', {
      approvalId, supportCaseId,
    }),
    jobId: intentCore.intentId,
    limit: 1,
  });
  assert.equal(completed.status, 'completed');
  assert.equal(completed.deletedCount, 2);
  assert.equal(completed.completion.recordType, 'deletion_completion');
  assert.equal(harness.storage.records().length, 0);
  assert.equal(harness.storage.audits('diagnostic_deletion_batch').length, 2);
  assert.equal(harness.storage.audits('diagnostic_deletion_completed').length, 1);

  const beforeRetry = harness.storage.snapshot();
  await expectRejected(harness.intelligence.executeDeletion({
    capability: harness.capability('diagnostics:delete:execute', {
      approvalId, supportCaseId,
    }),
    jobId: intentCore.intentId,
    limit: 1,
  }), 'diagnostic_deletion_state_invalid');
  assert.equal(harness.storage.snapshot(), beforeRetry);
});
