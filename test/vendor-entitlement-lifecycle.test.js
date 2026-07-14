'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const protocol = require('../server/vendor-control-protocol');
const connectedState = require('../server/connected-entitlement-state');
const { keyFingerprint } = require('../server/vendor-signed-artifact');
const {
  ACTIONS,
  AUTHORITY_MANIFEST_VERSION,
  AUTHORITY_PURPOSES,
  CREDENTIAL_PURPOSES,
  INTEGRITY_PURPOSE,
  OWNER_ATTESTATION_PURPOSE,
  OWNER_ATTESTATION_SIGNATURE_DOMAIN,
  TARGET_CONFIRMATION_PURPOSE,
  WITNESS_PURPOSE,
  createVendorEntitlementLifecycle,
} = require('../server/vendor-entitlement-lifecycle');

const NOW = Date.parse('2026-07-13T15:00:00.000Z');
const CUSTOMER_ID = 'customer_lifecycle';
const DEPLOYMENT_ID = 'dep_44444444444444444444444444444444';
const OTHER_CUSTOMER_ID = 'customer_other';
const OTHER_DEPLOYMENT_ID = 'dep_55555555555555555555555555555555';
const IDEMPOTENCY_KEY = 'entitlement-change-00000001';
const signingKeys = crypto.generateKeyPairSync('ed25519');
const nextSigningKeys = crypto.generateKeyPairSync('ed25519');
const ownerAttestationKeys = crypto.generateKeyPairSync('ed25519');
const SIGNING_KEY_ID = `rw-entitlement-${keyFingerprint(signingKeys.publicKey)}`;
const NEXT_SIGNING_KEY_ID = `rw-entitlement-${keyFingerprint(nextSigningKeys.publicKey)}`;

const PUBLIC_KEYRINGS = Object.freeze({
  [AUTHORITY_PURPOSES.OFFLINE_LICENSE]: keyringSpec('rw-offline-license-current'),
  [AUTHORITY_PURPOSES.ONLINE_VERDICT]: keyringSpec('rw-online-verdict-current'),
  [AUTHORITY_PURPOSES.ENTITLEMENT]: Object.freeze([
    publicIdentity('current', SIGNING_KEY_ID, signingKeys),
    publicIdentity('next', NEXT_SIGNING_KEY_ID, nextSigningKeys),
  ]),
  [AUTHORITY_PURPOSES.AUDIT_REQUEST]: keyringSpec(
    'rw-audit-request-current', 'rw-audit-request-next',
  ),
  [AUTHORITY_PURPOSES.POLICY]: keyringSpec('rw-policy-current', 'rw-policy-next'),
  [AUTHORITY_PURPOSES.CATALOG_GLOBAL]: keyringSpec(
    'rw-catalog-global-current', 'rw-catalog-global-next',
  ),
  [AUTHORITY_PURPOSES.CATALOG_DISTRIBUTION]: keyringSpec(
    'rw-catalog-distribution-current', 'rw-catalog-distribution-next',
  ),
  [AUTHORITY_PURPOSES.OWNER_ATTESTATION]: Object.freeze([
    publicIdentity('current', 'rw-owner-attestation-current', ownerAttestationKeys),
  ]),
});

const TEST_AUTHORITY_DEFINITIONS = Object.freeze({
  [AUTHORITY_PURPOSES.OFFLINE_LICENSE]: 'ed25519_public',
  [AUTHORITY_PURPOSES.ONLINE_VERDICT]: 'ed25519_public',
  [AUTHORITY_PURPOSES.ENTITLEMENT]: 'ed25519_public',
  [AUTHORITY_PURPOSES.PLATFORM_AUDIT]: 'hmac_secret',
  [AUTHORITY_PURPOSES.RECOVERY]: 'hmac_secret',
  [AUTHORITY_PURPOSES.LICENSE_REGISTRY_INTEGRITY]: 'hmac_secret',
  [AUTHORITY_PURPOSES.COMMAND_IDEMPOTENCY]: 'hmac_secret',
  [AUTHORITY_PURPOSES.PAGINATION_CURSOR]: 'hmac_secret',
  [AUTHORITY_PURPOSES.DIAGNOSTIC_INTEGRITY]: 'hmac_secret',
  [AUTHORITY_PURPOSES.AUDIT_REQUEST]: 'ed25519_public',
  [AUTHORITY_PURPOSES.POLICY]: 'ed25519_public',
  [AUTHORITY_PURPOSES.LIFECYCLE_INTEGRITY]: 'hmac_secret',
  [AUTHORITY_PURPOSES.CATALOG_GLOBAL]: 'ed25519_public',
  [AUTHORITY_PURPOSES.CATALOG_DISTRIBUTION]: 'ed25519_public',
  [AUTHORITY_PURPOSES.OWNER_ATTESTATION]: 'ed25519_public',
  [AUTHORITY_PURPOSES.WITNESS_INTEGRITY]: 'hmac_secret',
  [AUTHORITY_PURPOSES.HEARTBEAT_CREDENTIAL]: 'opaque_credential',
  [AUTHORITY_PURPOSES.ACKNOWLEDGEMENT_CREDENTIAL]: 'opaque_credential',
  [AUTHORITY_PURPOSES.DIAGNOSTIC_CREDENTIAL]: 'opaque_credential',
  [AUTHORITY_PURPOSES.SHADOW_CANDIDATE_CREDENTIAL]: 'opaque_credential',
});

function createHarness(options = {}) {
  const db = options.db || new DurableLifecycleDb();
  const witness = options.witness || new DurableWitnessStore();
  const clock = options.clock || { nowMs: NOW };
  const currentKey = options.currentKey || crypto.randomBytes(32);
  const currentKeyId = options.currentKeyId || 'rw-lifecycle-current';
  const integrityKeyring = options.integrityKeyring || lifecycleKeyring(
    currentKeyId, currentKey, options.retiredVerifyOnly,
  );
  const authorityManifestValue = options.authorityManifest || authorityManifest(
    integrityKeyring.current.keyId, integrityKeyring.current.key, witness,
  );
  const ownerAuditVerifier = options.ownerAuditVerifier
    || createOwnerAuditVerifier(db, authorityManifestValue);
  const lifecycle = createVendorEntitlementLifecycle({
    storage: db,
    witness,
    integrityKeyring,
    authorityManifest: authorityManifestValue,
    ownerAuditVerifier,
    randomUUID: options.randomUUID,
    now: () => clock.nowMs,
  });
  return {
    db, witness, clock, lifecycle, integrityKeyring, currentKey,
    authorityManifest: authorityManifestValue, ownerAuditVerifier,
  };
}

function recreate(harness, options = {}) {
  const integrityKeyring = options.integrityKeyring || harness.integrityKeyring;
  const witness = options.witness || harness.witness;
  const authorityManifestValue = options.authorityManifest
    || (options.integrityKeyring || options.witness
      ? authorityManifest(integrityKeyring.current.keyId, integrityKeyring.current.key, witness)
      : harness.authorityManifest);
  return createHarness({
    db: harness.db,
    witness,
    clock: harness.clock,
    integrityKeyring,
    authorityManifest: authorityManifestValue,
    ownerAuditVerifier: options.ownerAuditVerifier,
  });
}

function lifecycleKeyring(keyId, key, retiredVerifyOnly = {}) {
  return {
    purpose: INTEGRITY_PURPOSE,
    version: 1,
    current: { keyId, key },
    retiredVerifyOnly,
  };
}

function authorityManifest(lifecycleKeyId, lifecycleKey, witness, overrides = {}) {
  const authorities = {};
  for (const [purpose, identityType] of Object.entries(TEST_AUTHORITY_DEFINITIONS)) {
    const identities = PUBLIC_KEYRINGS[purpose]
      ? clone(PUBLIC_KEYRINGS[purpose])
      : [{
        slot: 'current', keyId: authorityKeyId(purpose),
        identity: sha256('authority:' + purpose),
      }];
    authorities[purpose] = { purpose, identityType, identities };
  }
  authorities[AUTHORITY_PURPOSES.LIFECYCLE_INTEGRITY].identities = [{
    slot: 'current', keyId: lifecycleKeyId, identity: sha256Buffer(lifecycleKey),
  }];
  const witnessIdentity = witness.identity().current;
  authorities[AUTHORITY_PURPOSES.WITNESS_INTEGRITY].identities = [{
    slot: 'current', keyId: witnessIdentity.keyId, identity: witnessIdentity.keyFingerprint,
  }];
  for (const [purpose, value] of Object.entries(overrides)) authorities[purpose] = clone(value);
  return { schemaVersion: AUTHORITY_MANIFEST_VERSION, authorities };
}

function keyringSpec(currentKeyId, nextKeyId = null) {
  const current = publicIdentity(
    'current', currentKeyId, crypto.generateKeyPairSync('ed25519'),
  );
  if (!nextKeyId) return Object.freeze([current]);
  return Object.freeze([
    current,
    publicIdentity('next', nextKeyId, crypto.generateKeyPairSync('ed25519')),
  ]);
}

function publicIdentity(slot, keyId, keys) {
  return Object.freeze({
    slot,
    keyId,
    identity: keyFingerprint(keys.publicKey),
    publicKeySpki: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  });
}

function authorityKeyId(purpose) {
  const prefixes = {
    [AUTHORITY_PURPOSES.PLATFORM_AUDIT]: 'rw-platform-audit-',
    [AUTHORITY_PURPOSES.RECOVERY]: 'rw-recovery-',
    [AUTHORITY_PURPOSES.LICENSE_REGISTRY_INTEGRITY]: 'rw-license-registry-integrity-',
    [AUTHORITY_PURPOSES.COMMAND_IDEMPOTENCY]: 'rw-command-idempotency-',
    [AUTHORITY_PURPOSES.PAGINATION_CURSOR]: 'rw-pagination-cursor-',
    [AUTHORITY_PURPOSES.DIAGNOSTIC_INTEGRITY]: 'rw-diagnostic-integrity-',
    [AUTHORITY_PURPOSES.LIFECYCLE_INTEGRITY]: 'rw-lifecycle-',
    [AUTHORITY_PURPOSES.WITNESS_INTEGRITY]: 'rw-lifecycle-witness-',
    [AUTHORITY_PURPOSES.HEARTBEAT_CREDENTIAL]: 'rw-heartbeat-credential-',
    [AUTHORITY_PURPOSES.ACKNOWLEDGEMENT_CREDENTIAL]: 'rw-ack-credential-',
    [AUTHORITY_PURPOSES.DIAGNOSTIC_CREDENTIAL]: 'rw-diagnostic-credential-',
    [AUTHORITY_PURPOSES.SHADOW_CANDIDATE_CREDENTIAL]: 'rw-shadow-candidate-credential-',
  };
  return prefixes[purpose] + 'current';
}

function currentAuthority(manifest, purpose) {
  const authority = manifest.authorities[purpose];
  const identity = authority.identities.find((value) => value.slot === 'current');
  return { purpose, keyId: identity.keyId, identity: identity.identity };
}

function createOwnerAuditVerifier(db, manifest) {
  const identity = currentAuthority(manifest, AUTHORITY_PURPOSES.PLATFORM_AUDIT);
  return {
    identity: () => clone(identity),
    verifyHistoryEvent: async (evidence) => canonicalEqual(
      db.ownerHistoryEvents.get(evidence.historyEventId) || null, evidence,
    ),
  };
}

function entitlement(overrides = {}) {
  const status = overrides.status || 'active';
  const base = {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status,
    plan: 'enterprise',
    seats: 40,
    features: ['catalog', 'policy'],
    entitlementVersion: 1,
    previousVersion: 0,
    issuedAt: iso(NOW - 1_000),
    expiresAt: iso(NOW + 5 * 60_000),
    fallbackUntil: status === 'active'
      ? iso(NOW + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000) : null,
    reasonCode: status === 'active' ? 'billing_active' : 'manual_pause',
  };
  return { ...base, ...overrides };
}

function signed(payload, keyId = SIGNING_KEY_ID, privateKey = signingKeys.privateKey) {
  return {
    keyId,
    payload,
    signature: crypto.sign(
      null, protocol.signingInput(payload, keyId), privateKey,
    ).toString('base64'),
  };
}

function addAuth(harness, action, role, overrides = {}) {
  const authEventId = overrides.authEventId || crypto.randomUUID();
  const purpose = overrides.credentialPurpose || {
    [ACTIONS.REQUEST]: CREDENTIAL_PURPOSES.REQUEST,
    [ACTIONS.ISSUE]: CREDENTIAL_PURPOSES.ISSUE,
    [ACTIONS.DELIVER]: CREDENTIAL_PURPOSES.DELIVER,
    [ACTIONS.ACKNOWLEDGE]: CREDENTIAL_PURPOSES.ACKNOWLEDGE,
    [ACTIONS.ACCEPT]: CREDENTIAL_PURPOSES.ACCEPT,
    [ACTIONS.READ]: CREDENTIAL_PURPOSES.READ,
  }[action];
  const event = {
    authEventId,
    action,
    role,
    principalRef: sha256('principal:' + role + ':' + authEventId),
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    authenticatedAt: iso(harness.clock.nowMs - 10),
    stepUpAt: null,
    credentialPurpose: purpose,
    credentialVersion: 1,
    ...overrides,
  };
  harness.db.authEvents.set(authEventId, clone(event));
  return authEventId;
}

function addTargetConfirmation(harness, payload, requesterRef, overrides = {}) {
  const targetConfirmationId = overrides.targetConfirmationId || crypto.randomUUID();
  const approverAuthEventId = overrides.approverAuthEventId || addAuth(
    harness, ACTIONS.TARGET_CONFIRM, overrides.approverRole || 'vendor_security_admin', {
      principalRef: overrides.approverRef || sha256('approver:' + targetConfirmationId),
      stepUpAt: overrides.stepUpAt || iso(harness.clock.nowMs - 500),
      credentialPurpose: overrides.credentialPurpose
        || CREDENTIAL_PURPOSES.TARGET_CONFIRMATION,
      credentialVersion: overrides.credentialVersion === undefined
        ? 1 : overrides.credentialVersion,
      ...(overrides.approverAuthOverrides || {}),
    },
  );
  const ownerAttestationId = overrides.ownerAttestationId || crypto.randomUUID();
  const confirmation = {
    targetConfirmationId,
    confirmationRef: sha256('confirmation:' + targetConfirmationId),
    approverAuthEventId,
    ownerAttestationId,
    confirmedAt: iso(harness.clock.nowMs - 5),
    purpose: TARGET_CONFIRMATION_PURPOSE,
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    entitlementVersion: payload.entitlementVersion,
    entitlementDigest: protocol.payloadDigest(
      payload, protocol.CHANNEL_KINDS.ENTITLEMENT,
    ),
    ...(overrides.confirmationOverrides || {}),
  };
  const approver = harness.db.authEvents.get(approverAuthEventId);
  if (requesterRef !== undefined && approver.principalRef === requesterRef
      && !overrides.approverRef && !overrides.approverAuthOverrides) {
    approver.principalRef = sha256('independent:' + targetConfirmationId);
  }
  const attestationValue = {
    attestationId: ownerAttestationId,
    targetConfirmationId,
    approverAuthEventId,
    customerId: confirmation.customerId,
    deploymentId: confirmation.deploymentId,
    entitlementVersion: confirmation.entitlementVersion,
    entitlementDigest: confirmation.entitlementDigest,
    purpose: OWNER_ATTESTATION_PURPOSE,
    version: 1,
    issuedAt: iso(harness.clock.nowMs - 6),
    expiresAt: iso(harness.clock.nowMs + 60 * 60_000),
    historyEventId: crypto.randomUUID(),
    historyEventDigest: sha256('owner-history:' + ownerAttestationId),
    authorityPurpose: AUTHORITY_PURPOSES.OWNER_ATTESTATION,
    verificationKeyFingerprint: keyFingerprint(ownerAttestationKeys.publicKey),
    verificationKeySpki: ownerAttestationKeys.publicKey.export({
      type: 'spki', format: 'der',
    }).toString('base64'),
    ...(overrides.attestationOverrides || {}),
  };
  const attestation = sealOwnerAttestation(attestationValue, {
    keyId: overrides.attestationKeyId,
    privateKey: overrides.attestationPrivateKey,
  });
  if (overrides.attestationEvidenceDigest) {
    attestation.evidenceDigest = overrides.attestationEvidenceDigest;
  }
  if (overrides.proofOverrides) Object.assign(attestation.proof, overrides.proofOverrides);
  harness.db.targetConfirmations.set(targetConfirmationId, clone(confirmation));
  harness.db.ownerAttestations.set(ownerAttestationId, clone(attestation));
  if (!overrides.omitOwnerHistory) {
    harness.db.ownerHistoryEvents.set(
      attestation.historyEventId,
      { ...ownerHistoryEvidence(attestation), ...(overrides.historyEvidenceOverrides || {}) },
    );
  }
  return targetConfirmationId;
}

function sealOwnerAttestation(value, options = {}) {
  const attestation = clone(value);
  attestation.evidenceDigest = digest(ownerAttestationEvidence(attestation));
  const keyId = options.keyId || 'rw-owner-attestation-current';
  attestation.proof = {
    keyId,
    signature: crypto.sign(
      null,
      ownerAttestationSigningInput(attestation),
      options.privateKey || ownerAttestationKeys.privateKey,
    ).toString('base64'),
  };
  return attestation;
}

function ownerAttestationEvidence(value) {
  const evidence = clone(value);
  delete evidence.evidenceDigest;
  delete evidence.proof;
  return evidence;
}

function ownerAttestationSigningInput(value) {
  const signed = clone(value);
  delete signed.proof;
  return Buffer.concat([
    Buffer.from(OWNER_ATTESTATION_SIGNATURE_DOMAIN + '\0', 'utf8'),
    Buffer.from(protocol.canonicalJson(signed), 'utf8'),
  ]);
}

function ownerHistoryEvidence(value) {
  return {
    historyEventId: value.historyEventId,
    historyEventDigest: value.historyEventDigest,
    attestationId: value.attestationId,
    targetConfirmationId: value.targetConfirmationId,
    approverAuthEventId: value.approverAuthEventId,
    customerId: value.customerId,
    deploymentId: value.deploymentId,
    entitlementVersion: value.entitlementVersion,
    entitlementDigest: value.entitlementDigest,
    evidenceDigest: value.evidenceDigest,
  };
}

function requestCommand(payload, authEventId, overrides = {}) {
  return {
    authEventId,
    targetConfirmationId: null,
    idempotencyKey: IDEMPOTENCY_KEY,
    entitlement: payload,
    ...overrides,
  };
}

function mutationCommand(result, authEventId, overrides = {}) {
  return {
    authEventId,
    lifecycleId: result.lifecycle.lifecycleId,
    expectedRevision: result.lifecycle.revision,
    ...overrides,
  };
}

function appliedAck(payload, recordedAt, overrides = {}) {
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    targetVersion: payload.entitlementVersion,
    targetDigest: protocol.payloadDigest(payload, protocol.CHANNEL_KINDS.ENTITLEMENT),
    lifecycleStage: 'applied',
    outcome: 'success',
    reasonCode: 'applied',
    recordedAt: iso(recordedAt),
    ...overrides,
  };
}

function deliveredAck(payload, recordedAt, overrides = {}) {
  return appliedAck(payload, recordedAt, {
    messageId: crypto.randomUUID(),
    lifecycleStage: 'delivered',
    reasonCode: 'delivered',
    ...overrides,
  });
}

function rejectedAck(payload, recordedAt, overrides = {}) {
  return appliedAck(payload, recordedAt, {
    messageId: crypto.randomUUID(),
    outcome: 'rejected',
    reasonCode: 'invalid_signature',
    ...overrides,
  });
}

async function requestAutomated(harness, payload = entitlement(), overrides = {}) {
  if (overrides.nowMs !== undefined) harness.clock.nowMs = overrides.nowMs;
  const authEventId = addAuth(harness, ACTIONS.REQUEST, 'billing_service');
  return harness.lifecycle.request(requestCommand(payload, authEventId, overrides.command));
}

async function issueRequested(harness, requested, payload) {
  harness.clock.nowMs += 1_000;
  return harness.lifecycle.issue(mutationCommand(
    requested, addAuth(harness, ACTIONS.ISSUE, 'billing_service'),
    { artifact: signed(payload) },
  ));
}

async function deliverIssued(harness, issued, payload, acknowledgement = null) {
  harness.clock.nowMs += 1_000;
  return harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: acknowledgement || deliveredAck(payload, harness.clock.nowMs),
  });
}

async function applyDelivered(harness, payload, acknowledgement) {
  harness.clock.nowMs += 1_000;
  return harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: acknowledgement || appliedAck(payload, harness.clock.nowMs),
  });
}

async function readLifecycle(harness, lifecycleId) {
  harness.clock.nowMs += 1;
  return harness.lifecycle.get({
    authEventId: addAuth(harness, ACTIONS.READ, 'vendor_owner'),
    lifecycleId,
  });
}

async function completeLifecycle(harness, payload = entitlement()) {
  const requested = await requestAutomated(harness, payload);
  return finishLifecycle(harness, payload, requested);
}

async function completeNextLifecycle(harness, payload, idempotencyKeyValue) {
  const requested = await requestAutomated(harness, payload, {
    command: { idempotencyKey: idempotencyKeyValue },
  });
  return finishLifecycle(harness, payload, requested);
}

async function finishLifecycle(harness, payload, requested) {
  const issued = await issueRequested(harness, requested, payload);
  const delivered = await deliverIssued(harness, issued, payload);
  const customerApply = payload.previousVersion === 0
    ? connectedState.applyEntitlement(
      connectedState.initialState(payload.customerId, payload.deploymentId),
      payload,
      {
        nowMs: harness.clock.nowMs + 1_000,
        keyId: SIGNING_KEY_ID,
        randomUUID: crypto.randomUUID,
        clock: { bootId: 'a'.repeat(32), nowMs: 10_000 },
      },
    )
    : { acknowledgement: appliedAck(payload, harness.clock.nowMs + 1_000) };
  const acknowledged = await applyDelivered(harness, payload, customerApply.acknowledgement);
  return { requested, issued, delivered, acknowledged, customerApply };
}

async function requestManual(harness, payload, idempotency = IDEMPOTENCY_KEY) {
  const authEventId = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
    stepUpAt: iso(harness.clock.nowMs - 100),
  });
  const confirmationId = addTargetConfirmation(
    harness, payload, harness.db.authEvents.get(authEventId).principalRef,
  );
  return harness.lifecycle.request(requestCommand(payload, authEventId, {
    idempotencyKey: idempotency,
    targetConfirmationId: confirmationId,
  }));
}

async function completeManualLifecycle(harness, payload, idempotency = IDEMPOTENCY_KEY) {
  const requested = await requestManual(harness, payload, idempotency);
  return finishLifecycle(harness, payload, requested);
}

test('customer delivered and applied ACKs are the only delivery authority and complete five stages', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const flow = await completeLifecycle(harness, payload);

  assert.equal(flow.customerApply.acknowledgement.lifecycleStage, 'applied');
  assert.deepEqual([
    flow.requested.lifecycle.stage,
    flow.issued.lifecycle.stage,
    flow.delivered.lifecycle.stage,
    flow.acknowledged.lifecycle.stage,
  ], ['requested', 'issued', 'delivered', 'acknowledged']);
  assert.equal(flow.acknowledged.lifecycle.completed, true);
  assert.equal(harness.db.records.size, 1);
  assert.equal(harness.witness.operations.size, 5);
  assert.equal(harness.db.pending.size, 0);
  assert.equal(harness.db.current.get(scopeKey(payload)).entitlementVersion, 1);
  assert.deepEqual(
    harness.db.events.get(flow.acknowledged.lifecycle.lifecycleId)
      .map((event) => event.toStage),
    ['requested', 'issued', 'delivered', 'applied', 'acknowledged'],
  );
});

test('publication and vendor service credentials cannot advance an issued lifecycle', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const issued = await issueRequested(harness, requested, payload);

  await expectCode(harness.lifecycle.markDelivered(mutationCommand(
    issued, addAuth(harness, ACTIONS.DELIVER, 'control_plane_service'),
    { artifact: signed(payload), deliveryId: crypto.randomUUID() },
  )), 'external_transition_forbidden');
  await expectCode(harness.lifecycle.acknowledgeApplied(mutationCommand(
    issued, addAuth(harness, ACTIONS.ACCEPT, 'control_plane_service'),
  )), 'external_transition_forbidden');

  const stored = await readLifecycle(harness, issued.lifecycle.lifecycleId);
  assert.equal(stored.stage, 'issued');
  assert.equal(harness.db.events.get(stored.lifecycleId).length, 2);
  assert.equal(harness.db.current.size, 0);
});

test('delivered ACK must durably precede applied ACK and message reuse conflicts', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const issued = await issueRequested(harness, requested, payload);
  harness.clock.nowMs += 1_000;

  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: appliedAck(payload, harness.clock.nowMs),
  }), 'ack_stage_out_of_order');
  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: deliveredAck(payload, harness.clock.nowMs, { targetVersion: 2 }),
  }), 'customer_ack_not_found');
  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: deliveredAck(payload, harness.clock.nowMs, {
      targetDigest: 'e'.repeat(64),
    }),
  }), 'customer_ack_not_found');
  assert.equal((await readLifecycle(harness, issued.lifecycle.lifecycleId)).stage, 'issued');
  assert.equal(harness.db.ackClaims.size, 0);

  const delivery = deliveredAck(payload, harness.clock.nowMs + 1_000);
  const delivered = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: delivery,
  });
  assert.equal(delivered.lifecycle.stage, 'delivered');
  const conflicting = { ...delivery, targetDigest: 'f'.repeat(64) };
  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: conflicting,
  }), 'ack_message_conflict');
  assert.equal((await readLifecycle(harness, issued.lifecycle.lifecycleId)).stage, 'delivered');
});

test('rejected ACKs are closed durably without claiming a success stage', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const issued = await issueRequested(harness, requested, payload);
  harness.clock.nowMs += 1_000;
  const acknowledgement = rejectedAck(payload, harness.clock.nowMs);

  const rejected = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.deepEqual(
    { ok: rejected.ok, closed: rejected.closed, accepted: rejected.accepted },
    { ok: true, closed: true, accepted: false },
  );
  assert.equal((await readLifecycle(harness, issued.lifecycle.lifecycleId)).stage, 'issued');
  assert.equal(harness.db.ackClaims.size, 1);

  const replay = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(replay.idempotent, true);
  assert.equal(harness.db.ackClaims.size, 1);
  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: { ...acknowledgement, reasonCode: 'internal_failure' },
  }), 'ack_message_conflict');
  harness.db.ackClaims.get(acknowledgement.messageId).reasonCode = 'internal_failure';
  await expectCode(recreate(harness).lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  }), 'ack_message_conflict');
});

test('applied ACK with pending final acceptance returns retryable and exact restart resumes once', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const issued = await issueRequested(harness, requested, payload);
  await deliverIssued(harness, issued, payload);
  harness.clock.nowMs += 1_000;
  const acknowledgement = appliedAck(payload, harness.clock.nowMs);
  harness.witness.blockFinalizeStage = 'acknowledged';

  const pending = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.deepEqual(
    { ok: pending.ok, pending: pending.pending, retryable: pending.retryable, code: pending.code },
    { ok: false, pending: true, retryable: true, code: 'acknowledgement_finalization_pending' },
  );
  const lifecycleId = issued.lifecycle.lifecycleId;
  assert.equal(harness.db.records.get(lifecycleId).stage, 'acknowledged');
  assert.equal(harness.db.pending.size, 1);
  assert.equal(harness.db.ackClaims.size, 2);
  assert.equal(harness.db.acceptanceClaims.size, 1);
  assert.equal(harness.db.events.get(lifecycleId).length, 5);

  const firstOperationRef = pending.operationRef;
  const stillPending = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.deepEqual(
    {
      ok: stillPending.ok,
      retryable: stillPending.retryable,
      code: stillPending.code,
      operationRef: stillPending.operationRef,
    },
    {
      ok: false,
      retryable: true,
      code: 'acknowledgement_finalization_pending',
      operationRef: firstOperationRef,
    },
  );
  const blockedRestart = recreate(harness);
  const restartPending = await blockedRestart.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(blockedRestart, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(restartPending.retryable, true);
  assert.equal(restartPending.operationRef, firstOperationRef);
  assert.equal(harness.db.ackClaims.size, 2);
  assert.equal(harness.db.acceptanceClaims.size, 1);
  assert.equal(harness.db.events.get(lifecycleId).length, 5);

  harness.witness.blockFinalizeStage = null;
  const restarted = recreate(harness);
  const retry = await restarted.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(restarted, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(retry.ok, true);
  assert.equal(retry.idempotent, true);
  assert.equal(retry.lifecycle.stage, 'acknowledged');
  assert.equal(harness.db.pending.size, 0);
  assert.equal(harness.db.ackClaims.size, 2);
  assert.equal(harness.db.acceptanceClaims.size, 1);
  assert.equal(harness.db.events.get(lifecycleId).length, 5);
});

test('applied ACK commit uncertainty resumes from the durable intermediate stage', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const issued = await issueRequested(harness, requested, payload);
  await deliverIssued(harness, issued, payload);
  harness.clock.nowMs += 1_000;
  const acknowledgement = appliedAck(payload, harness.clock.nowMs);
  harness.db.nextFailure = 'after_commit_unreadable';

  const pending = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.deepEqual(
    { ok: pending.ok, pending: pending.pending, retryable: pending.retryable },
    { ok: false, pending: true, retryable: true },
  );
  const lifecycleId = issued.lifecycle.lifecycleId;
  assert.equal(harness.db.records.get(lifecycleId).stage, 'applied');
  assert.equal(harness.db.events.get(lifecycleId).length, 4);
  assert.equal(harness.db.ackClaims.size, 2);
  assert.equal(harness.db.acceptanceClaims.size, 0);

  const restarted = recreate(harness);
  const resumed = await restarted.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(restarted, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(resumed.ok, true);
  assert.equal(resumed.lifecycle.stage, 'acknowledged');
  assert.equal(harness.db.events.get(lifecycleId).length, 5);
  assert.equal(harness.db.ackClaims.size, 2);
  assert.equal(harness.db.acceptanceClaims.size, 1);
  assert.equal(harness.db.current.get(scopeKey(payload)).entitlementVersion, 1);
});

test('blocked applied witness keeps the same retryable ACK reference through restart', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const issued = await issueRequested(harness, requested, payload);
  await deliverIssued(harness, issued, payload);
  harness.clock.nowMs += 1_000;
  const acknowledgement = appliedAck(payload, harness.clock.nowMs);
  harness.witness.blockFinalizeStage = 'applied';

  const first = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(first.retryable, true);
  assert.equal(first.code, 'acknowledgement_finalization_pending');
  assert.match(first.operationRef, /^[a-f0-9]{24}$/);
  const lifecycleId = issued.lifecycle.lifecycleId;
  assert.equal(harness.db.records.get(lifecycleId).stage, 'applied');
  assert.equal(harness.db.events.get(lifecycleId).length, 4);
  assert.equal(harness.db.ackClaims.size, 2);
  assert.equal(harness.db.acceptanceClaims.size, 0);
  assert.equal(harness.db.current.size, 0);

  const retry = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(retry.retryable, true);
  assert.equal(retry.code, 'acknowledgement_finalization_pending');
  assert.equal(retry.operationRef, first.operationRef);
  const restarted = recreate(harness);
  const restartRetry = await restarted.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(restarted, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(restartRetry.retryable, true);
  assert.equal(restartRetry.code, 'acknowledgement_finalization_pending');
  assert.equal(restartRetry.operationRef, first.operationRef);
  assert.equal(harness.db.events.get(lifecycleId).length, 4);
  assert.equal(harness.db.ackClaims.size, 2);
  assert.equal(harness.db.acceptanceClaims.size, 0);
  assert.equal(harness.db.current.size, 0);

  harness.witness.blockFinalizeStage = null;
  const recovered = await restarted.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(restarted, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(recovered.ok, true);
  assert.equal(recovered.lifecycle.stage, 'acknowledged');
  assert.equal(harness.db.events.get(lifecycleId).length, 5);
  assert.equal(harness.db.ackClaims.size, 2);
  assert.equal(harness.db.acceptanceClaims.size, 1);
  assert.equal(harness.db.current.size, 1);
  assert.equal(harness.db.current.get(scopeKey(payload)).entitlementVersion, 1);
  assert.equal(harness.witness.operations.size, 5);
});

test('vendor portal projection exposes status without internal authority or claim evidence', async () => {
  const harness = createHarness();
  const flow = await completeLifecycle(harness, entitlement());
  const portal = await readLifecycle(harness, flow.acknowledged.lifecycle.lifecycleId);
  assert.deepEqual(Object.keys(portal).sort(), [
    'completed', 'customerId', 'deploymentId', 'entitlementDigest',
    'entitlementVersion', 'lifecycleId', 'plan', 'reasonCode', 'revision',
    'seats', 'stage', 'status', 'timestamps',
  ]);
  const serialized = JSON.stringify(portal);
  for (const forbidden of [
    'acceptanceId', 'artifact', 'authEventId', 'confirmationRef', 'deliveryId', 'messageId',
    'principalRef', 'signature', 'targetConfirmationId', 'witnessOperationId',
  ]) assert.equal(serialized.includes(forbidden), false, forbidden + ' leaked');
});

test('two customer silos remain isolated and lifecycle channels reject prompt material', async () => {
  const harness = createHarness();
  const first = entitlement();
  const second = entitlement({
    messageId: crypto.randomUUID(),
    customerId: OTHER_CUSTOMER_ID,
    deploymentId: OTHER_DEPLOYMENT_ID,
  });
  const firstResult = await requestAutomated(harness, first);
  const secondAuth = addAuth(harness, ACTIONS.REQUEST, 'billing_service', {
    customerId: OTHER_CUSTOMER_ID,
    deploymentId: OTHER_DEPLOYMENT_ID,
  });
  const secondResult = await harness.lifecycle.request(requestCommand(
    second, secondAuth, { idempotencyKey: 'entitlement-change-00000002' },
  ));
  assert.equal(harness.db.records.size, 2);
  assert.equal(harness.witness.scopeHeads.size, 2);

  await expectCode(harness.lifecycle.get({
    authEventId: addAuth(harness, ACTIONS.READ, 'vendor_owner'),
    lifecycleId: secondResult.lifecycle.lifecycleId,
  }), 'lifecycle_not_found');
  await expectCode(harness.lifecycle.get({
    authEventId: addAuth(harness, ACTIONS.READ, 'vendor_owner', {
      customerId: OTHER_CUSTOMER_ID,
      deploymentId: OTHER_DEPLOYMENT_ID,
    }),
    lifecycleId: firstResult.lifecycle.lifecycleId,
  }), 'lifecycle_not_found');

  const promptMarker = 'synthetic prompt 123-45-6789';
  await expectCode(harness.lifecycle.request({
    ...requestCommand(first, addAuth(harness, ACTIONS.REQUEST, 'billing_service'), {
      idempotencyKey: 'entitlement-change-00000003',
    }),
    prompt: promptMarker,
  }), 'request_invalid');
  assert.equal(JSON.stringify([...harness.db.records.values()]).includes(promptMarker), false);
});

test('business idempotency survives fresh authorization at every stage', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const requestRetry = await harness.lifecycle.request(requestCommand(
    payload, addAuth(harness, ACTIONS.REQUEST, 'billing_service'),
  ));
  assert.equal(requestRetry.idempotent, true);

  const issued = await issueRequested(harness, requested, payload);
  const issueRetry = await harness.lifecycle.issue(mutationCommand(
    requested, addAuth(harness, ACTIONS.ISSUE, 'billing_service'),
    { artifact: signed(payload) },
  ));
  assert.equal(issueRetry.idempotent, true);

  const deliveryAcknowledgement = deliveredAck(payload, harness.clock.nowMs + 1_000);
  await deliverIssued(harness, issued, payload, deliveryAcknowledgement);
  const deliveryRetry = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: deliveryAcknowledgement,
  });
  assert.equal(deliveryRetry.idempotent, true);

  harness.clock.nowMs += 1_000;
  const acknowledgement = appliedAck(payload, harness.clock.nowMs);
  const accepted = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  const ackRetry = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(ackRetry.idempotent, true);
  assert.equal(accepted.lifecycle.revision, 5);
  assert.equal(harness.db.events.get(accepted.lifecycle.lifecycleId).length, 5);
});

test('manual and commercial target changes require independent vendor dual control', async () => {
  const harness = createHarness();
  const payload = entitlement({
    status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
  });
  const authEventId = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
    stepUpAt: iso(harness.clock.nowMs - 500),
  });
  const requester = harness.db.authEvents.get(authEventId);
  await expectCode(
    harness.lifecycle.request(requestCommand(payload, authEventId)),
    'target_confirmation_required',
  );

  const sameApprover = addTargetConfirmation(
    harness, payload, undefined, { approverRef: requester.principalRef },
  );
  await expectCode(harness.lifecycle.request(requestCommand(
    payload,
    addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
      principalRef: requester.principalRef,
      stepUpAt: iso(harness.clock.nowMs - 500),
    }),
    { targetConfirmationId: sameApprover },
  )), 'target_confirmation_required');

  const independentAuth = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
    stepUpAt: iso(harness.clock.nowMs - 500),
  });
  const confirmationId = addTargetConfirmation(
    harness, payload, harness.db.authEvents.get(independentAuth).principalRef,
  );
  const requested = await harness.lifecycle.request(requestCommand(
    payload, independentAuth, { targetConfirmationId: confirmationId },
  ));
  assert.equal(
    harness.db.records.get(requested.lifecycle.lifecycleId).targetConfirmation.purpose,
    TARGET_CONFIRMATION_PURPOSE,
  );

  const base = createHarness();
  const flow = await completeLifecycle(base, entitlement());
  base.clock.nowMs += 1_000;
  const changed = entitlement({
    messageId: crypto.randomUUID(),
    entitlementVersion: 2,
    previousVersion: 1,
    seats: 41,
    issuedAt: iso(base.clock.nowMs - 100),
    expiresAt: iso(base.clock.nowMs + 5 * 60_000),
    fallbackUntil: iso(base.clock.nowMs + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000),
  });
  const changeAuth = addAuth(base, ACTIONS.REQUEST, 'vendor_billing_admin', {
    stepUpAt: iso(base.clock.nowMs - 100),
  });
  const changeConfirmation = addTargetConfirmation(
    base, changed, base.db.authEvents.get(changeAuth).principalRef,
  );
  const changedRequest = await base.lifecycle.request(requestCommand(
    changed, changeAuth, {
      idempotencyKey: 'entitlement-change-00000002',
      targetConfirmationId: changeConfirmation,
    },
  ));
  assert.equal(changedRequest.lifecycle.seats, 41);
  assert.equal(flow.acknowledged.lifecycle.completed, true);
});

test('dual-control confirmation requires a fresh purpose-bound approver and Owner audit attestation', async (t) => {
  const variants = [
    ['wrong credential purpose', { credentialPurpose: CREDENTIAL_PURPOSES.REQUEST }],
    ['wrong credential version', { credentialVersion: 2 }],
    ['stale step-up', { stepUpAt: iso(NOW - 6 * 60_000) }],
  ];
  for (const [name, confirmationOptions] of variants) {
    await t.test(name, async () => {
      const harness = createHarness();
      const payload = entitlement({
        status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
      });
      const requestAuth = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
        stepUpAt: iso(harness.clock.nowMs - 100),
      });
      const confirmationId = addTargetConfirmation(
        harness, payload, harness.db.authEvents.get(requestAuth).principalRef,
        confirmationOptions,
      );
      await expectCode(harness.lifecycle.request(requestCommand(
        payload, requestAuth, { targetConfirmationId: confirmationId },
      )), 'target_confirmation_required');
    });
  }

  await t.test('missing Owner audit attestation', async () => {
    const harness = createHarness();
    const payload = entitlement({
      status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
    });
    const requestAuth = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
      stepUpAt: iso(harness.clock.nowMs - 100),
    });
    const confirmationId = addTargetConfirmation(
      harness, payload, harness.db.authEvents.get(requestAuth).principalRef,
    );
    harness.db.ownerAttestations.clear();
    await expectCode(harness.lifecycle.request(requestCommand(
      payload, requestAuth, { targetConfirmationId: confirmationId },
    )), 'target_confirmation_required');
  });

  await t.test('invalid Owner attestation signature', async () => {
    const harness = createHarness();
    const payload = entitlement({
      status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
    });
    const requestAuth = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
      stepUpAt: iso(harness.clock.nowMs - 100),
    });
    const confirmationId = addTargetConfirmation(
      harness, payload, harness.db.authEvents.get(requestAuth).principalRef,
    );
    const attestationId = harness.db.targetConfirmations.get(confirmationId).ownerAttestationId;
    harness.db.ownerAttestations.get(attestationId).proof.signature = crypto
      .randomBytes(64).toString('base64');
    await expectCode(harness.lifecycle.request(requestCommand(
      payload, requestAuth, { targetConfirmationId: confirmationId },
    )), 'target_confirmation_required');
  });

  await t.test('a freshly signed self-consistent attestation cannot invent Owner history', async () => {
    const harness = createHarness();
    const payload = entitlement({
      status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
    });
    const requestAuth = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
      stepUpAt: iso(harness.clock.nowMs - 100),
    });
    const confirmationId = addTargetConfirmation(
      harness, payload, harness.db.authEvents.get(requestAuth).principalRef,
    );
    const attestationId = harness.db.targetConfirmations.get(confirmationId).ownerAttestationId;
    const original = harness.db.ownerAttestations.get(attestationId);
    const nonexistentHistoryId = crypto.randomUUID();
    const forged = sealOwnerAttestation({
      ...original,
      historyEventId: nonexistentHistoryId,
      historyEventDigest: digest({
        historyEventId: nonexistentHistoryId,
        attestationId,
        targetConfirmationId: confirmationId,
      }),
    });
    harness.db.ownerAttestations.set(attestationId, forged);
    assert.equal(harness.db.ownerHistoryEvents.has(nonexistentHistoryId), false);
    await expectCode(harness.lifecycle.request(requestCommand(
      payload, requestAuth, { targetConfirmationId: confirmationId },
    )), 'target_confirmation_required');
  });

  await t.test('signed proof binds history, target, approver, and validity window', async () => {
    const mutations = [
      ['historyEventId', crypto.randomUUID()],
      ['historyEventDigest', '0'.repeat(64)],
      ['attestationId', crypto.randomUUID()],
      ['targetConfirmationId', crypto.randomUUID()],
      ['customerId', OTHER_CUSTOMER_ID],
      ['deploymentId', OTHER_DEPLOYMENT_ID],
      ['entitlementVersion', 2],
      ['entitlementDigest', '0'.repeat(64)],
      ['approverAuthEventId', crypto.randomUUID()],
      ['issuedAt', iso(NOW - 7)],
      ['expiresAt', iso(NOW + 2 * 60 * 60_000)],
    ];
    for (const [field, replacement] of mutations) {
      const harness = createHarness();
      const payload = entitlement({
        status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
      });
      const requestAuth = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
        stepUpAt: iso(harness.clock.nowMs - 100),
      });
      const confirmationId = addTargetConfirmation(
        harness, payload, harness.db.authEvents.get(requestAuth).principalRef,
      );
      const attestationId = harness.db.targetConfirmations.get(confirmationId).ownerAttestationId;
      harness.db.ownerAttestations.get(attestationId)[field] = replacement;
      await expectCode(harness.lifecycle.request(requestCommand(
        payload, requestAuth, { targetConfirmationId: confirmationId },
      )), 'target_confirmation_required');
    }
  });

  await t.test('expired signed Owner attestation', async () => {
    const harness = createHarness();
    const payload = entitlement({
      status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
    });
    const requestAuth = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
      stepUpAt: iso(harness.clock.nowMs - 100),
    });
    const confirmationId = addTargetConfirmation(
      harness, payload, harness.db.authEvents.get(requestAuth).principalRef,
      {
        attestationOverrides: {
          issuedAt: iso(harness.clock.nowMs - 1_000),
          expiresAt: iso(harness.clock.nowMs - 1),
        },
      },
    );
    await expectCode(harness.lifecycle.request(requestCommand(
      payload, requestAuth, { targetConfirmationId: confirmationId },
    )), 'target_confirmation_required');
  });
});

test('break-glass emergency revoke is vendor-authorized and cannot be customer-vetoed', async () => {
  const harness = createHarness();
  await completeLifecycle(harness, entitlement());
  harness.clock.nowMs += 1_000;
  const revoked = entitlement({
    messageId: crypto.randomUUID(),
    status: 'revoked',
    reasonCode: 'emergency_revoke',
    fallbackUntil: null,
    entitlementVersion: 2,
    previousVersion: 1,
    issuedAt: iso(harness.clock.nowMs - 100),
    expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
  });
  const authEventId = addAuth(harness, ACTIONS.REQUEST, 'vendor_security_admin', {
    credentialPurpose: CREDENTIAL_PURPOSES.BREAK_GLASS,
    stepUpAt: iso(harness.clock.nowMs - 100),
  });
  const requested = await harness.lifecycle.request(requestCommand(revoked, authEventId, {
    idempotencyKey: 'entitlement-change-00000002',
  }));
  assert.equal(requested.lifecycle.reasonCode, 'emergency_revoke');

  const withConfirmation = createHarness();
  await completeLifecycle(withConfirmation, entitlement());
  withConfirmation.clock.nowMs += 1_000;
  const forbiddenPayload = entitlement({
    messageId: crypto.randomUUID(),
    status: 'revoked',
    reasonCode: 'emergency_revoke',
    fallbackUntil: null,
    entitlementVersion: 2,
    previousVersion: 1,
    issuedAt: iso(withConfirmation.clock.nowMs - 100),
    expiresAt: iso(withConfirmation.clock.nowMs + 5 * 60_000),
  });
  const forbiddenAuth = addAuth(
    withConfirmation, ACTIONS.REQUEST, 'vendor_security_admin', {
      credentialPurpose: CREDENTIAL_PURPOSES.BREAK_GLASS,
      stepUpAt: iso(withConfirmation.clock.nowMs - 100),
    },
  );
  const confirmationId = addTargetConfirmation(
    withConfirmation,
    forbiddenPayload,
    withConfirmation.db.authEvents.get(forbiddenAuth).principalRef,
  );
  await expectCode(withConfirmation.lifecycle.request(requestCommand(
    forbiddenPayload,
    forbiddenAuth,
    {
      idempotencyKey: 'entitlement-change-00000003',
      targetConfirmationId: confirmationId,
    },
  )), 'target_confirmation_forbidden');
});

test('paused and emergency-revoked silos can return active only through manual restore dual control', async (t) => {
  await t.test('paused state rejects billing and trial automation before manual restore', async () => {
    const harness = createHarness();
    await completeManualLifecycle(harness, entitlement({
      status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
    }));
    harness.clock.nowMs += 1_000;
    for (const [index, reasonCode] of ['billing_active', 'trial_active'].entries()) {
      const attempted = entitlement({
        messageId: crypto.randomUUID(), entitlementVersion: 2, previousVersion: 1,
        reasonCode, issuedAt: iso(harness.clock.nowMs - 100),
        expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
        fallbackUntil: iso(harness.clock.nowMs + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000),
      });
      await expectCode(harness.lifecycle.request(requestCommand(
        attempted, addAuth(harness, ACTIONS.REQUEST, 'billing_service'),
        { idempotencyKey: `entitlement-restore-auto-0000000${index}` },
      )), 'explicit_restore_required');
    }
    const restoredPayload = entitlement({
      messageId: crypto.randomUUID(), entitlementVersion: 2, previousVersion: 1,
      reasonCode: 'manual_restore', issuedAt: iso(harness.clock.nowMs - 100),
      expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
      fallbackUntil: iso(harness.clock.nowMs + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000),
    });
    await expectCode(harness.lifecycle.request(requestCommand(
      restoredPayload, addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
        stepUpAt: iso(harness.clock.nowMs - 100),
      }), { idempotencyKey: 'entitlement-restore-no-dual-0001' },
    )), 'target_confirmation_required');
    const restored = await completeManualLifecycle(
      harness, restoredPayload, 'entitlement-manual-restore-000001',
    );
    assert.equal(restored.acknowledged.lifecycle.status, 'active');
    assert.equal(restored.acknowledged.lifecycle.reasonCode, 'manual_restore');
  });

  await t.test('emergency revoke cannot be lifted by a later billing verdict', async () => {
    const harness = createHarness();
    await completeLifecycle(harness, entitlement());
    harness.clock.nowMs += 1_000;
    const revoked = entitlement({
      messageId: crypto.randomUUID(), status: 'revoked', reasonCode: 'emergency_revoke',
      fallbackUntil: null, entitlementVersion: 2, previousVersion: 1,
      issuedAt: iso(harness.clock.nowMs - 100),
      expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
    });
    const revokeAuth = addAuth(harness, ACTIONS.REQUEST, 'vendor_security_admin', {
      credentialPurpose: CREDENTIAL_PURPOSES.BREAK_GLASS,
      stepUpAt: iso(harness.clock.nowMs - 100),
    });
    const revokedRequest = await harness.lifecycle.request(requestCommand(
      revoked, revokeAuth, { idempotencyKey: 'entitlement-emergency-revoke-0001' },
    ));
    await finishLifecycle(harness, revoked, revokedRequest);
    harness.clock.nowMs += 1_000;
    for (const reasonCode of ['billing_active', 'trial_active']) {
      const attempted = entitlement({
        messageId: crypto.randomUUID(), entitlementVersion: 3, previousVersion: 2,
        reasonCode, issuedAt: iso(harness.clock.nowMs - 100),
        expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
        fallbackUntil: iso(harness.clock.nowMs + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000),
      });
      await expectCode(harness.lifecycle.request(requestCommand(
        attempted, addAuth(harness, ACTIONS.REQUEST, 'billing_service'),
        { idempotencyKey: 'entitlement-emergency-auto-' + reasonCode },
      )), 'explicit_restore_required');
    }
    const manual = entitlement({
      messageId: crypto.randomUUID(), entitlementVersion: 3, previousVersion: 2,
      reasonCode: 'manual_restore', issuedAt: iso(harness.clock.nowMs - 100),
      expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
      fallbackUntil: iso(harness.clock.nowMs + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000),
    });
    const requested = await requestManual(
      harness, manual, 'entitlement-emergency-restore-0001',
    );
    assert.equal(requested.lifecycle.reasonCode, 'manual_restore');
  });
});

test('restricted-state precedence permits only exact restriction, escalation, or dual-control restore', async () => {
  const harness = createHarness();
  await completeManualLifecycle(harness, entitlement({
    status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
  }));
  harness.clock.nowMs += 1_000;

  const revoked = entitlement({
    messageId: crypto.randomUUID(), status: 'revoked', reasonCode: 'subscription_ended',
    fallbackUntil: null, entitlementVersion: 2, previousVersion: 1,
    issuedAt: iso(harness.clock.nowMs - 100),
    expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
  });
  const revokeRequested = await requestAutomated(harness, revoked, {
    command: { idempotencyKey: 'entitlement-restriction-escalate-01' },
  });
  assert.equal(revokeRequested.lifecycle.status, 'revoked');
  await finishLifecycle(harness, revoked, revokeRequested);
  harness.clock.nowMs += 1_000;

  const weakened = entitlement({
    messageId: crypto.randomUUID(), status: 'paused', reasonCode: 'payment_past_due',
    fallbackUntil: null, entitlementVersion: 3, previousVersion: 2,
    issuedAt: iso(harness.clock.nowMs - 100),
    expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
  });
  await expectCode(requestAutomated(harness, weakened, {
    command: { idempotencyKey: 'entitlement-restriction-weaken-0001' },
  }), 'restriction_precedence_violation');

  const exactRestriction = entitlement({
    messageId: crypto.randomUUID(), status: 'revoked', reasonCode: 'subscription_ended',
    fallbackUntil: null, entitlementVersion: 3, previousVersion: 2,
    issuedAt: iso(harness.clock.nowMs - 100),
    expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
  });
  const exactRequested = await requestAutomated(harness, exactRestriction, {
    command: { idempotencyKey: 'entitlement-restriction-exact-00001' },
  });
  assert.equal(exactRequested.lifecycle.status, 'revoked');
});

test('current state is accepted only with the latest acknowledged lifecycle provenance', async () => {
  const harness = createHarness();
  const flow = await completeLifecycle(harness, entitlement());
  const current = harness.db.current.get(scopeKey(entitlement()));
  current.provenance.eventHead = '0'.repeat(64);
  harness.db.current.set(scopeKey(entitlement()), current);

  harness.clock.nowMs += 1_000;
  const next = entitlement({
    messageId: crypto.randomUUID(),
    entitlementVersion: 2,
    previousVersion: 1,
    issuedAt: iso(harness.clock.nowMs - 100),
    expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
    fallbackUntil: iso(harness.clock.nowMs + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000),
  });
  await expectCode(harness.lifecycle.request(requestCommand(
    next, addAuth(harness, ACTIONS.REQUEST, 'billing_service'),
    { idempotencyKey: 'entitlement-change-00000002' },
  )), 'current_state_invalid');
  assert.equal(flow.acknowledged.lifecycle.stage, 'acknowledged');
});

test('connector authentication precedes ACK lookup and all cross-scope misses are normalized', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const issued = await issueRequested(harness, requested, payload);
  await deliverIssued(harness, issued, payload);
  harness.clock.nowMs += 1_000;
  const acknowledgement = appliedAck(payload, harness.clock.nowMs);

  const lookupsBefore = harness.db.ackLookups;
  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: crypto.randomUUID(), acknowledgement,
  }), 'auth_event_invalid');
  assert.equal(harness.db.ackLookups, lookupsBefore);

  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector', {
      customerId: OTHER_CUSTOMER_ID,
      deploymentId: OTHER_DEPLOYMENT_ID,
    }),
    acknowledgement,
  }), 'customer_ack_not_found');

  const stale = { ...acknowledgement, messageId: crypto.randomUUID(), recordedAt: iso(
    harness.clock.nowMs - 24 * 60 * 60 * 1000 - 1,
  ) };
  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: stale,
  }), 'customer_ack_not_found');

  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector', {
      credentialPurpose: CREDENTIAL_PURPOSES.DELIVER,
    }),
    acknowledgement,
  }), 'authorization_denied');
});

test('an authenticated ACK claim replays exactly after 24 hours while a novel stale ACK fails', async () => {
  const harness = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const issued = await issueRequested(harness, requested, payload);
  await deliverIssued(harness, issued, payload);
  harness.clock.nowMs += 1_000;
  const acknowledgement = appliedAck(payload, harness.clock.nowMs);
  const first = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  harness.clock.nowMs += 24 * 60 * 60 * 1000 + 1;
  const replay = await harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement,
  });
  assert.equal(first.lifecycle.stage, 'acknowledged');
  assert.equal(replay.idempotent, true);
  assert.equal(replay.lifecycle.lifecycleId, first.lifecycle.lifecycleId);

  await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
    authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
    acknowledgement: { ...acknowledgement, messageId: crypto.randomUUID() },
  }), 'customer_ack_not_found');
});

test('applied ACK replay requires an authenticated current projection at or above its lineage', async (t) => {
  await t.test('missing projection fails closed', async () => {
    const harness = createHarness();
    const flow = await completeLifecycle(harness, entitlement());
    harness.db.current.delete(scopeKey(entitlement()));
    await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
      authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
      acknowledgement: flow.customerApply.acknowledgement,
    }), 'current_state_invalid');
  });

  await t.test('tampered projection fails closed', async () => {
    const harness = createHarness();
    const flow = await completeLifecycle(harness, entitlement());
    const current = harness.db.current.get(scopeKey(entitlement()));
    current.provenance.eventHead = '0'.repeat(64);
    harness.db.current.set(scopeKey(entitlement()), current);
    await expectCode(harness.lifecycle.acceptCustomerAcknowledgement({
      authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
      acknowledgement: flow.customerApply.acknowledgement,
    }), 'current_state_invalid');
  });

  await t.test('a valid newer acknowledged descendant permits the old exact replay', async () => {
    const harness = createHarness();
    const firstPayload = entitlement();
    const first = await completeLifecycle(harness, firstPayload);
    harness.clock.nowMs += 1_000;
    const secondPayload = entitlement({
      messageId: crypto.randomUUID(),
      entitlementVersion: 2,
      previousVersion: 1,
      issuedAt: iso(harness.clock.nowMs - 100),
      expiresAt: iso(harness.clock.nowMs + 5 * 60_000),
      fallbackUntil: iso(
        harness.clock.nowMs + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000,
      ),
    });
    const second = await completeNextLifecycle(
      harness, secondPayload, 'entitlement-change-00000002',
    );
    assert.equal(second.acknowledged.lifecycle.entitlementVersion, 2);

    const replay = await harness.lifecycle.acceptCustomerAcknowledgement({
      authEventId: addAuth(harness, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
      acknowledgement: first.customerApply.acknowledgement,
    });
    assert.equal(replay.ok, true);
    assert.equal(replay.idempotent, true);
    assert.equal(replay.lifecycle.lifecycleId, first.acknowledged.lifecycle.lifecycleId);
  });

  await t.test('a valid newer projection on a different branch is rejected', async () => {
    const integrityKey = crypto.randomBytes(32);
    const witnessKey = crypto.randomBytes(32);
    const witnessKeyId = 'rw-lifecycle-witness-shared';
    const branchA = createHarness({
      currentKey: integrityKey,
      currentKeyId: 'rw-lifecycle-shared',
      witness: new DurableWitnessStore({ key: witnessKey, keyId: witnessKeyId }),
    });
    const branchB = createHarness({
      currentKey: integrityKey,
      currentKeyId: 'rw-lifecycle-shared',
      witness: new DurableWitnessStore({ key: witnessKey, keyId: witnessKeyId }),
    });
    const firstA = await completeLifecycle(branchA, entitlement());
    await completeLifecycle(branchB, entitlement({ messageId: crypto.randomUUID() }));
    branchB.clock.nowMs += 1_000;
    const secondBPayload = entitlement({
      messageId: crypto.randomUUID(),
      entitlementVersion: 2,
      previousVersion: 1,
      issuedAt: iso(branchB.clock.nowMs - 100),
      expiresAt: iso(branchB.clock.nowMs + 5 * 60_000),
      fallbackUntil: iso(
        branchB.clock.nowMs + protocol.DEFAULT_FALLBACK_WINDOW_MS - 2_000,
      ),
    });
    await completeNextLifecycle(
      branchB, secondBPayload, 'entitlement-branch-b-00000002',
    );

    const lifecycleId = firstA.acknowledged.lifecycle.lifecycleId;
    branchB.db.records.set(lifecycleId, clone(branchA.db.records.get(lifecycleId)));
    branchB.db.events.set(lifecycleId, clone(branchA.db.events.get(lifecycleId)));
    for (const [key, value] of branchA.db.authClaims) {
      branchB.db.authClaims.set(key, clone(value));
    }
    for (const [key, value] of branchA.db.ackClaims) {
      branchB.db.ackClaims.set(key, clone(value));
    }
    for (const [key, value] of branchA.db.acceptanceClaims) {
      branchB.db.acceptanceClaims.set(key, clone(value));
    }
    for (const [key, value] of branchA.db.witnessOperations) {
      branchB.db.witnessOperations.set(key, value);
    }
    for (const [key, value] of branchA.witness.operations) {
      branchB.witness.operations.set(key, clone(value));
    }

    await expectCode(branchB.lifecycle.acceptCustomerAcknowledgement({
      authEventId: addAuth(branchB, ACTIONS.ACKNOWLEDGE, 'customer_connector'),
      acknowledgement: firstA.customerApply.acknowledgement,
    }), 'current_state_invalid');
  });
});

test('lifecycle MAC key rotation verifies retired history and rejects identity reuse', async () => {
  const oldKey = crypto.randomBytes(32);
  const harness = createHarness({
    integrityKeyring: lifecycleKeyring('rw-lifecycle-old', oldKey),
  });
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const newKey = crypto.randomBytes(32);
  const rotated = recreate(harness, {
    integrityKeyring: lifecycleKeyring(
      'rw-lifecycle-new', newKey, { 'rw-lifecycle-old': oldKey },
    ),
  });
  const read = await readLifecycle(rotated, requested.lifecycle.lifecycleId);
  assert.equal(read.stage, 'requested');
  const issued = await issueRequested(rotated, requested, payload);
  assert.equal(rotated.db.records.get(issued.lifecycle.lifecycleId).macKeyId, 'rw-lifecycle-new');

  assert.throws(() => createHarness({
    integrityKeyring: {
      ...lifecycleKeyring('rw-lifecycle-bad-purpose', crypto.randomBytes(32)),
      purpose: 'vendor_offline_license_signing',
    },
  }), hasCode('integrity_keyring_invalid'));

  const reused = crypto.randomBytes(32);
  const reusedWitness = new DurableWitnessStore();
  const reusedManifest = authorityManifest('rw-lifecycle-current', reused, reusedWitness, {
    [AUTHORITY_PURPOSES.RECOVERY]: {
      purpose: AUTHORITY_PURPOSES.RECOVERY,
      identityType: 'hmac_secret',
      identities: [{
        slot: 'current', keyId: 'rw-recovery-current', identity: sha256Buffer(reused),
      }],
    },
  });
  assert.throws(() => createHarness({
    currentKey: reused,
    witness: reusedWitness,
    authorityManifest: reusedManifest,
  }), hasCode('owner_authority_identity_reused'));

  const witness = new DurableWitnessStore({ key: reused });
  assert.throws(() => createHarness({ currentKey: reused, witness }),
    hasCode('owner_authority_identity_reused'));
});

test('witness rotation verifies retired history and seals new transitions with the current identity', async () => {
  const oldKey = crypto.randomBytes(32);
  const oldWitness = new DurableWitnessStore({
    current: { keyId: 'rw-lifecycle-witness-old', key: oldKey },
  });
  const harness = createHarness({ witness: oldWitness });
  const payload = entitlement();
  const requested = await requestAutomated(harness, payload);
  const oldOperationId = harness.db.records.get(requested.lifecycle.lifecycleId).witnessOperationId;

  const newKey = crypto.randomBytes(32);
  const rotatedWitness = new DurableWitnessStore({
    current: { keyId: 'rw-lifecycle-witness-new', key: newKey },
    retiredVerifyOnly: { 'rw-lifecycle-witness-old': oldKey },
    operations: oldWitness.operations,
    scopeHeads: oldWitness.scopeHeads,
  });
  const rotated = recreate(harness, { witness: rotatedWitness });
  assert.equal((await readLifecycle(rotated, requested.lifecycle.lifecycleId)).stage, 'requested');
  const issued = await issueRequested(rotated, requested, payload);
  const newOperationId = rotated.db.records.get(issued.lifecycle.lifecycleId).witnessOperationId;
  assert.equal(
    rotatedWitness.operations.get(oldOperationId).witnessIdentity.keyId,
    'rw-lifecycle-witness-old',
  );
  assert.equal(
    rotatedWitness.operations.get(newOperationId).witnessIdentity.keyId,
    'rw-lifecycle-witness-new',
  );
  assert.equal((await readLifecycle(rotated, issued.lifecycle.lifecycleId)).stage, 'issued');
});

test('startup consumes the exact typed Owner authority manifest and enforces key separation', async () => {
  const lifecycleKey = crypto.randomBytes(32);
  const witness = new DurableWitnessStore();
  const complete = authorityManifest('rw-lifecycle-current', lifecycleKey, witness);
  assert.equal(Object.keys(complete.authorities).length, 20);
  for (const purpose of [
    AUTHORITY_PURPOSES.ENTITLEMENT,
    AUTHORITY_PURPOSES.AUDIT_REQUEST,
    AUTHORITY_PURPOSES.POLICY,
    AUTHORITY_PURPOSES.CATALOG_GLOBAL,
    AUTHORITY_PURPOSES.CATALOG_DISTRIBUTION,
  ]) assert.equal(complete.authorities[purpose].identities.length, 2, purpose);
  const channelCredentialPurposes = [
    AUTHORITY_PURPOSES.HEARTBEAT_CREDENTIAL,
    AUTHORITY_PURPOSES.ACKNOWLEDGEMENT_CREDENTIAL,
    AUTHORITY_PURPOSES.DIAGNOSTIC_CREDENTIAL,
    AUTHORITY_PURPOSES.SHADOW_CANDIDATE_CREDENTIAL,
  ];
  assert.equal(new Set(channelCredentialPurposes.map((purpose) => (
    complete.authorities[purpose].identities[0].identity
  ))).size, channelCredentialPurposes.length);
  const incomplete = clone(complete);
  delete incomplete.authorities[AUTHORITY_PURPOSES.POLICY];
  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness,
    authorityManifest: incomplete,
  }), hasCode('owner_authority_manifest_invalid'));

  const missingRegistryIntegrity = clone(complete);
  delete missingRegistryIntegrity.authorities[
    AUTHORITY_PURPOSES.LICENSE_REGISTRY_INTEGRITY
  ];
  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness,
    authorityManifest: missingRegistryIntegrity,
  }), hasCode('owner_authority_manifest_invalid'));

  for (const purpose of [
    AUTHORITY_PURPOSES.COMMAND_IDEMPOTENCY,
    AUTHORITY_PURPOSES.PAGINATION_CURSOR,
  ]) {
    const missingOwnerPurpose = clone(complete);
    delete missingOwnerPurpose.authorities[purpose];
    assert.throws(() => createHarness({
      currentKey: lifecycleKey,
      witness,
      authorityManifest: missingOwnerPurpose,
    }), hasCode('owner_authority_manifest_invalid'));
  }

  const reusedRegistryIntegrity = clone(complete);
  reusedRegistryIntegrity.authorities[
    AUTHORITY_PURPOSES.LICENSE_REGISTRY_INTEGRITY
  ].identities[0].identity = complete.authorities[
    AUTHORITY_PURPOSES.DIAGNOSTIC_INTEGRITY
  ].identities[0].identity;
  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness,
    authorityManifest: reusedRegistryIntegrity,
  }), hasCode('owner_authority_identity_reused'));

  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness: new DurableWitnessStore({ keyId: 'witness-unscoped' }),
    authorityManifest: complete,
  }), hasCode('witness_identity_invalid'));

  const witnessKey = crypto.randomBytes(32);
  const collidingWitness = new DurableWitnessStore({ key: witnessKey });
  const manifestWithWitnessCollision = authorityManifest(
    'rw-lifecycle-current', lifecycleKey, collidingWitness,
  );
  manifestWithWitnessCollision.authorities[
    AUTHORITY_PURPOSES.DIAGNOSTIC_INTEGRITY
  ].identities[0].identity = sha256Buffer(witnessKey);
  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    authorityManifest: manifestWithWitnessCollision,
    witness: collidingWitness,
  }), hasCode('owner_authority_identity_reused'));

  const retired = crypto.randomBytes(32);
  const manifestWithRetiredCollision = authorityManifest(
    'rw-lifecycle-current', lifecycleKey, witness,
  );
  manifestWithRetiredCollision.authorities[
    AUTHORITY_PURPOSES.RECOVERY
  ].identities[0].identity = sha256Buffer(retired);
  assert.throws(() => createHarness({
    integrityKeyring: lifecycleKeyring(
      'rw-lifecycle-current', lifecycleKey, { 'rw-lifecycle-retired': retired },
    ),
    witness,
    authorityManifest: manifestWithRetiredCollision,
  }), hasCode('integrity_key_identity_conflict'));

  const badPublicMaterial = clone(complete);
  badPublicMaterial.authorities[AUTHORITY_PURPOSES.POLICY]
    .identities[0].identity = sha256('not-the-policy-public-key');
  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness,
    authorityManifest: badPublicMaterial,
  }), hasCode('owner_authority_manifest_invalid'));

  const reusedPublicMaterial = clone(complete);
  const entitlementIdentity = reusedPublicMaterial.authorities[
    AUTHORITY_PURPOSES.ENTITLEMENT
  ].identities[0];
  Object.assign(
    reusedPublicMaterial.authorities[AUTHORITY_PURPOSES.POLICY].identities[0],
    {
      identity: entitlementIdentity.identity,
      publicKeySpki: entitlementIdentity.publicKeySpki,
    },
  );
  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness,
    authorityManifest: reusedPublicMaterial,
  }), hasCode('owner_authority_identity_reused'));

  const excessiveOverlap = clone(complete);
  const thirdEntitlementKeys = crypto.generateKeyPairSync('ed25519');
  excessiveOverlap.authorities[AUTHORITY_PURPOSES.ENTITLEMENT].identities.push(
    publicIdentity(
      'next',
      `rw-entitlement-${keyFingerprint(thirdEntitlementKeys.publicKey)}`,
      thirdEntitlementKeys,
    ),
  );
  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness,
    authorityManifest: excessiveOverlap,
  }), hasCode('owner_authority_manifest_invalid'));

  const forbiddenCredentialOverlap = clone(complete);
  forbiddenCredentialOverlap.authorities[
    AUTHORITY_PURPOSES.HEARTBEAT_CREDENTIAL
  ].identities.push({
    slot: 'next', keyId: 'rw-heartbeat-credential-next', identity: sha256('heartbeat-next'),
  });
  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness,
    authorityManifest: forbiddenCredentialOverlap,
  }), hasCode('owner_authority_manifest_invalid'));

  assert.throws(() => createHarness({
    currentKey: lifecycleKey,
    witness,
    authorityManifest: complete,
    ownerAuditVerifier: {
      identity: () => ({
        ...currentAuthority(complete, AUTHORITY_PURPOSES.PLATFORM_AUDIT),
        identity: sha256('different-owner-audit-authority'),
      }),
      verifyHistoryEvent: async () => true,
    },
  }), hasCode('owner_audit_verifier_invalid'));

  const overlap = createHarness();
  const payload = entitlement();
  const requested = await requestAutomated(overlap, payload);
  const issued = await overlap.lifecycle.issue(mutationCommand(
    requested, addAuth(overlap, ACTIONS.ISSUE, 'billing_service'),
    { artifact: signed(payload, NEXT_SIGNING_KEY_ID, nextSigningKeys.privateKey) },
  ));
  assert.equal(issued.lifecycle.stage, 'issued');
});

test('lifecycle Owner manifest requires exact full-fingerprint entitlement key IDs', () => {
  const lifecycleKey = crypto.randomBytes(32);
  const witness = new DurableWitnessStore();
  const complete = authorityManifest('rw-lifecycle-current', lifecycleKey, witness);
  for (const slot of ['current', 'next']) {
    const index = slot === 'current' ? 0 : 1;
    const identity = complete.authorities[AUTHORITY_PURPOSES.ENTITLEMENT]
      .identities[index].identity;
    const wrongFingerprint = identity === 'f'.repeat(64) ? 'e'.repeat(64) : 'f'.repeat(64);
    for (const keyId of [
      'rw-entitlement-current',
      `rw-entitlement-${identity.slice(0, 32)}`,
      `rw-entitlement-${wrongFingerprint}`,
    ]) {
      const candidate = clone(complete);
      candidate.authorities[AUTHORITY_PURPOSES.ENTITLEMENT].identities[index].keyId = keyId;
      assert.throws(() => createHarness({
        currentKey: lifecycleKey,
        witness,
        authorityManifest: candidate,
      }), hasCode('owner_authority_manifest_invalid'));
    }
  }
});

test('commands reject accessors, excessive depth, oversized values, and out-of-range dates', async () => {
  const harness = createHarness();
  const accessor = {};
  Object.defineProperty(accessor, 'authEventId', {
    enumerable: true, get() { throw new Error('must not execute'); },
  });
  await expectCode(harness.lifecycle.get(accessor), 'read_command_invalid');

  let deep = 'x';
  for (let index = 0; index < 20; index += 1) deep = { nested: deep };
  await expectCode(harness.lifecycle.request({
    authEventId: crypto.randomUUID(),
    targetConfirmationId: null,
    idempotencyKey: IDEMPOTENCY_KEY,
    entitlement: deep,
  }), 'request_invalid');

  await expectCode(harness.lifecycle.request({
    authEventId: crypto.randomUUID(),
    targetConfirmationId: null,
    idempotencyKey: IDEMPOTENCY_KEY,
    entitlement: { padding: 'x'.repeat(40 * 1024) },
  }), 'request_invalid');

  const invalidDate = entitlement({ issuedAt: '2101-01-01T00:00:00.000Z' });
  await expectCode(harness.lifecycle.request(requestCommand(
    invalidDate, addAuth(harness, ACTIONS.REQUEST, 'billing_service'),
  )), 'request_invalid');
});

test('external prepare is independent of DB rollback and is safely aborted before retry', async () => {
  const harness = createHarness();
  harness.db.nextFailure = 'before_commit';
  await expectCode(requestAutomated(harness, entitlement()), 'db_before_commit');
  assert.equal(harness.db.records.size, 0);
  assert.equal(harness.db.pending.size, 0);
  assert.equal(harness.witness.operations.size, 0);
  assert.deepEqual(await harness.lifecycle.readiness(), {
    ok: true, ready: true, retryable: false, pendingCount: 0,
  });
  const retry = await requestAutomated(harness, entitlement());
  assert.equal(retry.ok, true);
});

test('a lost DB commit response is recovered as committed and never returned retryable', async () => {
  const harness = createHarness();
  harness.db.nextFailure = 'after_commit';
  const result = await requestAutomated(harness, entitlement());
  assert.equal(result.ok, true);
  assert.equal(result.retryable, false);
  assert.equal(harness.db.records.size, 1);
  assert.equal(harness.db.pending.size, 0);
  assert.equal(harness.witness.operations.size, 1);
});

test('success is withheld when durable indexes, current state, or finalized scope are not exact', async (t) => {
  for (const index of ['idempotency', 'target', 'witness']) {
    await t.test('missing ' + index + ' binding freezes readiness', async () => {
      const harness = createHarness();
      harness.db.omitNextIndex = index;
      const result = await requestAutomated(harness, entitlement());
      assert.equal(result.ok, false);
      assert.equal(result.pending, true);
      assert.equal(result.retryable, false);
      assert.equal((await harness.lifecycle.readiness()).ready, false);
    });
  }

  for (const mode of ['noop_success', 'wrong_success']) {
    await t.test(mode + ' current advance freezes readiness', async () => {
      const harness = createHarness();
      const payload = entitlement();
      const requested = await requestAutomated(harness, payload);
      const issued = await issueRequested(harness, requested, payload);
      const delivered = await deliverIssued(harness, issued, payload);
      assert.equal(delivered.lifecycle.stage, 'delivered');
      harness.db.advanceMode = mode;
      const result = await applyDelivered(
        harness, payload, appliedAck(payload, harness.clock.nowMs + 1_000),
      );
      assert.equal(result.ok, false);
      assert.equal(result.pending, true);
      assert.equal(result.retryable, true);
      assert.equal((await harness.lifecycle.readiness()).ready, false);
    });
  }

  await t.test('final operation without the exact scope head freezes readiness', async () => {
    const harness = createHarness();
    harness.witness.skipScopeHeadOnce = true;
    const result = await requestAutomated(harness, entitlement());
    assert.equal(result.ok, false);
    assert.equal(result.pending, true);
    const operationId = harness.db.records.values().next().value.witnessOperationId;
    assert.equal(harness.witness.operations.get(operationId).state, 'final');
    assert.equal(harness.witness.scopeHeads.size, 0);
    assert.equal((await harness.lifecycle.readiness()).ready, false);
  });
});

test('post-commit read ambiguity returns non-retryable pending until reconciliation', async () => {
  const harness = createHarness();
  harness.db.nextFailure = 'after_commit_unreadable';
  const result = await requestAutomated(harness, entitlement());
  assert.deepEqual(
    { ok: result.ok, pending: result.pending, retryable: result.retryable, code: result.code },
    {
      ok: false, pending: true, retryable: false,
      code: 'commit_pending_reconciliation',
    },
  );
  assert.equal(harness.db.records.size, 1);
  assert.equal(harness.db.pending.size, 1);
  assert.equal((await harness.lifecycle.readiness()).ready, true);
  assert.equal(harness.db.pending.size, 0);
});

test('finalize failure freezes readiness until reconciliation proves the committed transition', async () => {
  const harness = createHarness();
  harness.witness.blockFinalize = true;
  const result = await requestAutomated(harness, entitlement());
  assert.deepEqual(
    { ok: result.ok, pending: result.pending, retryable: result.retryable, code: result.code },
    {
      ok: false, pending: true, retryable: false,
      code: 'witness_finalize_pending',
    },
  );
  const frozen = await harness.lifecycle.readiness();
  assert.equal(frozen.ready, false);
  assert.equal(harness.db.pending.size, 1);

  harness.witness.blockFinalize = false;
  const recovered = await harness.lifecycle.readiness();
  assert.equal(recovered.ready, true);
  assert.equal(harness.db.pending.size, 0);
  const lifecycleId = [...harness.db.records.keys()][0];
  assert.equal((await readLifecycle(harness, lifecycleId)).stage, 'requested');
});

test('a lost finalize response and a lost prepare response are resolved from durable witness state', async () => {
  const prepareLost = createHarness();
  prepareLost.witness.failPrepareAfterWrite = true;
  const prepared = await requestAutomated(prepareLost, entitlement());
  assert.equal(prepared.ok, true);

  const finalizeLost = createHarness();
  finalizeLost.witness.failFinalizeAfterWrite = true;
  const finalized = await requestAutomated(finalizeLost, entitlement());
  assert.equal(finalized.ok, true);
  assert.equal(finalizeLost.db.pending.size, 0);
});

test('an orphan prepared witness is reconciled after a simulated crash', async () => {
  const harness = createHarness();
  harness.db.nextFailure = 'before_commit';
  harness.witness.blockAbort = true;
  const pending = await requestAutomated(harness, entitlement());
  assert.equal(pending.pending, true);
  assert.equal(harness.db.records.size, 0);
  assert.equal(harness.witness.operations.size, 1);

  harness.witness.blockAbort = false;
  const restarted = recreate(harness);
  const readiness = await restarted.lifecycle.readiness();
  assert.equal(readiness.ready, true);
  assert.equal(harness.witness.operations.size, 0);
});

test('hostile storage callback and result behavior cannot manufacture success', async () => {
  const double = createHarness();
  double.db.nextFailure = 'double_callback';
  await expectCode(requestAutomated(double, entitlement()), 'storage_invalid');
  assert.equal(double.db.records.size, 0);
  assert.equal(double.witness.operations.size, 0);

  const forged = createHarness();
  forged.db.nextFailure = 'forged_result';
  const recovered = await requestAutomated(forged, entitlement());
  assert.equal(recovered.ok, true);
  assert.equal(recovered.retryable, false);
  assert.equal(forged.db.records.size, 1);

  const rollback = createHarness();
  rollback.db.nextFailure = 'rollback_with_success';
  const pending = await requestAutomated(rollback, entitlement());
  assert.equal(pending.ok, false);
  assert.equal(pending.pending, true);
  assert.equal(pending.retryable, false);
  assert.equal(rollback.db.records.size, 0);
  assert.equal(rollback.witness.operations.size, 1);
  assert.equal((await rollback.lifecycle.readiness()).ready, true);
  assert.equal(rollback.witness.operations.size, 0);
});

test('restore revalidates archived authority, target confirmation, event, record, and witness evidence', async (t) => {
  async function manualRequested() {
    const harness = createHarness();
    const payload = entitlement({
      status: 'paused', reasonCode: 'manual_pause', fallbackUntil: null,
    });
    const authEventId = addAuth(harness, ACTIONS.REQUEST, 'vendor_owner', {
      stepUpAt: iso(harness.clock.nowMs - 100),
    });
    const confirmationId = addTargetConfirmation(
      harness, payload, harness.db.authEvents.get(authEventId).principalRef,
    );
    const result = await harness.lifecycle.request(requestCommand(payload, authEventId, {
      targetConfirmationId: confirmationId,
    }));
    return { harness, result, confirmationId };
  }

  await t.test('authority claim', async () => {
    const { harness, result } = await manualRequested();
    const event = harness.db.events.get(result.lifecycle.lifecycleId)[0];
    harness.db.authClaims.get(event.authority.authEventId).principalRef = '0'.repeat(64);
    await expectCode(readLifecycle(harness, result.lifecycle.lifecycleId),
      'lifecycle_integrity_invalid');
  });

  await t.test('target confirmation claim', async () => {
    const { harness, result, confirmationId } = await manualRequested();
    harness.db.targetClaims.get(confirmationId).confirmationRef = '0'.repeat(64);
    await expectCode(readLifecycle(harness, result.lifecycle.lifecycleId),
      'lifecycle_integrity_invalid');
  });

  await t.test('approver auth claim', async () => {
    const { harness, result } = await manualRequested();
    const event = harness.db.events.get(result.lifecycle.lifecycleId)[0];
    const approvalId = event.claimEvidence.approvalAuthClaim.authEventId;
    harness.db.authClaims.get(approvalId).principalRef = '0'.repeat(64);
    await expectCode(readLifecycle(harness, result.lifecycle.lifecycleId),
      'lifecycle_integrity_invalid');
  });

  await t.test('Owner attestation history', async () => {
    const { harness, result } = await manualRequested();
    const record = harness.db.records.get(result.lifecycle.lifecycleId);
    const attestationId = record.targetConfirmation.ownerAttestationId;
    harness.db.ownerAttestations.get(attestationId).historyEventDigest = '0'.repeat(64);
    await expectCode(readLifecycle(harness, result.lifecycle.lifecycleId),
      'lifecycle_integrity_invalid');
  });

  await t.test('archived Owner attestation proof', async () => {
    const { harness, result, confirmationId } = await manualRequested();
    harness.db.targetClaims.get(confirmationId).ownerAttestation.proof.signature = crypto
      .randomBytes(64).toString('base64');
    await expectCode(readLifecycle(harness, result.lifecycle.lifecycleId),
      'lifecycle_integrity_invalid');
  });

  await t.test('archived proof remains verifiable after Owner attestation key rotation', async () => {
    const { harness, result } = await manualRequested();
    const rotatedAttestationKeys = crypto.generateKeyPairSync('ed25519');
    const rotatedManifest = authorityManifest(
      harness.integrityKeyring.current.keyId,
      harness.integrityKeyring.current.key,
      harness.witness,
      {
        [AUTHORITY_PURPOSES.OWNER_ATTESTATION]: {
          purpose: AUTHORITY_PURPOSES.OWNER_ATTESTATION,
          identityType: 'ed25519_public',
          identities: [publicIdentity(
            'current', 'rw-owner-attestation-rotated', rotatedAttestationKeys,
          )],
        },
      },
    );
    const rotated = recreate(harness, { authorityManifest: rotatedManifest });
    assert.equal((await readLifecycle(
      rotated, result.lifecycle.lifecycleId,
    )).stage, 'requested');
  });

  await t.test('event', async () => {
    const { harness, result } = await manualRequested();
    harness.db.events.get(result.lifecycle.lifecycleId)[0].recordedAt = iso(NOW + 99_000);
    await expectCode(readLifecycle(harness, result.lifecycle.lifecycleId),
      'lifecycle_integrity_invalid');
  });

  await t.test('record', async () => {
    const { harness, result } = await manualRequested();
    harness.db.records.get(result.lifecycle.lifecycleId).proposedState.seats += 1;
    await expectCode(readLifecycle(harness, result.lifecycle.lifecycleId),
      'lifecycle_integrity_invalid');
  });

  await t.test('witness rollback', async () => {
    const { harness, result } = await manualRequested();
    const operationId = harness.db.records.get(result.lifecycle.lifecycleId).witnessOperationId;
    harness.witness.operations.get(operationId).descriptor.checkpoint.eventHead = '0'.repeat(64);
    await expectCode(readLifecycle(harness, result.lifecycle.lifecycleId),
      'witness_invalid');
  });
});

async function expectCode(promise, code) {
  await assert.rejects(promise, hasCode(code));
}

function hasCode(code) {
  return (error) => error && error.code === code;
}

function iso(value) {
  return new Date(value).toISOString();
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function digest(value) {
  return sha256(protocol.canonicalJson(value));
}

function clone(value) {
  if (value === undefined) return undefined;
  return JSON.parse(protocol.canonicalJson(value));
}

function cloneMap(map) {
  return new Map([...map.entries()].map(([key, value]) => [key, clone(value)]));
}

function claimUnique(map, key, value) {
  if (map.has(key)) return false;
  map.set(key, clone(value));
  return true;
}

function scopeKey(value) {
  return value.customerId + '\0' + value.deploymentId;
}

function idempotencyKey(customerId, deploymentId, key) {
  return scopeKey({ customerId, deploymentId }) + '\0' + key;
}

function targetKey(customerId, deploymentId, version) {
  return scopeKey({ customerId, deploymentId }) + '\0' + version;
}

class DurableLifecycleDb {
  constructor() {
    this.records = new Map();
    this.idempotency = new Map();
    this.targets = new Map();
    this.events = new Map();
    this.authEvents = new Map();
    this.authClaims = new Map();
    this.targetConfirmations = new Map();
    this.ownerAttestations = new Map();
    this.ownerHistoryEvents = new Map();
    this.targetClaims = new Map();
    this.ackClaims = new Map();
    this.acceptanceClaims = new Map();
    this.current = new Map();
    this.pending = new Map();
    this.witnessOperations = new Map();
    this.omitNextIndex = null;
    this.advanceMode = 'normal';
    this.nextFailure = null;
    this.failBeforeCallback = false;
    this.ackLookups = 0;
    this.coordinateTail = Promise.resolve();
  }

  coordinate(work) {
    const run = this.coordinateTail.then(work);
    this.coordinateTail = run.catch(() => undefined);
    return run;
  }

  async transaction(work) {
    if (this.failBeforeCallback) {
      this.failBeforeCallback = false;
      throw codedError('db_read_unavailable');
    }
    const snapshot = this.snapshot();
    const state = { mutated: false };
    const tx = this.adapter(state);
    let result;
    try {
      result = await work(tx);
      if (state.mutated && this.nextFailure === 'double_callback') {
        this.nextFailure = null;
        await work(tx);
      }
    } catch (error) {
      this.restore(snapshot);
      throw error;
    }
    if (!state.mutated) return result;
    const failure = this.nextFailure;
    this.nextFailure = null;
    if (failure === 'before_commit') {
      this.restore(snapshot);
      throw codedError('db_before_commit');
    }
    if (failure === 'after_commit') throw codedError('db_commit_response_lost');
    if (failure === 'after_commit_unreadable') {
      this.failBeforeCallback = true;
      throw codedError('db_commit_response_lost');
    }
    if (failure === 'rollback_with_success') {
      this.restore(snapshot);
      return result;
    }
    if (failure === 'forged_result') return clone(result);
    return result;
  }

  adapter(state) {
    const mutate = () => { state.mutated = true; };
    return {
      findByIdempotencyKey: async (customerId, deploymentId, key) => {
        const id = this.idempotency.get(idempotencyKey(customerId, deploymentId, key));
        return clone(id ? this.records.get(id) : null);
      },
      findByTargetVersion: async (customerId, deploymentId, version) => {
        const id = this.targets.get(targetKey(customerId, deploymentId, version));
        return clone(id ? this.records.get(id) : null);
      },
      findByAckMessageId: async (messageId) => {
        this.ackLookups += 1;
        return clone(this.ackClaims.get(messageId) || null);
      },
      findByWitnessOperationId: async (operationId) => {
        const lifecycleId = this.witnessOperations.get(operationId);
        return clone(lifecycleId ? this.records.get(lifecycleId) : null);
      },
      get: async (lifecycleId) => clone(this.records.get(lifecycleId) || null),
      listEvents: async (lifecycleId) => clone(this.events.get(lifecycleId) || []),
      listPendingWitnesses: async () => clone([...this.pending.values()]),
      getPendingWitness: async (operationId) => clone(this.pending.get(operationId) || null),
      lockAuthEvent: async (authEventId) => clone(this.authEvents.get(authEventId) || null),
      lockCurrentEntitlement: async (customerId, deploymentId) => clone(
        this.current.get(scopeKey({ customerId, deploymentId })) || null,
      ),
      lockTargetConfirmation: async (id) => clone(this.targetConfirmations.get(id) || null),
      lockOwnerAttestation: async (id) => clone(this.ownerAttestations.get(id) || null),
      getOwnerAttestation: async (id) => clone(this.ownerAttestations.get(id) || null),
      lockAuthEventClaim: async () => null,
      getAuthClaim: async (id) => clone(this.authClaims.get(id) || null),
      getTargetConfirmationClaim: async (id) => clone(this.targetClaims.get(id) || null),
      getAckClaim: async (id) => clone(this.ackClaims.get(id) || null),
      getAcceptanceClaim: async (id) => clone(this.acceptanceClaims.get(id) || null),
      claimAuthEvent: async (claim) => {
        mutate();
        return claimUnique(this.authClaims, claim.authEventId, claim);
      },
      claimTargetConfirmation: async (claim) => {
        mutate();
        return claimUnique(this.targetClaims, claim.targetConfirmationId, claim);
      },
      claimAckMessage: async (claim) => {
        mutate();
        return claimUnique(this.ackClaims, claim.messageId, claim);
      },
      claimAcceptanceId: async (claim) => {
        mutate();
        return claimUnique(this.acceptanceClaims, claim.acceptanceId, claim);
      },
      insertLifecycle: async (record, event, pending) => {
        mutate();
        const idempotency = idempotencyKey(
          record.customerId, record.deploymentId, record.idempotencyKey,
        );
        const target = targetKey(
          record.customerId, record.deploymentId, record.entitlementVersion,
        );
        if (this.records.has(record.lifecycleId)
            || this.idempotency.has(idempotency) || this.targets.has(target)
            || this.witnessOperations.has(record.witnessOperationId)) return false;
        this.records.set(record.lifecycleId, clone(record));
        if (this.omitNextIndex !== 'idempotency') {
          this.idempotency.set(idempotency, record.lifecycleId);
        }
        if (this.omitNextIndex !== 'target') this.targets.set(target, record.lifecycleId);
        this.events.set(record.lifecycleId, [clone(event)]);
        this.pending.set(record.witnessOperationId, clone(pending));
        if (this.omitNextIndex !== 'witness') {
          this.witnessOperations.set(record.witnessOperationId, record.lifecycleId);
        }
        this.omitNextIndex = null;
        return true;
      },
      updateLifecycle: async (
        lifecycleId, expectedRevision, record, event, pending,
      ) => {
        mutate();
        const current = this.records.get(lifecycleId);
        if (!current || current.revision !== expectedRevision
            || this.witnessOperations.has(record.witnessOperationId)) return false;
        this.records.set(lifecycleId, clone(record));
        this.events.get(lifecycleId).push(clone(event));
        this.pending.set(record.witnessOperationId, clone(pending));
        this.witnessOperations.set(record.witnessOperationId, lifecycleId);
        return true;
      },
      clearPendingWitness: async (operationId, descriptorDigest) => {
        mutate();
        const pending = this.pending.get(operationId);
        if (!pending) return true;
        if (pending.descriptorDigest !== descriptorDigest) return false;
        this.pending.delete(operationId);
        return true;
      },
      advanceCurrentEntitlement: async (input) => {
        mutate();
        const key = scopeKey(input);
        const current = this.current.get(key) || null;
        const currentVersion = current ? current.entitlementVersion : 0;
        if (currentVersion !== input.expectedPreviousVersion
            || input.nextState.entitlementVersion <= currentVersion) return false;
        if (this.advanceMode === 'noop_success') {
          this.advanceMode = 'normal';
          return true;
        }
        if (this.advanceMode === 'wrong_success') {
          this.advanceMode = 'normal';
          this.current.set(key, { ...clone(input.nextState), seats: input.nextState.seats + 1 });
          return true;
        }
        this.current.set(key, clone(input.nextState));
        return true;
      },
    };
  }

  snapshot() {
    return {
      records: cloneMap(this.records),
      idempotency: new Map(this.idempotency),
      targets: new Map(this.targets),
      events: cloneMap(this.events),
      authClaims: cloneMap(this.authClaims),
      targetClaims: cloneMap(this.targetClaims),
      ackClaims: cloneMap(this.ackClaims),
      acceptanceClaims: cloneMap(this.acceptanceClaims),
      current: cloneMap(this.current),
      pending: cloneMap(this.pending),
      witnessOperations: new Map(this.witnessOperations),
    };
  }

  restore(snapshot) {
    this.records = snapshot.records;
    this.idempotency = snapshot.idempotency;
    this.targets = snapshot.targets;
    this.events = snapshot.events;
    this.authClaims = snapshot.authClaims;
    this.targetClaims = snapshot.targetClaims;
    this.ackClaims = snapshot.ackClaims;
    this.acceptanceClaims = snapshot.acceptanceClaims;
    this.current = snapshot.current;
    this.pending = snapshot.pending;
    this.witnessOperations = snapshot.witnessOperations;
  }
}

class DurableWitnessStore {
  constructor(options = {}) {
    this.current = {
      key: options.current && options.current.key || options.key || crypto.randomBytes(32),
      keyId: options.current && options.current.keyId
        || options.keyId || 'rw-lifecycle-witness-current',
    };
    this.retiredVerifyOnly = new Map(Object.entries(options.retiredVerifyOnly || {}));
    this.operations = options.operations || new Map();
    this.scopeHeads = options.scopeHeads || new Map();
    this.blockFinalize = false;
    this.blockFinalizeStage = null;
    this.blockAbort = false;
    this.failPrepareAfterWrite = false;
    this.failFinalizeAfterWrite = false;
    this.skipScopeHeadOnce = false;
  }

  identity() {
    const retiredVerifyOnly = {};
    for (const [keyId, key] of this.retiredVerifyOnly) {
      retiredVerifyOnly[keyId] = sha256Buffer(key);
    }
    return {
      purpose: WITNESS_PURPOSE,
      version: 1,
      current: {
        keyId: this.current.keyId,
        keyFingerprint: sha256Buffer(this.current.key),
      },
      retiredVerifyOnly,
    };
  }

  async prepare(descriptor) {
    const operationId = descriptor.operationId;
    const existing = this.operations.get(operationId);
    if (existing) {
      if (!canonicalEqual(existing.descriptor, descriptor)) throw codedError('witness_conflict');
      return clone(existing);
    }
    const current = this.scopeHeads.get(scopeKey(descriptor)) || null;
    if ((current ? current.descriptorDigest : null) !== descriptor.previousWitnessDigest) {
      throw codedError('witness_chain_conflict');
    }
    const envelope = this.seal({
      schemaVersion: 1,
      state: 'prepared',
      descriptor: clone(descriptor),
      descriptorDigest: digest(descriptor),
      witnessIdentity: this.envelopeIdentity(this.identity().current),
      preparedAt: descriptor.preparedAt,
      finalizedAt: null,
    });
    this.operations.set(operationId, clone(envelope));
    if (this.failPrepareAfterWrite) {
      this.failPrepareAfterWrite = false;
      throw codedError('witness_prepare_response_lost');
    }
    return clone(envelope);
  }

  async finalize(operationId, descriptorDigest) {
    const current = this.operations.get(operationId);
    if (!current || current.descriptorDigest !== descriptorDigest) {
      throw codedError('witness_not_found');
    }
    if (current.state === 'final') return clone(current);
    if (this.blockFinalize || this.blockFinalizeStage === current.descriptor.stage) {
      throw codedError('witness_finalize_blocked');
    }
    const scope = scopeKey(current.descriptor);
    const prior = this.scopeHeads.get(scope) || null;
    if ((prior ? prior.descriptorDigest : null)
        !== current.descriptor.previousWitnessDigest) {
      throw codedError('witness_chain_conflict');
    }
    const finalized = this.seal({
      ...clone(current),
      state: 'final',
      finalizedAt: current.preparedAt,
      witnessMac: undefined,
    }, this.keyForIdentity(current.witnessIdentity));
    this.operations.set(operationId, clone(finalized));
    if (this.skipScopeHeadOnce) this.skipScopeHeadOnce = false;
    else this.scopeHeads.set(scope, clone(finalized));
    if (this.failFinalizeAfterWrite) {
      this.failFinalizeAfterWrite = false;
      throw codedError('witness_finalize_response_lost');
    }
    return clone(finalized);
  }

  async abort(operationId, descriptorDigest) {
    if (this.blockAbort) throw codedError('witness_abort_blocked');
    const current = this.operations.get(operationId);
    if (!current) return true;
    if (current.state !== 'prepared' || current.descriptorDigest !== descriptorDigest) {
      throw codedError('witness_abort_conflict');
    }
    this.operations.delete(operationId);
    return true;
  }

  async readOperation(operationId) {
    return clone(this.operations.get(operationId) || null);
  }

  async readFinal(operationId) {
    const value = this.operations.get(operationId);
    return clone(value && value.state === 'final' ? value : null);
  }

  async readScope(customerId, deploymentId) {
    return clone(this.scopeHeads.get(scopeKey({ customerId, deploymentId })) || null);
  }

  async listPrepared() {
    return clone([...this.operations.values()].filter((value) => value.state === 'prepared'));
  }

  async verify(envelope) {
    if (!envelope || !envelope.witnessIdentity) return false;
    const key = this.keyForIdentity(envelope.witnessIdentity);
    if (!key) return false;
    const expected = this.seal({ ...clone(envelope), witnessMac: undefined }, key);
    const stored = this.operations.get(envelope.descriptor.operationId);
    return canonicalEqual(expected, envelope) && canonicalEqual(stored, envelope);
  }

  keyForIdentity(identity) {
    if (identity.keyId === this.current.keyId
        && identity.keyFingerprint === sha256Buffer(this.current.key)) return this.current.key;
    const key = this.retiredVerifyOnly.get(identity.keyId);
    return key && identity.keyFingerprint === sha256Buffer(key) ? key : null;
  }

  envelopeIdentity(identity) {
    return {
      purpose: WITNESS_PURPOSE,
      version: 1,
      keyId: identity.keyId,
      keyFingerprint: identity.keyFingerprint,
    };
  }

  seal(value, key = this.current.key) {
    const unsigned = { ...value };
    delete unsigned.witnessMac;
    return {
      ...unsigned,
      witnessMac: crypto.createHmac('sha256', key)
        .update('redactwall.vendor-entitlement-lifecycle.witness.v1\0', 'utf8')
        .update(protocol.canonicalJson(unsigned), 'utf8')
        .digest('hex'),
    };
  }
}

function canonicalEqual(left, right) {
  return protocol.canonicalJson(left) === protocol.canonicalJson(right);
}

function codedError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
