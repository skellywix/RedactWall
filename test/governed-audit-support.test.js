'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
process.env.NODE_ENV = 'test';
test.after(() => {
  if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
});

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');
const {
  createReferenceMonotonicAnchorAuthority,
  createReferenceMonotonicAnchorStorage,
} = require('../server/monotonic-anchor-authority');
const {
  createReferenceAuditAcknowledgementRegistry,
  createReferenceAuditAcknowledgementSigner,
} = require('../server/audit-support-acknowledgement');

const protocol = require('../server/vendor-control-protocol');
const { KEY_PURPOSES, keyFingerprint } = require('../server/vendor-signed-artifact');
const {
  CANCELLATION_KIND,
  REQUEST_SIGNATURE_DOMAIN,
  assertAuditSupportRequest,
  payloadDigest: auditSupportPayloadDigest,
  signAuditSupportRequest,
} = require('../server/audit-support-control-artifacts');

const {
  createProductionVendorAuditSupportAuthority,
  createReferenceAuthenticatedCustomerRegistry,
  createReferenceOwnerAuditStepUpVerifier,
  createReferenceVendorAuditSupportAuthority,
} = require('../server/vendor-audit-support-authority');
const {
  openProductionVendorAuditSupportStore,
  openReferenceVendorAuditSupportSqlite,
} = require('../server/vendor-audit-support-sqlite');
const {
  CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN,
  createCustomerAuditResponseKeyRegistry,
  createCustomerAuditResponseSigner,
  verifyCustomerAuditResponse,
} = require('../server/customer-audit-response');
const {
  createCustomerAuditResponseOutboxWorker,
  createReferenceCustomerAuditIntegrityAuthority,
  createReferenceCustomerAuditWitnessAuthority,
  openCustomerAuditSupportSqlite,
  openProductionCustomerAuditSupportStore,
} = require('../server/customer-audit-support-store');
const {
  CustomerAuditSupportBroker,
  createProductionCustomerAuditSupportBroker,
  createReferenceAuditSummaryProvider,
  createReferenceLocalAuditAdminAuthorizer,
} = require('../server/customer-audit-support-broker');

const NOW = Date.parse('2026-07-13T12:00:00.000Z');
const CUSTOMER_ID = 'customer_alpha';
const DEPLOYMENT_ID = 'dep_11111111111111111111111111111111';
const SIBLING_DEPLOYMENT_ID = 'dep_22222222222222222222222222222222';
const REQUEST_CURRENT_ID = 'rw-audit-request-current';
const REQUEST_NEXT_ID = 'rw-audit-request-next';
const REQUEST_OLD_ID = 'rw-audit-request-old';
const RESPONSE_CURRENT_ID = 'rw-customer-audit-response-alpha-current';
const requestCurrent = crypto.generateKeyPairSync('ed25519');
const requestNext = crypto.generateKeyPairSync('ed25519');
const requestOld = crypto.generateKeyPairSync('ed25519');
const responseCurrent = crypto.generateKeyPairSync('ed25519');
const ACKNOWLEDGEMENT_KEY_ID = 'rw-audit-ack-customer-alpha';
const ACKNOWLEDGEMENT_SECRET = Buffer.alloc(32, 36);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function referenceAnchorAuthority(purpose, secretByte) {
  const storage = createReferenceMonotonicAnchorStorage();
  return createReferenceMonotonicAnchorAuthority({
    storage,
    keyId: `rw-anchor-${purpose.replaceAll('_', '-')}`,
    purpose,
    secret: Buffer.alloc(32, secretByte),
  });
}

function manifestRegistry(options = {}) {
  const active = new Map([
    [REQUEST_CURRENT_ID, requestCurrent.publicKey],
    [REQUEST_NEXT_ID, requestNext.publicKey],
  ]);
  const historical = new Map([[REQUEST_OLD_ID, requestOld.publicKey]]);
  return Object.freeze({
    activePublicKeys(purpose) {
      assert.equal(purpose, KEY_PURPOSES.AUDIT_REQUEST);
      return new Map(active);
    },
    assertPublicKey(purpose, keyId, fingerprint) {
      assert.equal(purpose, KEY_PURPOSES.AUDIT_REQUEST);
      const key = active.get(keyId);
      if (!key || keyFingerprint(key) !== fingerprint) {
        const error = new Error('manifest key mismatch');
        error.code = 'vendor_authority_manifest_mismatch';
        throw error;
      }
    },
    verificationPublicKey(purpose, keyId) {
      assert.equal(purpose, KEY_PURPOSES.AUDIT_REQUEST);
      const key = active.get(keyId) || historical.get(keyId);
      if (!key) throw new Error('manifest key missing');
      return new Map([[keyId, key]]);
    },
    assertHistoricalPublicKey(purpose, keyId, fingerprint) {
      assert.equal(purpose, KEY_PURPOSES.AUDIT_REQUEST);
      const key = active.get(keyId) || historical.get(keyId);
      if (!key || keyFingerprint(key) !== fingerprint) {
        const error = new Error('manifest historical key mismatch');
        error.code = 'vendor_authority_manifest_mismatch';
        throw error;
      }
    },
    historicalPublicKeys: () => new Map(historical),
    ...options,
  });
}

function responseKeyRecord(pair, keyId, validFrom, verifyUntil) {
  const record = {
    keyId,
    publicKey: pair.publicKey.export({ format: 'pem', type: 'spki' }),
    validFrom: new Date(validFrom).toISOString(),
  };
  if (verifyUntil !== undefined) record.verifyUntil = new Date(verifyUntil).toISOString();
  return record;
}

function responseRegistry(now = () => NOW, overrides = {}) {
  return createCustomerAuditResponseKeyRegistry({
    now,
    integrityKey: Buffer.alloc(32, 31),
    anchorAuthority: referenceAnchorAuthority('customer_audit_response_registry', 32),
    anchorNamespace: 'audit-response-registry:default',
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(responseCurrent, RESPONSE_CURRENT_ID, NOW - 60_000),
      next: null,
      verifyOnly: [],
      ...overrides,
    }],
  });
}

function responseSigner(options = {}) {
  return createCustomerAuditResponseSigner({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    keyId: RESPONSE_CURRENT_ID,
    privateKey: responseCurrent.privateKey,
    ...options,
  });
}

function acknowledgementSigner(options = {}) {
  return createReferenceAuditAcknowledgementSigner({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    keyId: ACKNOWLEDGEMENT_KEY_ID,
    secret: ACKNOWLEDGEMENT_SECRET,
    ...options,
  });
}

function acknowledgementRegistry(records = [{
  customerId: CUSTOMER_ID,
  deploymentId: DEPLOYMENT_ID,
  keyId: ACKNOWLEDGEMENT_KEY_ID,
  secret: ACKNOWLEDGEMENT_SECRET,
}]) {
  return createReferenceAuditAcknowledgementRegistry({ records });
}

function requestCommand(overrides = {}) {
  return {
    authEventId: '00000000-0000-4000-8000-000000000101',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    expiresAt: new Date(NOW + 60 * 60 * 1000).toISOString(),
    fields: ['integrity_status'],
    idempotencyKey: 'audit-issue-command-0001',
    maxRecords: 2,
    notBefore: new Date(NOW - 60_000).toISOString(),
    purposeCode: 'customer_support',
    requestId: '00000000-0000-4000-8000-000000000201',
    requestType: 'integrity_status',
    requestVersion: 1,
    ...overrides,
  };
}

function operationDigest(action, command) {
  return sha256(protocol.canonicalJson({ action, command }));
}

function deliveryReceipt(claim, payload, receivedAt, options = {}) {
  const receipt = {
    accepted: true,
    artifactDigest: claim.artifactDigest,
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    messageId: claim.messageId,
    receivedAt: new Date(receivedAt).toISOString(),
    requestDigest: options.requestDigest || auditSupportPayloadDigest(
      payload, REQUEST_SIGNATURE_DOMAIN,
    ),
    requestId: payload.requestId,
    requestVersion: payload.requestVersion,
  };
  if (options.cancellationDigest) receipt.cancellationDigest = options.cancellationDigest;
  return acknowledgementSigner({
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
  }).attest(receipt);
}

function ownerEvent(command, action = 'audit_support.issue', overrides = {}) {
  return {
    action,
    auditRef: 'owner_audit_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    authEventId: command.authEventId,
    authenticatedAt: new Date(NOW - 1000).toISOString(),
    credentialPurpose: 'vendor_audit_support',
    customerId: command.customerId,
    deploymentId: command.deploymentId,
    operationDigest: operationDigest(action, command),
    principalRef: sha256('owner-principal'),
    purposeCode: command.purposeCode,
    role: 'vendor_owner',
    stepUpAt: new Date(NOW - 2000).toISOString(),
    ...overrides,
  };
}

function buildVendor(command = requestCommand(), options = {}) {
  const store = options.store || openReferenceVendorAuditSupportSqlite({
    acknowledgementRegistry: options.acknowledgementRegistry || acknowledgementRegistry(),
  });
  const authority = createReferenceVendorAuditSupportAuthority({
    authorityRegistry: options.authorityRegistry || manifestRegistry(),
    signingSlot: options.signingSlot || {
      keyId: REQUEST_CURRENT_ID,
      privateKey: requestCurrent.privateKey,
    },
    customerRegistry: options.customerRegistry
      || createReferenceAuthenticatedCustomerRegistry({ records: [{
        auditRef: 'registry_audit_aaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        customerId: command.customerId,
        deploymentId: command.deploymentId,
        generation: 7,
        status: 'active',
      }] }),
    ownerStepUpVerifier: options.ownerStepUpVerifier
      || createReferenceOwnerAuditStepUpVerifier({ events: [ownerEvent(command)] }),
    responseKeyRegistry: options.responseKeyRegistry || responseRegistry(options.now),
    store,
    now: options.now || (() => NOW),
    messageId: options.messageId || (() => '00000000-0000-4000-8000-000000000301'),
  });
  return { authority, store };
}

function signedRequest(payload, pair = requestCurrent, keyId = REQUEST_CURRENT_ID) {
  return signAuditSupportRequest(payload, { keyId, privateKey: pair.privateKey });
}

function localAuthorization(payload, requestDigest, action, suffix = '1') {
  return {
    action,
    auditRef: `local_audit_${'a'.repeat(30)}${suffix}`,
    authEventId: `00000000-0000-4000-8000-0000000004${suffix.padStart(2, '0')}`,
    authenticatedAt: new Date(NOW - 1000).toISOString(),
    authorizationId: `00000000-0000-4000-8000-0000000005${suffix.padStart(2, '0')}`,
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    purposeCode: payload.purposeCode,
    requestDigest,
    requestId: payload.requestId,
    requestVersion: payload.requestVersion,
    role: 'security_admin',
    stepUpAt: new Date(NOW - 2000).toISOString(),
  };
}

function buildCustomer(signedArtifact, options = {}) {
  const payload = signedArtifact.payload;
  const digest = auditSupportPayloadDigest(payload, REQUEST_SIGNATURE_DOMAIN);
  const actions = options.actions || ['approve'];
  const authEvents = actions.map((action, index) => localAuthorization(
    payload, digest, action, String(index + 1),
  ));
  const summaryProvider = options.summaryProvider || createReferenceAuditSummaryProvider({
    summaries: [{
      field: 'integrity_status', valueCode: 'intact', version: null,
      coarseTimestamp: null, count: 1,
    }],
  });
  const store = options.store || openCustomerAuditSupportSqlite({
    path: options.path,
    witnessPath: options.witnessPath,
    integrityAuthority: options.integrityAuthority
      || createReferenceCustomerAuditIntegrityAuthority({
        keyId: 'customer-audit-reference-v1',
        secret: Buffer.alloc(32, 7),
      }),
    witnessAuthority: options.witnessAuthority
      || createReferenceCustomerAuditWitnessAuthority({
        keyId: 'customer-audit-witness-reference-v1',
        secret: Buffer.alloc(32, 8),
      }),
    anchorAuthority: options.anchorAuthority
      || referenceAnchorAuthority('customer_audit_support', 9),
    anchorNamespace: options.anchorNamespace
      || `audit-support:${payload.customerId}:${payload.deploymentId}`,
  });
  const broker = new CustomerAuditSupportBroker({
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    authorityRegistry: options.authorityRegistry || manifestRegistry(),
    store,
    localAdminAuthorizer: options.localAdminAuthorizer
      || createReferenceLocalAuditAdminAuthorizer({ events: authEvents }),
    summaryProvider,
    responseSigner: options.responseSigner || responseSigner({
      customerId: payload.customerId,
      deploymentId: payload.deploymentId,
    }),
    acknowledgementSigner: options.acknowledgementSigner || acknowledgementSigner({
      customerId: payload.customerId,
      deploymentId: payload.deploymentId,
    }),
    now: options.now || (() => NOW),
    messageId: options.messageId || (() => '00000000-0000-4000-8000-000000000601'),
  });
  return { authEvents, broker, digest, store, summaryProvider };
}

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

test('production audit/support constructors fail closed until managed adapters exist', () => {
  assert.throws(
    () => createProductionVendorAuditSupportAuthority({
      assurance: 'production', productionReady: true, driver: 'postgres',
    }),
    (error) => error && error.code === 'audit_support_owner_step_up_adapter_unavailable',
  );
  assert.throws(
    () => openProductionVendorAuditSupportStore({
      assurance: 'production', productionReady: true, driver: 'postgres',
    }),
    (error) => error && error.code === 'audit_support_postgres_adapter_unavailable',
  );
  assert.throws(
    () => openProductionCustomerAuditSupportStore({
      assurance: 'production', productionReady: true, driver: 'postgres',
    }),
    (error) => error && error.code === 'customer_audit_root_db_adapter_required',
  );
  assert.throws(
    () => createProductionCustomerAuditSupportBroker({
      assurance: 'production', productionReady: true,
    }),
    (error) => error && error.code === 'customer_audit_root_db_adapter_required',
  );
});

test('every audit/support reference factory refuses NODE_ENV production directly', () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    for (const factory of [
      () => createReferenceVendorAuditSupportAuthority(),
      () => createReferenceAuthenticatedCustomerRegistry(),
      () => createReferenceOwnerAuditStepUpVerifier(),
      () => openReferenceVendorAuditSupportSqlite(),
    ]) expectCode(factory, 'audit_support_reference_runtime_forbidden');
    for (const factory of [
      () => createReferenceCustomerAuditIntegrityAuthority(),
      () => createReferenceCustomerAuditWitnessAuthority(),
      () => openCustomerAuditSupportSqlite(),
      () => createCustomerAuditResponseOutboxWorker(),
    ]) expectCode(factory, 'customer_audit_reference_runtime_forbidden');
    for (const factory of [
      () => new CustomerAuditSupportBroker(),
      () => createReferenceLocalAuditAdminAuthorizer(),
      () => createReferenceAuditSummaryProvider(),
    ]) expectCode(factory, 'customer_audit_reference_runtime_forbidden');
    for (const factory of [
      () => createCustomerAuditResponseSigner(),
      () => createCustomerAuditResponseKeyRegistry(),
    ]) expectCode(factory, 'customer_response_reference_runtime_forbidden');
    for (const factory of [
      () => createReferenceAuditAcknowledgementSigner(),
      () => createReferenceAuditAcknowledgementRegistry(),
    ]) expectCode(factory, 'audit_acknowledgement_reference_runtime_forbidden');
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});

test('governed constructors are available only through explicit reference capabilities', () => {
  assert.equal(typeof createReferenceVendorAuditSupportAuthority, 'function');
  assert.equal(typeof createReferenceAuthenticatedCustomerRegistry, 'function');
  assert.equal(typeof createReferenceOwnerAuditStepUpVerifier, 'function');
  assert.equal(typeof openReferenceVendorAuditSupportSqlite, 'function');
  assert.equal(typeof createCustomerAuditResponseKeyRegistry, 'function');
  assert.equal(typeof createCustomerAuditResponseSigner, 'function');
  assert.equal(typeof createReferenceCustomerAuditIntegrityAuthority, 'function');
  assert.equal(typeof openCustomerAuditSupportSqlite, 'function');
  assert.equal(typeof CustomerAuditSupportBroker, 'function');
  assert.equal(typeof createReferenceAuditSummaryProvider, 'function');
  assert.equal(typeof createReferenceLocalAuditAdminAuthorizer, 'function');
  assert.equal(crypto.generateKeyPairSync('ed25519').privateKey.type, 'private');
});

test('vendor issue through customer approval produces one signed, scope-bound response', () => {
  const command = requestCommand();
  const vendor = buildVendor(command);
  const issued = vendor.authority.issue(command);
  assert.equal(issued.status, 'issued');
  assert.equal(issued.duplicate, false);
  assert.equal(issued.signedArtifact.payload.issuedAt, new Date(NOW).toISOString());
  const replay = vendor.authority.issue(command);
  assert.equal(replay.duplicate, true);
  assert.deepEqual(replay.signedArtifact, issued.signedArtifact);

  const customer = buildCustomer(issued.signedArtifact);
  assert.equal(customer.broker.receive(issued.signedArtifact).status, 'pending');
  expectCode(
    () => customer.broker.decide(command.requestId, 1, 'approve'),
    'audit_decision_invalid',
  );
  expectCode(
    () => customer.broker.respond(command.requestId, 1, []),
    'audit_response_command_invalid',
  );
  assert.equal(customer.summaryProvider.calls(), 0);
  customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: command.requestId,
    requestVersion: 1,
  });
  const envelope = customer.broker.respond({
    requestId: command.requestId,
    requestVersion: 1,
  });
  assert.equal(customer.summaryProvider.calls(), 1);
  assert.equal(envelope.payload.decision, 'approved');
  assert.equal(envelope.payload.requestDigest, issued.requestDigest);
  assert.equal(envelope.payload.localApprovalRef, customer.authEvents[0].auditRef);
  assert.equal(envelope.payload.summaries[0].valueCode, 'intact');
  assert.equal(Object.isFrozen(envelope), true);
  assert.deepEqual(customer.broker.respond({
    requestId: command.requestId,
    requestVersion: 1,
  }), envelope);

  const verified = verifyCustomerAuditResponse(envelope, responseRegistry());
  assert.equal(verified.signatureDomain, CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN);
  const accepted = vendor.authority.acceptResponse(envelope);
  assert.equal(accepted.status, 'responded');
  assert.equal(accepted.duplicate, false);
  assert.equal(vendor.authority.acceptResponse(envelope).duplicate, true);
  const lifecycle = vendor.authority.auditEvents().items.map((event) => event.eventType);
  assert.deepEqual(lifecycle, ['issued', 'customer_decision', 'response_received']);
  assert.equal(JSON.stringify(vendor.authority.auditEvents()).includes(CUSTOMER_ID), false);
  assert.equal(JSON.stringify(customer.broker.auditEvents()).includes(command.requestId), false);
});

test('vendor lifecycle durably records delivery, expiry, and Owner-authorized revocation', () => {
  const deliveredCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000211',
    idempotencyKey: 'audit-issue-command-0011',
  });
  const deliveredVendor = buildVendor(deliveredCommand);
  const delivered = deliveredVendor.authority.issue(deliveredCommand);
  const claimed = deliveredVendor.authority.claimDeliveries(1, new Date(NOW).toISOString());
  assert.equal(claimed.length, 1);
  assert.equal(claimed[0].requestDigest, delivered.requestDigest);
  const deliveryCommand = {
    artifactDigest: claimed[0].artifactDigest,
    claimToken: claimed[0].claimToken,
    idempotencyKey: 'audit-delivery-command-0011',
    messageId: claimed[0].messageId,
    receipt: deliveryReceipt(claimed[0], delivered.signedArtifact.payload, NOW + 30_000),
    requestDigest: delivered.requestDigest,
    requestId: deliveredCommand.requestId,
    requestVersion: 1,
  };
  const forgedReceipt = {
    ...deliveryCommand.receipt,
    acknowledgementMac: `${deliveryCommand.receipt.acknowledgementMac[0] === 'A' ? 'B' : 'A'}${deliveryCommand.receipt.acknowledgementMac.slice(1)}`,
  };
  expectCode(() => deliveredVendor.authority.markDelivered({
    ...deliveryCommand, receipt: forgedReceipt,
  }), 'audit_support_acknowledgement_invalid');
  assert.equal(deliveredVendor.authority.markDelivered(deliveryCommand).status, 'delivered');
  assert.equal(deliveredVendor.authority.markDelivered(deliveryCommand).duplicate, true);
  const deliveryEvidence = deliveredVendor.authority.get(deliveredCommand.requestId, 1);
  assert.equal(deliveryEvidence.deliveryAppliedAt, new Date(NOW + 30_000).toISOString());
  assert.equal(deliveryEvidence.deliveryAcknowledgementKeyId, ACKNOWLEDGEMENT_KEY_ID);
  assert.equal(
    deliveryEvidence.deliveryAcknowledgementDigest,
    sha256(protocol.canonicalJson(deliveryCommand.receipt)),
  );
  const deliveryAudit = deliveredVendor.authority.auditEvents().items.at(-1);
  assert.equal(deliveryAudit.acknowledgementDigest,
    deliveryEvidence.deliveryAcknowledgementDigest);
  assert.equal(deliveryAudit.acknowledgementAppliedAt, deliveryEvidence.deliveryAppliedAt);

  const skewedCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000210',
    idempotencyKey: 'audit-issue-command-0010',
  });
  const skewedVendor = buildVendor(skewedCommand);
  const skewed = skewedVendor.authority.issue(skewedCommand);
  const [skewedClaim] = skewedVendor.authority.claimDeliveries(
    1, new Date(NOW).toISOString(),
  );
  expectCode(() => skewedVendor.authority.markDelivered({
    artifactDigest: skewedClaim.artifactDigest,
    claimToken: skewedClaim.claimToken,
    idempotencyKey: 'audit-delivery-command-0010',
    messageId: skewedClaim.messageId,
    receipt: deliveryReceipt(
      skewedClaim, skewed.signedArtifact.payload, NOW + 60_001,
    ),
    requestDigest: skewed.requestDigest,
    requestId: skewedCommand.requestId,
    requestVersion: 1,
  }), 'audit_support_transition_invalid');

  const expiringCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000212',
    idempotencyKey: 'audit-issue-command-0012',
  });
  const expiringVendor = buildVendor(expiringCommand);
  const expiring = expiringVendor.authority.issue(expiringCommand);
  assert.equal(expiringVendor.authority.expire({
    idempotencyKey: 'audit-expire-command-0012',
    requestDigest: expiring.requestDigest,
    requestId: expiringCommand.requestId,
    requestVersion: 1,
  }).status, 'expired');

  const revokingCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000213',
    idempotencyKey: 'audit-issue-command-0013',
  });
  const store = openReferenceVendorAuditSupportSqlite({
    acknowledgementRegistry: acknowledgementRegistry(),
  });
  const firstAuthority = buildVendor(revokingCommand, { store }).authority;
  const revoking = firstAuthority.issue(revokingCommand);
  const revokeCommand = {
    authEventId: '00000000-0000-4000-8000-000000000113',
    idempotencyKey: 'audit-revoke-command-0013',
    requestDigest: revoking.requestDigest,
    requestId: revokingCommand.requestId,
    requestVersion: 1,
  };
  const revokeEvent = {
    action: 'audit_support.revoke',
    auditRef: 'owner_audit_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    authEventId: revokeCommand.authEventId,
    authenticatedAt: new Date(NOW - 1000).toISOString(),
    credentialPurpose: 'vendor_audit_support',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    operationDigest: operationDigest('audit_support.revoke', revokeCommand),
    principalRef: sha256('owner-revoker'),
    purposeCode: revokingCommand.purposeCode,
    role: 'vendor_security_admin',
    stepUpAt: new Date(NOW - 2000).toISOString(),
  };
  const secondAuthority = buildVendor(revokingCommand, {
    store,
    ownerStepUpVerifier: createReferenceOwnerAuditStepUpVerifier({
      events: [ownerEvent(revokingCommand), revokeEvent],
    }),
  }).authority;
  assert.equal(secondAuthority.revoke(revokeCommand).status, 'revoked');
  assert.deepEqual(
    secondAuthority.auditEvents().items.map((event) => event.eventType),
    ['issued', 'revoked'],
  );
});

test('signed vendor cancellation survives retries and blocks customer responses after restart', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-audit-cancel-'));
  const vendorPath = path.join(tempDir, 'vendor.db');
  const customerPath = path.join(tempDir, 'customer.db');
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000214',
    idempotencyKey: 'audit-issue-command-0014',
  });
  const revokeCommand = {
    authEventId: '00000000-0000-4000-8000-000000000114',
    idempotencyKey: 'audit-revoke-command-0014',
    requestDigest: null,
    requestId: command.requestId,
    requestVersion: 1,
  };
  const revokeVerifier = (requestDigest) => createReferenceOwnerAuditStepUpVerifier({ events: [
    ownerEvent(command),
    ownerEvent({
      ...revokeCommand,
      customerId: command.customerId,
      deploymentId: command.deploymentId,
      purposeCode: command.purposeCode,
      requestDigest,
    }, 'audit_support.revoke', {
      auditRef: 'owner_audit_cccccccccccccccccccccccccccccccc',
      operationDigest: operationDigest('audit_support.revoke', {
        ...revokeCommand, requestDigest,
      }),
      purposeCode: command.purposeCode,
      role: 'vendor_security_admin',
    }),
  ] });
  const vendorAcknowledgements = acknowledgementRegistry();
  let vendorStore = openReferenceVendorAuditSupportSqlite({
    path: vendorPath, acknowledgementRegistry: vendorAcknowledgements,
  });
  let vendor = buildVendor(command, { store: vendorStore }).authority;
  const issued = vendor.issue(command);
  revokeCommand.requestDigest = issued.requestDigest;
  vendor = buildVendor(command, {
    store: vendorStore,
    ownerStepUpVerifier: revokeVerifier(issued.requestDigest),
  }).authority;

  const integrityAuthority = createReferenceCustomerAuditIntegrityAuthority({
    keyId: 'customer-audit-cancel-v1', secret: Buffer.alloc(32, 18),
  });
  const anchorAuthority = referenceAnchorAuthority('customer_audit_support', 19);
  const anchorNamespace = 'audit-support:cancel-restart';
  let customer = buildCustomer(issued.signedArtifact, {
    path: customerPath, integrityAuthority, anchorAuthority, anchorNamespace,
  });
  customer.broker.receive(issued.signedArtifact);
  const revoked = vendor.revoke(revokeCommand);
  assert.equal(revoked.status, 'revoked');
  assert.equal(revoked.signedCancellation.payload.kind, CANCELLATION_KIND);
  assert.equal(revoked.signedCancellation.payload.requestDigest, issued.requestDigest);
  const cancellationApplied = customer.broker.receiveCancellation(revoked.signedCancellation);
  assert.equal(cancellationApplied.status, 'revoked');
  assert.equal(customer.broker.receiveCancellation(revoked.signedCancellation).duplicate, true);
  expectCode(() => customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: command.requestId,
    requestVersion: 1,
  }), 'audit_request_revoked');
  expectCode(() => customer.broker.respond({
    requestId: command.requestId,
    requestVersion: 1,
  }), 'audit_request_revoked');

  const [delivery] = vendor.claimDeliveries(1, new Date(NOW).toISOString());
  assert.equal(delivery.documentKind, CANCELLATION_KIND);
  assert.equal(delivery.document.payload.requestDigest, issued.requestDigest);
  assert.equal(vendor.markDeliveryRetry(
    delivery.messageId, delivery.artifactDigest, new Date(NOW + 1000).toISOString(),
    'network_timeout', delivery.claimToken,
  ), true);
  vendorStore.close();
  vendorStore = openReferenceVendorAuditSupportSqlite({
    path: vendorPath, acknowledgementRegistry: vendorAcknowledgements,
  });
  vendor = buildVendor(command, {
    store: vendorStore,
    ownerStepUpVerifier: revokeVerifier(issued.requestDigest),
    now: () => NOW + 1001,
  }).authority;
  const [retried] = vendor.claimDeliveries(1, new Date(NOW + 1001).toISOString());
  assert.deepEqual(retried.document, delivery.document);
  const persisted = vendor.get(command.requestId, 1);
  const delivered = vendor.markCancellationDelivered({
    artifactDigest: retried.artifactDigest,
    cancellationDigest: persisted.cancellationDigest,
    claimToken: retried.claimToken,
    idempotencyKey: 'audit-cancel-delivery-0014',
    messageId: retried.messageId,
    receipt: cancellationApplied.receipt,
    requestDigest: issued.requestDigest,
    requestId: command.requestId,
    requestVersion: 1,
  });
  assert.equal(delivered.status, 'revoked');
  const cancellationEvidence = vendor.get(command.requestId, 1);
  assert.equal(
    cancellationEvidence.cancellationAcknowledgementDigest,
    sha256(protocol.canonicalJson(cancellationApplied.receipt)),
  );
  assert.equal(
    cancellationEvidence.cancellationAcknowledgementKeyId, ACKNOWLEDGEMENT_KEY_ID,
  );
  assert.equal(cancellationEvidence.cancellationAppliedAt,
    cancellationApplied.receipt.receivedAt);
  assert.equal(vendor.markCancellationDelivered({
    artifactDigest: retried.artifactDigest,
    cancellationDigest: persisted.cancellationDigest,
    claimToken: retried.claimToken,
    idempotencyKey: 'audit-cancel-delivery-0014',
    messageId: retried.messageId,
    receipt: cancellationApplied.receipt,
    requestDigest: issued.requestDigest,
    requestId: command.requestId,
    requestVersion: 1,
  }).duplicate, true);

  vendor = buildVendor(command, {
    store: vendorStore,
    ownerStepUpVerifier: revokeVerifier(issued.requestDigest),
    now: () => NOW + 10 * 60 * 1000,
  }).authority;
  const revokeReplay = vendor.revoke(revokeCommand);
  assert.equal(revokeReplay.duplicate, true);
  assert.deepEqual(revokeReplay.signedCancellation, revoked.signedCancellation);

  customer.store.close();
  customer = buildCustomer(issued.signedArtifact, {
    path: customerPath, integrityAuthority, anchorAuthority, anchorNamespace,
    now: () => NOW + 30 * 60 * 1000,
  });
  assert.equal(customer.broker.getState(command.requestId, 1).status, 'revoked');
  const cancellationReplay = customer.broker.receiveCancellation(revoked.signedCancellation);
  assert.equal(cancellationReplay.duplicate, true);
  assert.deepEqual(cancellationReplay.receipt, cancellationApplied.receipt);
  expectCode(() => customer.broker.respond({
    requestId: command.requestId,
    requestVersion: 1,
  }), 'audit_request_revoked');
  customer.store.close();
  vendorStore.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('vendor retry mutation refuses a tampered audit chain', () => {
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000216',
    idempotencyKey: 'audit-issue-command-0016',
  });
  const vendor = buildVendor(command);
  vendor.authority.issue(command);
  const [claim] = vendor.authority.claimDeliveries(1, new Date(NOW).toISOString());
  vendor.store.database.prepare(`
    UPDATE vendor_audit_support_audit SET event_json = '{}' WHERE sequence = 1
  `).run();
  expectCode(() => vendor.authority.markDeliveryRetry(
    claim.messageId, claim.artifactDigest, new Date(NOW + 1000).toISOString(),
    'network_timeout', claim.claimToken,
  ), 'audit_support_audit_integrity_failed');
  assert.equal(vendor.store.database.prepare(`
    SELECT status FROM vendor_audit_support_outbox WHERE message_id = ?
  `).get(claim.messageId).status, 'sending');
});

test('final vendor cancellation lease fails readiness and becomes blocked after a crash', () => {
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000217',
    idempotencyKey: 'audit-issue-command-0017',
  });
  const store = openReferenceVendorAuditSupportSqlite({
    acknowledgementRegistry: acknowledgementRegistry(),
  });
  let vendor = buildVendor(command, { store }).authority;
  const issued = vendor.issue(command);
  const revokeCommand = {
    authEventId: '00000000-0000-4000-8000-000000000117',
    idempotencyKey: 'audit-revoke-command-0017',
    requestDigest: issued.requestDigest,
    requestId: command.requestId,
    requestVersion: 1,
  };
  vendor = buildVendor(command, {
    store,
    ownerStepUpVerifier: createReferenceOwnerAuditStepUpVerifier({ events: [
      ownerEvent(command),
      ownerEvent({
        ...revokeCommand,
        customerId: command.customerId,
        deploymentId: command.deploymentId,
        purposeCode: command.purposeCode,
      }, 'audit_support.revoke', {
        auditRef: 'owner_audit_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        operationDigest: operationDigest('audit_support.revoke', revokeCommand),
        role: 'vendor_security_admin',
      }),
    ] }),
  }).authority;
  vendor.revoke(revokeCommand);
  for (let attempt = 1; attempt < 16; attempt += 1) {
    const [claim] = vendor.claimDeliveries(1, new Date(NOW).toISOString());
    assert.equal(claim.attempts, attempt);
    assert.equal(vendor.markDeliveryRetry(
      claim.messageId, claim.artifactDigest, new Date(NOW).toISOString(),
      'network_timeout', claim.claimToken,
    ), true);
  }
  const [finalClaim] = vendor.claimDeliveries(1, new Date(NOW).toISOString());
  assert.equal(finalClaim.attempts, 16);
  const leaseExpiredAt = new Date(NOW + 60_001).toISOString();
  const degraded = vendor.readiness(leaseExpiredAt);
  assert.equal(degraded.ready, false);
  assert.equal(degraded.outboxExpiredFinalLeases, 1);
  assert.deepEqual(vendor.claimDeliveries(1, leaseExpiredAt), []);
  assert.equal(store.database.prepare(`
    SELECT status FROM vendor_audit_support_outbox WHERE message_id = ?
  `).get(finalClaim.messageId).status, 'blocked');
});

test('vendor cancellation cancels a prepared customer response before retry delivery', () => {
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000215',
    idempotencyKey: 'audit-issue-command-0015',
  });
  const store = openReferenceVendorAuditSupportSqlite({
    acknowledgementRegistry: acknowledgementRegistry(),
  });
  let vendor = buildVendor(command, { store }).authority;
  const issued = vendor.issue(command);
  const revokeCommand = {
    authEventId: '00000000-0000-4000-8000-000000000115',
    idempotencyKey: 'audit-revoke-command-0015',
    requestDigest: issued.requestDigest,
    requestId: command.requestId,
    requestVersion: 1,
  };
  const revokeEvent = ownerEvent({
    ...revokeCommand,
    customerId: command.customerId,
    deploymentId: command.deploymentId,
    purposeCode: command.purposeCode,
  }, 'audit_support.revoke', {
    auditRef: 'owner_audit_dddddddddddddddddddddddddddddddd',
    operationDigest: operationDigest('audit_support.revoke', revokeCommand),
    role: 'vendor_security_admin',
  });
  vendor = buildVendor(command, {
    store,
    ownerStepUpVerifier: createReferenceOwnerAuditStepUpVerifier({
      events: [ownerEvent(command), revokeEvent],
    }),
  }).authority;
  const customer = buildCustomer(issued.signedArtifact);
  customer.broker.receive(issued.signedArtifact);
  customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: command.requestId,
    requestVersion: 1,
  });
  const prepared = customer.broker.respond({
    requestId: command.requestId,
    requestVersion: 1,
  });
  assert.equal(customer.store.database.prepare(`
    SELECT status FROM customer_audit_support_outbox WHERE request_id = ?
  `).get(command.requestId).status, 'pending');
  const revoked = vendor.revoke(revokeCommand);
  customer.broker.receiveCancellation(revoked.signedCancellation);
  assert.equal(customer.store.database.prepare(`
    SELECT status FROM customer_audit_support_outbox WHERE request_id = ?
  `).get(command.requestId).status, 'cancelled');
  assert.deepEqual(customer.broker.claimResponses(1, new Date(NOW).toISOString()), []);
  expectCode(() => vendor.acceptResponse(prepared), 'audit_support_response_not_current');
});

test('customer broker produces terminal deny, expiry, and revoke responses without summaries', () => {
  const decisions = [
    ['deny', 'denied', 'customer_denied'],
    ['revoke', 'revoked', 'customer_revoked'],
  ];
  for (const [action, status, reasonCode] of decisions) {
    const command = requestCommand({
      requestId: action === 'deny'
        ? '00000000-0000-4000-8000-000000000221'
        : '00000000-0000-4000-8000-000000000222',
      idempotencyKey: action === 'deny'
        ? 'audit-issue-command-0021' : 'audit-issue-command-0022',
    });
    const issued = buildVendor(command).authority.issue(command);
    const customer = buildCustomer(issued.signedArtifact, {
      actions: action === 'revoke' ? ['approve', 'revoke'] : ['deny'],
    });
    customer.broker.receive(issued.signedArtifact);
    if (action === 'revoke') {
      customer.broker.decide({
        action: 'approve',
        authorizationId: customer.authEvents[0].authorizationId,
        requestId: command.requestId,
        requestVersion: 1,
      });
      customer.broker.decide({
        action: 'revoke',
        authorizationId: customer.authEvents[1].authorizationId,
        requestId: command.requestId,
        requestVersion: 1,
      });
    } else {
      customer.broker.decide({
        action,
        authorizationId: customer.authEvents[0].authorizationId,
        requestId: command.requestId,
        requestVersion: 1,
      });
    }
    const response = customer.broker.respond({
      requestId: command.requestId,
      requestVersion: 1,
    });
    assert.equal(response.payload.status, status);
    assert.equal(response.payload.reasonCode, reasonCode);
    assert.deepEqual(response.payload.summaries, []);
    assert.equal(customer.summaryProvider.calls(), 0);
  }

  let nowMs = NOW;
  const expiringCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000223',
    idempotencyKey: 'audit-issue-command-0023',
    expiresAt: new Date(NOW + 1000).toISOString(),
  });
  const expiring = buildVendor(expiringCommand).authority.issue(expiringCommand);
  const expiringCustomer = buildCustomer(expiring.signedArtifact, { now: () => nowMs });
  expiringCustomer.broker.receive(expiring.signedArtifact);
  nowMs = NOW + 1001;
  assert.equal(expiringCustomer.broker.getState(expiringCommand.requestId, 1).status, 'expired');
  expectCode(() => expiringCustomer.broker.respond({
    requestId: expiringCommand.requestId,
    requestVersion: 1,
  }), 'audit_request_expired');
  assert.equal(expiringCustomer.broker.getState(expiringCommand.requestId, 1).status, 'expired');
});

test('lost customer responses retry byte-for-byte after a durable store restart', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-audit-support-'));
  const dbPath = path.join(tempDir, 'customer-audit.db');
  const integrityAuthority = createReferenceCustomerAuditIntegrityAuthority({
    keyId: 'customer-audit-restart-v1',
    secret: Buffer.alloc(32, 9),
  });
  const witnessAuthority = createReferenceCustomerAuditWitnessAuthority({
    keyId: 'customer-audit-restart-witness-v1',
    secret: Buffer.alloc(32, 10),
  });
  const anchorAuthority = referenceAnchorAuthority('customer_audit_support', 11);
  const anchorNamespace = 'audit-support:response-restart';
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000231',
    idempotencyKey: 'audit-issue-command-0031',
  });
  const issued = buildVendor(command).authority.issue(command);
  const digest = auditSupportPayloadDigest(
    issued.signedArtifact.payload, REQUEST_SIGNATURE_DOMAIN,
  );
  const event = localAuthorization(issued.signedArtifact.payload, digest, 'approve', '7');
  const authorizer = createReferenceLocalAuditAdminAuthorizer({ events: [event] });
  const provider = createReferenceAuditSummaryProvider({ summaries: [{
    field: 'integrity_status', valueCode: 'intact', version: null,
    coarseTimestamp: null, count: 1,
  }] });
  const signer = responseSigner();
  let nowMs = NOW;
  let firstStore;
  let secondStore;
  try {
    firstStore = openCustomerAuditSupportSqlite({
      path: dbPath, integrityAuthority, witnessAuthority, anchorAuthority, anchorNamespace,
    });
    const first = buildCustomer(issued.signedArtifact, {
      store: firstStore,
      localAdminAuthorizer: authorizer,
      summaryProvider: provider,
      responseSigner: signer,
      now: () => nowMs,
    });
    first.broker.receive(issued.signedArtifact);
    first.broker.decide({
      action: 'approve',
      authorizationId: event.authorizationId,
      requestId: command.requestId,
      requestVersion: 1,
    });
    const original = first.broker.respond({
      requestId: command.requestId,
      requestVersion: 1,
    });
    const claim = first.broker.claimResponses(1, new Date(nowMs).toISOString())[0];
    assert.deepEqual(claim.document, original);
    assert.equal(first.broker.markResponseRetry(
      claim.messageId,
      claim.responseDigest,
      new Date(nowMs + 1000).toISOString(),
      'network_unavailable',
      claim.claimToken,
    ), true);
    firstStore.close();
    firstStore = null;

    nowMs += 2000;
    secondStore = openCustomerAuditSupportSqlite({
      path: dbPath, integrityAuthority, witnessAuthority, anchorAuthority, anchorNamespace,
    });
    const restarted = buildCustomer(issued.signedArtifact, {
      store: secondStore,
      localAdminAuthorizer: authorizer,
      summaryProvider: provider,
      responseSigner: signer,
      now: () => nowMs,
    });
    assert.deepEqual(restarted.broker.respond({
      requestId: command.requestId,
      requestVersion: 1,
    }), original);
    assert.equal(provider.calls(), 1);
    let deliveredEnvelope;
    const worker = createCustomerAuditResponseOutboxWorker({
      store: secondStore,
      clock: () => nowMs,
      send: async ({ messageId, responseDigest, envelope }) => {
        deliveredEnvelope = envelope;
        return { accepted: true, messageId, responseDigest };
      },
    });
    assert.deepEqual(await worker.runOnce(1), [{
      messageId: original.payload.messageId,
      status: 'delivered',
    }]);
    assert.deepEqual(deliveredEnvelope, original);
    assert.equal(secondStore.readiness(new Date(nowMs).toISOString()).ready, true);
  } finally {
    if (firstStore) firstStore.close();
    if (secondStore) secondStore.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('customer witness rejects state deletion, audit truncation, time reset, and rollback', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-audit-witness-'));
  const mainPath = path.join(tempDir, 'current.db');
  const witnessPath = path.join(tempDir, 'current.witness.db');
  const oldPath = path.join(tempDir, 'old.db');
  const oldWitnessPath = path.join(tempDir, 'old.witness.db');
  const integrityAuthority = createReferenceCustomerAuditIntegrityAuthority({
    keyId: 'customer-audit-anchor-integrity-v1', secret: Buffer.alloc(32, 21),
  });
  const witnessAuthority = createReferenceCustomerAuditWitnessAuthority({
    keyId: 'customer-audit-anchor-witness-v1', secret: Buffer.alloc(32, 22),
  });
  const anchorAuthority = referenceAnchorAuthority('customer_audit_support', 23);
  const anchorNamespace = 'audit-support:tamper-proof';
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000235',
    idempotencyKey: 'audit-issue-command-0035',
  });
  const issued = buildVendor(command).authority.issue(command);
  let customer = buildCustomer(issued.signedArtifact, {
    path: mainPath, witnessPath, integrityAuthority, witnessAuthority,
    anchorAuthority, anchorNamespace,
  });
  customer.broker.receive(issued.signedArtifact);
  customer.store.close();
  fs.copyFileSync(mainPath, oldPath);
  fs.copyFileSync(witnessPath, oldWitnessPath);

  customer = buildCustomer(issued.signedArtifact, {
    path: mainPath, witnessPath, integrityAuthority, witnessAuthority,
    anchorAuthority, anchorNamespace,
  });
  customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: command.requestId,
    requestVersion: 1,
  });
  customer.broker.respond({ requestId: command.requestId, requestVersion: 1 });
  customer.store.close();

  const reopened = openCustomerAuditSupportSqlite({
    path: mainPath, witnessPath, integrityAuthority, witnessAuthority,
    anchorAuthority, anchorNamespace,
  });
  assert.equal(reopened.auditEvents().items.length, 3);
  reopened.close();
  const baselineMain = path.join(tempDir, 'baseline.db');
  const baselineWitness = path.join(tempDir, 'baseline.witness.db');
  fs.copyFileSync(mainPath, baselineMain);
  fs.copyFileSync(witnessPath, baselineWitness);

  const assertTamperRejected = (name, tamper, code) => {
    const candidateMain = path.join(tempDir, `${name}.db`);
    const candidateWitness = path.join(tempDir, `${name}.witness.db`);
    fs.copyFileSync(baselineMain, candidateMain);
    fs.copyFileSync(baselineWitness, candidateWitness);
    tamper(candidateMain, candidateWitness);
    expectCode(() => openCustomerAuditSupportSqlite({
      path: candidateMain,
      witnessPath: candidateWitness,
      integrityAuthority,
      witnessAuthority,
      anchorAuthority,
      anchorNamespace,
    }), code);
  };
  const mutateMain = (sql) => (candidateMain) => {
    const database = new Database(candidateMain);
    database.exec(sql);
    database.close();
  };
  assertTamperRejected('state-delete', mutateMain(
    'DELETE FROM customer_audit_support_requests',
  ), 'customer_audit_snapshot_rewind');
  assertTamperRejected('audit-truncate', mutateMain(
    'DELETE FROM customer_audit_support_audit WHERE sequence = '
      + '(SELECT MAX(sequence) FROM customer_audit_support_audit)',
  ), 'customer_audit_snapshot_rewind');
  assertTamperRejected('outbox-delete', mutateMain(
    'DELETE FROM customer_audit_support_outbox',
  ), 'customer_audit_snapshot_rewind');
  assertTamperRejected('time-reset', mutateMain(
    'UPDATE customer_audit_support_meta SET trusted_time_ms = 0',
  ), 'customer_audit_integrity_failed');
  assertTamperRejected('witness-delete', (_candidateMain, candidateWitness) => {
    fs.rmSync(candidateWitness);
  }, 'customer_audit_witness_missing');
  assertTamperRejected('planted-genesis', (candidateMain, candidateWitness) => {
    fs.rmSync(candidateWitness);
    const database = new Database(candidateMain);
    database.exec(`
      UPDATE customer_audit_support_meta
      SET generation = 0, trusted_time_ms = 0, state_digest = '${'0'.repeat(64)}',
        outbox_digest = '${'0'.repeat(64)}', audit_sequence = 0,
        audit_head = '${'0'.repeat(64)}', meta_mac = ''
    `);
    database.close();
  }, 'customer_audit_anchor_mismatch');
  assertTamperRejected('main-witness-pair-rollback', (candidateMain, candidateWitness) => {
    fs.copyFileSync(oldPath, candidateMain);
    fs.copyFileSync(oldWitnessPath, candidateWitness);
  }, 'customer_audit_anchor_mismatch');

  const proof = new Database(baselineMain);
  proof.prepare('ATTACH DATABASE ? AS proof_witness').run(baselineWitness);
  const meta = proof.prepare(`
    SELECT generation, trusted_time_ms, state_digest, outbox_digest,
      audit_sequence, audit_head FROM customer_audit_support_meta WHERE singleton = 1
  `).get();
  const anchor = proof.prepare(`
    SELECT generation, trusted_time_ms, state_digest, outbox_digest,
      audit_sequence, audit_head
    FROM proof_witness.customer_audit_support_anchor WHERE singleton = 1
  `).get();
  assert.deepEqual(anchor, meta);
  proof.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('final customer response lease fails readiness and a newer request cancels the block', () => {
  const firstCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000236',
    idempotencyKey: 'audit-issue-command-0036',
  });
  const secondCommand = requestCommand({
    authEventId: '00000000-0000-4000-8000-000000000137',
    idempotencyKey: 'audit-issue-command-0037',
    requestId: firstCommand.requestId,
    requestVersion: 2,
  });
  const ids = [
    '00000000-0000-4000-8000-000000000336',
    '00000000-0000-4000-8000-000000000337',
  ];
  const vendor = buildVendor(firstCommand, {
    messageId: () => ids.shift(),
    ownerStepUpVerifier: createReferenceOwnerAuditStepUpVerifier({
      events: [ownerEvent(firstCommand), ownerEvent(secondCommand)],
    }),
  });
  const first = vendor.authority.issue(firstCommand);
  const customer = buildCustomer(first.signedArtifact);
  customer.broker.receive(first.signedArtifact);
  customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: firstCommand.requestId,
    requestVersion: 1,
  });
  customer.broker.respond({ requestId: firstCommand.requestId, requestVersion: 1 });
  for (let attempt = 1; attempt < 16; attempt += 1) {
    const [claim] = customer.broker.claimResponses(1, new Date(NOW).toISOString());
    assert.equal(claim.attempts, attempt);
    assert.equal(customer.broker.markResponseRetry(
      claim.messageId, claim.responseDigest, new Date(NOW).toISOString(),
      'network_unavailable', claim.claimToken,
    ), true);
  }
  const [finalClaim] = customer.broker.claimResponses(1, new Date(NOW).toISOString());
  assert.equal(finalClaim.attempts, 16);
  const leaseExpiredAt = new Date(NOW + 60_001).toISOString();
  const degraded = customer.store.readiness(leaseExpiredAt);
  assert.equal(degraded.ready, false);
  assert.equal(degraded.outboxExpiredFinalLeases, 1);
  assert.deepEqual(customer.broker.claimResponses(1, leaseExpiredAt), []);
  assert.equal(customer.store.database.prepare(`
    SELECT status FROM customer_audit_support_outbox WHERE request_id = ?
  `).get(firstCommand.requestId).status, 'blocked');

  const second = vendor.authority.issue(secondCommand);
  customer.broker.receive(second.signedArtifact);
  assert.equal(customer.store.database.prepare(`
    SELECT status FROM customer_audit_support_outbox WHERE request_id = ?
  `).get(firstCommand.requestId).status, 'cancelled');
});

test('same-version conflicts, request key slots, and persisted clock rollback fail closed', () => {
  let nowMs = NOW;
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000241',
    idempotencyKey: 'audit-issue-command-0041',
  });
  const issued = buildVendor(command).authority.issue(command);
  const customer = buildCustomer(issued.signedArtifact, { now: () => nowMs });
  customer.broker.receive(issued.signedArtifact);
  const conflicting = {
    ...issued.signedArtifact.payload,
    messageId: '00000000-0000-4000-8000-000000000341',
    purposeCode: 'security_incident',
  };
  expectCode(() => customer.broker.receive(signedRequest(conflicting)), 'audit_version_conflict');

  const next = {
    ...issued.signedArtifact.payload,
    messageId: '00000000-0000-4000-8000-000000000342',
    requestVersion: 2,
    purposeCode: 'security_incident',
  };
  const nextState = customer.broker.receive(signedRequest(next, requestNext, REQUEST_NEXT_ID));
  assert.equal(nextState.requestVersion, 2);
  assert.equal(nextState.previousDigest, issued.requestDigest);

  const historical = {
    ...issued.signedArtifact.payload,
    messageId: '00000000-0000-4000-8000-000000000343',
    requestId: '00000000-0000-4000-8000-000000000242',
  };
  assert.equal(
    customer.broker.receive(signedRequest(historical, requestOld, REQUEST_OLD_ID)).status,
    'pending',
  );
  nowMs = NOW - 5 * 60 * 1000 - 1;
  expectCode(() => customer.broker.getState(command.requestId, 2), 'audit_clock_rollback');

  expectCode(() => buildVendor(command, {
    signingSlot: { keyId: REQUEST_OLD_ID, privateKey: requestOld.privateKey },
  }), 'audit_support_signing_slot_not_active');
  const nextVendor = buildVendor(command, {
    signingSlot: { keyId: REQUEST_NEXT_ID, privateKey: requestNext.privateKey },
  });
  assert.equal(nextVendor.authority.issue(command).signedArtifact.keyId, REQUEST_NEXT_ID);
});

test('customer response registry accepts current, next, and bounded historical keys only', () => {
  let nowMs = NOW;
  const oldPair = crypto.generateKeyPairSync('ed25519');
  const nextPair = crypto.generateKeyPairSync('ed25519');
  const oldKeyId = 'rw-customer-audit-response-alpha-old';
  const nextKeyId = 'rw-customer-audit-response-alpha-next';
  const anchorAuthority = referenceAnchorAuthority('customer_audit_response_registry', 34);
  const registry = createCustomerAuditResponseKeyRegistry({
    now: () => nowMs,
    integrityKey: Buffer.alloc(32, 32),
    anchorAuthority,
    anchorNamespace: 'audit-response-registry:slots',
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(responseCurrent, RESPONSE_CURRENT_ID, NOW - 60_000),
      next: responseKeyRecord(nextPair, nextKeyId, NOW - 60_000),
      verifyOnly: [responseKeyRecord(
        oldPair, oldKeyId, NOW - 24 * 60 * 60 * 1000, NOW + 60 * 60 * 1000,
      )],
    }],
  });
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000251',
    idempotencyKey: 'audit-issue-command-0051',
  });
  const vendor = buildVendor(command, { responseKeyRegistry: registry });
  const issued = vendor.authority.issue(command);
  const oldSigner = createCustomerAuditResponseSigner({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    keyId: oldKeyId,
    privateKey: oldPair.privateKey,
  });
  const customer = buildCustomer(issued.signedArtifact, { responseSigner: oldSigner });
  customer.broker.receive(issued.signedArtifact);
  customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: command.requestId,
    requestVersion: 1,
  });
  const historicalEnvelope = customer.broker.respond({
    requestId: command.requestId,
    requestVersion: 1,
  });
  assert.equal(verifyCustomerAuditResponse(historicalEnvelope, registry).keyId, oldKeyId);
  assert.equal(vendor.authority.acceptResponse(historicalEnvelope).status, 'responded');

  const nextSigner = createCustomerAuditResponseSigner({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    keyId: nextKeyId,
    privateKey: nextPair.privateKey,
  });
  assert.equal(
    verifyCustomerAuditResponse(nextSigner.sign(historicalEnvelope.payload), registry).keyId,
    nextKeyId,
  );
  nowMs = NOW + 60 * 60 * 1000 + 1;
  expectCode(
    () => verifyCustomerAuditResponse(historicalEnvelope, registry),
    'customer_response_signature_invalid',
  );
  assert.equal(vendor.authority.acceptResponse(historicalEnvelope).duplicate, true);
});

test('acknowledgement registry rejects cross-silo key and secret reuse', () => {
  const beta = {
    customerId: 'customer_beta',
    deploymentId: SIBLING_DEPLOYMENT_ID,
    keyId: 'rw-audit-ack-customer-beta',
    secret: ACKNOWLEDGEMENT_SECRET,
  };
  expectCode(() => acknowledgementRegistry([{
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    keyId: ACKNOWLEDGEMENT_KEY_ID,
    secret: ACKNOWLEDGEMENT_SECRET,
  }, beta]), 'audit_acknowledgement_registry_invalid');
  expectCode(() => acknowledgementRegistry([{
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    keyId: ACKNOWLEDGEMENT_KEY_ID,
    secret: ACKNOWLEDGEMENT_SECRET,
  }, {
    ...beta,
    keyId: ACKNOWLEDGEMENT_KEY_ID,
    secret: Buffer.alloc(32, 37),
  }]), 'audit_acknowledgement_registry_invalid');
});

test('response-key generations preserve tombstones and trusted expiry across restart', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-response-registry-'));
  const registryPath = path.join(tempDir, 'registry.db');
  const witnessPath = path.join(tempDir, 'registry.witness.db');
  const oldMainPath = path.join(tempDir, 'registry-generation-2.db');
  const rollbackPath = path.join(tempDir, 'registry-rollback.db');
  const rollbackWitnessPath = path.join(tempDir, 'registry-rollback.witness.db');
  const oldWitnessPath = path.join(tempDir, 'registry-generation-2.witness.db');
  const integrityKey = Buffer.alloc(32, 33);
  const anchorAuthority = referenceAnchorAuthority('customer_audit_response_registry', 35);
  const anchorNamespace = 'audit-response-registry:durable';
  const nextPair = crypto.generateKeyPairSync('ed25519');
  const laterPair = crypto.generateKeyPairSync('ed25519');
  const replacementPair = crypto.generateKeyPairSync('ed25519');
  const nextKeyId = 'rw-customer-audit-response-rotation-next';
  const laterKeyId = 'rw-customer-audit-response-rotation-later';
  const replacementKeyId = 'rw-customer-audit-response-rotation-reused';
  const validFrom = NOW - 60_000;
  let nowMs = NOW;
  let registry = createCustomerAuditResponseKeyRegistry({
    path: registryPath,
    witnessPath,
    integrityKey,
    anchorAuthority,
    anchorNamespace,
    now: () => nowMs,
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(responseCurrent, RESPONSE_CURRENT_ID, validFrom),
      next: responseKeyRecord(nextPair, nextKeyId, validFrom),
      verifyOnly: [],
    }],
  });
  const generation1 = registry.manifest();
  const generation2 = registry.install({
    generation: 2,
    previousRegistryDigest: generation1.registryDigest,
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(nextPair, nextKeyId, validFrom),
      next: responseKeyRecord(laterPair, laterKeyId, validFrom),
      verifyOnly: [responseKeyRecord(
        responseCurrent, RESPONSE_CURRENT_ID, validFrom, NOW + 60 * 60 * 1000,
      )],
    }],
  });
  assert.equal(generation2.generation, 2);
  assert.equal(generation2.previousRegistryDigest, generation1.registryDigest);
  expectCode(() => registry.install({
    generation: 2,
    previousRegistryDigest: generation1.registryDigest,
    entries: generation1.entries,
  }), 'customer_response_registry_generation_invalid');
  expectCode(() => registry.install({
    generation: 3,
    previousRegistryDigest: generation2.registryDigest,
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(nextPair, nextKeyId, validFrom),
      next: responseKeyRecord(laterPair, laterKeyId, validFrom),
      verifyOnly: [responseKeyRecord(
        responseCurrent, RESPONSE_CURRENT_ID, validFrom, NOW + 2 * 60 * 60 * 1000,
      )],
    }],
  }), 'customer_response_verify_window_extended');

  const oldSigner = responseSigner();
  const oldEnvelope = oldSigner.sign({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: '00000000-0000-4000-8000-000000000671',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.AUDIT_RESPONSE,
    requestId: '00000000-0000-4000-8000-000000000271',
    requestVersion: 1,
    requestDigest: sha256('registry-response-request'),
    decision: 'approved',
    status: 'completed',
    reasonCode: 'completed',
    respondedAt: new Date(NOW).toISOString(),
    summaries: [],
    localApprovalRef: `local_audit_${'r'.repeat(32)}`,
  });
  assert.equal(verifyCustomerAuditResponse(oldEnvelope, registry).keyId, RESPONSE_CURRENT_ID);
  nowMs = NOW + 60 * 60 * 1000 + 1;
  expectCode(() => verifyCustomerAuditResponse(oldEnvelope, registry),
    'customer_response_signature_invalid');
  registry.close();
  fs.copyFileSync(registryPath, oldMainPath);
  fs.copyFileSync(witnessPath, oldWitnessPath);

  nowMs = NOW - 24 * 60 * 60 * 1000;
  registry = createCustomerAuditResponseKeyRegistry({
    path: registryPath, witnessPath, integrityKey, now: () => nowMs,
    anchorAuthority, anchorNamespace,
  });
  expectCode(() => verifyCustomerAuditResponse(oldEnvelope, registry),
    'customer_response_signature_invalid');
  const generation3 = registry.install({
    generation: 3,
    previousRegistryDigest: generation2.registryDigest,
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(nextPair, nextKeyId, validFrom),
      next: responseKeyRecord(laterPair, laterKeyId, validFrom),
      verifyOnly: [],
    }],
  });
  assert.equal(generation3.tombstones[0].keyId, RESPONSE_CURRENT_ID);
  registry.close();

  registry = createCustomerAuditResponseKeyRegistry({
    path: registryPath, witnessPath, integrityKey, now: () => nowMs,
    anchorAuthority, anchorNamespace,
  });
  expectCode(() => registry.install({
    generation: 4,
    previousRegistryDigest: generation3.registryDigest,
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(responseCurrent, RESPONSE_CURRENT_ID, validFrom),
      next: responseKeyRecord(laterPair, laterKeyId, validFrom),
      verifyOnly: [],
    }],
  }), 'customer_response_key_retired');
  expectCode(() => registry.install({
    generation: 4,
    previousRegistryDigest: generation3.registryDigest,
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(laterPair, laterKeyId, validFrom),
      next: responseKeyRecord(replacementPair, RESPONSE_CURRENT_ID, validFrom),
      verifyOnly: [],
    }],
  }), 'customer_response_key_retired');
  expectCode(() => registry.install({
    generation: 4,
    previousRegistryDigest: generation3.registryDigest,
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(laterPair, laterKeyId, validFrom),
      next: responseKeyRecord(responseCurrent, replacementKeyId, validFrom),
      verifyOnly: [],
    }],
  }), 'customer_response_key_retired');
  expectCode(() => registry.install({
    generation: 4,
    previousRegistryDigest: generation3.registryDigest,
    entries: [{
      customerId: CUSTOMER_ID,
      deploymentId: DEPLOYMENT_ID,
      current: responseKeyRecord(laterPair, laterKeyId, validFrom),
      next: null,
      verifyOnly: [],
    }, {
      customerId: 'customer_beta',
      deploymentId: SIBLING_DEPLOYMENT_ID,
      current: responseKeyRecord(nextPair, nextKeyId, validFrom),
      next: null,
      verifyOnly: [],
    }],
  }), 'customer_response_key_identity_reused');
  registry.close();

  fs.copyFileSync(oldMainPath, rollbackPath);
  fs.copyFileSync(oldWitnessPath, rollbackWitnessPath);
  expectCode(() => createCustomerAuditResponseKeyRegistry({
    path: rollbackPath,
    witnessPath: rollbackWitnessPath,
    integrityKey,
    anchorAuthority,
    anchorNamespace,
    now: () => nowMs,
  }), 'customer_response_registry_anchor_mismatch');
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('two independent customer stores reject cross-silo request routing', () => {
  const alphaCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000261',
    idempotencyKey: 'audit-issue-command-0061',
  });
  const alphaArtifact = buildVendor(alphaCommand).authority.issue(alphaCommand).signedArtifact;
  const betaPayload = assertAuditSupportRequest({
    ...alphaArtifact.payload,
    customerId: 'customer_beta',
    deploymentId: SIBLING_DEPLOYMENT_ID,
    messageId: '00000000-0000-4000-8000-000000000361',
    requestId: '00000000-0000-4000-8000-000000000262',
  });
  const betaArtifact = signedRequest(betaPayload);
  const alpha = buildCustomer(alphaArtifact);
  const beta = buildCustomer(betaArtifact);
  assert.notEqual(alpha.store.database, beta.store.database);
  assert.equal(alpha.broker.receive(alphaArtifact).status, 'pending');
  assert.equal(beta.broker.receive(betaArtifact).status, 'pending');
  expectCode(() => beta.broker.receive(alphaArtifact), 'audit_customer_mismatch');
  assert.equal(beta.broker.getState(alphaCommand.requestId), null);
  assert.equal(alpha.broker.getState(betaPayload.requestId), null);
  assert.equal(alpha.store.database.prepare(
    'SELECT COUNT(*) AS count FROM customer_audit_support_requests',
  ).get().count, 1);
  assert.equal(beta.store.database.prepare(
    'SELECT COUNT(*) AS count FROM customer_audit_support_requests',
  ).get().count, 1);
});

test('free text, raw prompt fields, canaries, and overlong requests are rejected without audit leakage', () => {
  const marker = 'CANARY_RAW_PROMPT_12345';
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000271',
    idempotencyKey: 'audit-issue-command-0071',
  });
  const vendor = buildVendor(command);
  expectCode(() => vendor.authority.issue({ ...command, rawPrompt: marker }),
    'audit_support_issue_invalid');
  const longCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000272',
    idempotencyKey: 'audit-issue-command-0072',
    expiresAt: new Date(NOW + 24 * 60 * 60 * 1000 + 1).toISOString(),
  });
  const longVendor = buildVendor(longCommand);
  expectCode(() => longVendor.authority.issue(longCommand),
    'audit_support_request_window_invalid');

  const issued = vendor.authority.issue(command);
  const unsafeProvider = createReferenceAuditSummaryProvider({ summaries: [{
    field: 'integrity_status',
    valueCode: marker,
    version: null,
    coarseTimestamp: null,
    count: 1,
    note: marker,
  }] });
  const customer = buildCustomer(issued.signedArtifact, { summaryProvider: unsafeProvider });
  customer.broker.receive(issued.signedArtifact);
  customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: command.requestId,
    requestVersion: 1,
  });
  expectCode(() => customer.broker.respond({
    requestId: command.requestId,
    requestVersion: 1,
  }), 'customer_response_payload_invalid');
  const persisted = [
    ...customer.store.database.prepare(
      'SELECT record_json AS document FROM customer_audit_support_requests',
    ).all(),
    ...customer.store.database.prepare(
      'SELECT event_json AS document FROM customer_audit_support_audit',
    ).all(),
    ...customer.store.database.prepare(
      'SELECT document_json AS document FROM customer_audit_support_outbox',
    ).all(),
  ].map((row) => row.document).join('\n');
  assert.equal(persisted.includes(marker), false);
  assert.equal(JSON.stringify(customer.broker.auditEvents()).includes(marker), false);
  assert.equal(JSON.stringify(vendor.authority.auditEvents()).includes(marker), false);
  assert.equal(vendor.authority.auditEvents().items.length, 1);
  assert.equal(customer.store.readiness(new Date(NOW).toISOString()).ready, true);
});

test('only the latest request version remains actionable in both planes', () => {
  const firstCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000281',
    idempotencyKey: 'audit-issue-command-0081',
  });
  const secondCommand = requestCommand({
    authEventId: '00000000-0000-4000-8000-000000000182',
    requestId: firstCommand.requestId,
    requestVersion: 2,
    idempotencyKey: 'audit-issue-command-0082',
  });
  const verifier = createReferenceOwnerAuditStepUpVerifier({
    events: [ownerEvent(firstCommand), ownerEvent(secondCommand)],
  });
  const ids = [
    '00000000-0000-4000-8000-000000000381',
    '00000000-0000-4000-8000-000000000382',
  ];
  const vendor = buildVendor(firstCommand, {
    ownerStepUpVerifier: verifier,
    messageId: () => ids.shift(),
  });
  const first = vendor.authority.issue(firstCommand);
  const second = vendor.authority.issue(secondCommand);
  const customer = buildCustomer(first.signedArtifact);
  customer.broker.receive(first.signedArtifact);
  customer.broker.receive(second.signedArtifact);
  expectCode(() => customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: firstCommand.requestId,
    requestVersion: 1,
  }), 'audit_request_not_current');
  expectCode(() => customer.broker.respond({
    requestId: firstCommand.requestId,
    requestVersion: 1,
  }), 'audit_request_not_current');

  const secondCustomer = buildCustomer(first.signedArtifact);
  secondCustomer.broker.receive(first.signedArtifact);
  secondCustomer.broker.decide({
    action: 'approve',
    authorizationId: secondCustomer.authEvents[0].authorizationId,
    requestId: firstCommand.requestId,
    requestVersion: 1,
  });
  const staleEnvelope = secondCustomer.broker.respond({
    requestId: firstCommand.requestId,
    requestVersion: 1,
  });
  secondCustomer.broker.receive(second.signedArtifact);
  assert.equal(secondCustomer.store.database.prepare(`
    SELECT status FROM customer_audit_support_outbox WHERE request_id = ?
  `).get(firstCommand.requestId).status, 'cancelled');
  assert.deepEqual(
    secondCustomer.broker.claimResponses(1, new Date(NOW).toISOString()), [],
  );
  expectCode(() => vendor.authority.acceptResponse(staleEnvelope),
    'audit_support_response_not_current');
});

test('request lineage cannot cross customer scope or purpose between versions', () => {
  const firstCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000283',
    idempotencyKey: 'audit-issue-command-0083',
  });
  const store = openReferenceVendorAuditSupportSqlite({
    acknowledgementRegistry: acknowledgementRegistry(),
  });
  buildVendor(firstCommand, { store }).authority.issue(firstCommand);
  const crossScope = requestCommand({
    authEventId: '00000000-0000-4000-8000-000000000184',
    customerId: 'customer_beta',
    deploymentId: SIBLING_DEPLOYMENT_ID,
    idempotencyKey: 'audit-issue-command-0084',
    requestId: firstCommand.requestId,
    requestVersion: 2,
  });
  expectCode(() => buildVendor(crossScope, { store }).authority.issue(crossScope),
    'audit_support_request_lineage_invalid');
  const crossPurpose = requestCommand({
    authEventId: '00000000-0000-4000-8000-000000000185',
    idempotencyKey: 'audit-issue-command-0085',
    purposeCode: 'compliance_assistance',
    requestId: firstCommand.requestId,
    requestVersion: 2,
  });
  expectCode(() => buildVendor(crossPurpose, { store }).authority.issue(crossPurpose),
    'audit_support_request_lineage_invalid');
});

test('issuedAt binds activation and rejects a months-future notBefore', () => {
  const futureCommand = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000291',
    idempotencyKey: 'audit-issue-command-0091',
    notBefore: new Date(NOW + 90 * 24 * 60 * 60 * 1000).toISOString(),
    expiresAt: new Date(NOW + 90 * 24 * 60 * 60 * 1000 + 60 * 60 * 1000).toISOString(),
  });
  const vendor = buildVendor(futureCommand);
  expectCode(() => vendor.authority.issue(futureCommand),
    'audit_support_request_window_invalid');
});

test('vendor receive time rejects a backdated response after request expiry', () => {
  let vendorNow = NOW;
  const command = requestCommand({
    requestId: '00000000-0000-4000-8000-000000000292',
    idempotencyKey: 'audit-issue-command-0092',
    expiresAt: new Date(NOW + 1000).toISOString(),
  });
  const vendor = buildVendor(command, { now: () => vendorNow });
  const issued = vendor.authority.issue(command);
  const customer = buildCustomer(issued.signedArtifact);
  customer.broker.receive(issued.signedArtifact);
  customer.broker.decide({
    action: 'approve',
    authorizationId: customer.authEvents[0].authorizationId,
    requestId: command.requestId,
    requestVersion: 1,
  });
  const backdated = customer.broker.respond({
    requestId: command.requestId,
    requestVersion: 1,
  });
  vendorNow = NOW + 1001;
  expectCode(() => vendor.authority.acceptResponse(backdated),
    'audit_support_response_expired');
});
