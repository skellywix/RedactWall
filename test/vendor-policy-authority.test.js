'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../server/vendor-control-protocol');
const policyState = require('../server/connected-policy-state');
const policyProtocol = require('../server/vendor-policy-protocol');
const {
  createVendorPolicyAuthority,
  INTEGRITY_DOMAINS,
} = require('../server/vendor-policy-authority');
const { createMemoryPolicyExternalState } = require('../server/vendor-policy-external-state');
const { AUTHORITY_DEFINITIONS, KEY_PURPOSES } = require('../server/vendor-signed-artifact');

const NOW = Date.parse('2026-07-13T12:00:00.000Z');
const SCOPE_A = Object.freeze({
  customerId: 'cu-policy-a', deploymentId: 'dep_66666666666666666666666666666666',
});
const SCOPE_B = Object.freeze({
  customerId: 'cu-policy-b', deploymentId: 'dep_77777777777777777777777777777777',
});
const INTEGRITY_SECRET = Buffer.alloc(32, 0x31);
const PENDING_SECRET = Buffer.alloc(32, 0x42);

function createHarness() {
  const storage = memoryStorage();
  const keyOne = crypto.generateKeyPairSync('ed25519');
  const keyTwo = crypto.generateKeyPairSync('ed25519');
  const approvalKeys = crypto.generateKeyPairSync('ed25519');
  const approvalKeyId = 'rw-owner-policy-approval-1';
  const keyState = { current: 'rw-policy-signing-1', next: 'rw-policy-signing-2', epoch: 1 };
  const keyPairs = {
    'rw-policy-signing-1': keyOne,
    'rw-policy-signing-2': keyTwo,
  };
  const authorityManifest = ownerAuthorityManifest(keyPairs, keyState);
  const provider = () => ({
    archivedPublicKeys: Object.fromEntries(Object.entries(keyPairs)
      .map(([keyId, keys]) => [keyId, {
        publicKey: keys.publicKey, validFromEpoch: keyId.endsWith('1') ? 1 : 2, retireAfterEpoch: null,
      }])),
    current: {
      keyId: keyState.current,
      privateKey: keyPairs[keyState.current].privateKey,
      validFromEpoch: keyState.current.endsWith('1') ? 1 : 2,
      retireAfterEpoch: null,
    },
    next: keyState.next === null ? null
      : {
        keyId: keyState.next,
        privateKey: keyPairs[keyState.next].privateKey,
        validFromEpoch: 2,
        retireAfterEpoch: null,
      },
    epoch: keyState.epoch,
  });
  const externalState = createMemoryPolicyExternalState({ testOnly: true });
  const policyApprovalTrust = () => approvalTrust(
    approvalKeyId, approvalKeys.publicKey, authorityManifest,
  );
  const authority = createVendorPolicyAuthority({
    storage,
    externalState,
    allowTestExternalState: true,
    clock: () => NOW,
    randomUUID: crypto.randomUUID,
    policyIntegrityAuthority: { keyId: 'rw-policy-integrity-v1', secret: INTEGRITY_SECRET },
    policyWitnessAuthority: { keyId: 'rw-policy-witness-v1', secret: PENDING_SECRET },
    policySigningAuthority: provider,
    authorityManifest,
    policyApprovalTrust,
    policyApprovalActiveKeyIds: () => [approvalKeyId],
  });
  const policyTrust = () => trustForPolicy(
    keyPairs, keyState.epoch, authorityManifest, approvalKeys.publicKey,
  );
  return {
    authority,
    storage,
    keyState,
    keyPairs,
    approvalKeys,
    approvalKeyId,
    authorityManifest,
    externalState,
    provider,
    policyApprovalTrust,
    policyTrust: policyTrust(),
    refreshTrust() { this.policyTrust = policyTrust(); },
  };
}

function authorityOptions(harness, overrides = {}) {
  return {
    storage: memoryStorage(),
    externalState: createMemoryPolicyExternalState({ testOnly: true }),
    allowTestExternalState: true,
    clock: () => NOW,
    policyIntegrityAuthority: { keyId: 'rw-policy-integrity-v1', secret: INTEGRITY_SECRET },
    policyWitnessAuthority: { keyId: 'rw-policy-witness-v1', secret: PENDING_SECRET },
    policySigningAuthority: harness.provider,
    authorityManifest: harness.authorityManifest,
    policyApprovalTrust: harness.policyApprovalTrust,
    policyApprovalActiveKeyIds: () => [harness.approvalKeyId],
    ...overrides,
  };
}

function basePolicy(name, overrides = {}) {
  return {
    enforcementMode: 'warn',
    alwaysBlock: [...policyState.MANDATORY_ALWAYS_BLOCK],
    blockMinSeverity: 3,
    blockRiskScore: 60,
    blockUnapprovedAiDestinations: false,
    responseScanMode: 'flag',
    unmanagedInstalls: 'allow',
    licensing: { failClosed: true },
    audit: { required: true },
    blockedDestinations: [],
    blockedFileUploadDestinations: [],
    mcpBlockedTools: [],
    mcpApprovalRequiredTools: [],
    ...overrides,
  };
}

function authorization(storage, purpose, role, scope = null, actorId = `actor:${crypto.randomUUID()}`) {
  const authEventId = crypto.randomUUID();
  storage.data.authorizations.set(authEventId, {
    schemaVersion: 1,
    authEventId,
    actorId,
    actorRole: role,
    purposes: [purpose],
    customerId: scope?.customerId || null,
    deploymentId: scope?.deploymentId || null,
    authenticatedAt: new Date(NOW - 60_000).toISOString(),
    expiresAt: new Date(NOW + 10 * 60_000).toISOString(),
    stepUpAt: purpose === 'policy_customer_ack' || purpose === 'policy_distribution_status'
      ? null : new Date(NOW - 30_000).toISOString(),
  });
  return authEventId;
}

function confirmedCommand(storage, purpose, role, build, scope = null, actorId) {
  const authEventId = authorization(storage, purpose, role, scope, actorId);
  const confirmationId = crypto.randomUUID();
  const command = build({ authEventId, confirmationId });
  const operationDigest = commandDigest(command, purpose);
  storage.data.confirmations.set(confirmationId, {
    schemaVersion: 1,
    confirmationId,
    authEventId,
    purpose,
    operationDigest,
    confirmedAt: new Date(NOW - 20_000).toISOString(),
    expiresAt: new Date(NOW + 4 * 60_000).toISOString(),
  });
  return command;
}

function emergencyCommand(storage, scope, expectedRevision, rules, actors = {}) {
  const purpose = 'policy_emergency_deny';
  const authEventId = authorization(storage, purpose, 'vendor_security_admin', scope,
    actors.initiator || 'actor:emergency-initiator');
  const approverAuthEventId = authorization(storage, purpose, 'vendor_owner', scope,
    actors.approver || 'actor:emergency-approver');
  const confirmationId = crypto.randomUUID();
  const approvalId = crypto.randomUUID();
  const command = {
    approvalId,
    authEventId,
    confirmationId,
    ...scope,
    expectedRevision,
    rules,
  };
  const operationDigest = commandDigest(command, purpose);
  storage.data.confirmations.set(confirmationId, {
    schemaVersion: 1,
    confirmationId,
    authEventId,
    purpose,
    operationDigest,
    confirmedAt: new Date(NOW - 20_000).toISOString(),
    expiresAt: new Date(NOW + 4 * 60_000).toISOString(),
  });
  storage.data.approvals.set(approvalId, {
    schemaVersion: 1,
    approvalId,
    approverAuthEventId,
    purpose,
    operationDigest,
    approvedAt: new Date(NOW - 10_000).toISOString(),
    expiresAt: new Date(NOW + 4 * 60_000).toISOString(),
  });
  return command;
}

function commandDigest(command, purpose) {
  let normalized = clone(command);
  if (purpose === 'policy_global_publish') {
    normalized.globalPolicy = policyState.normalizeVendorPolicy(command.globalPolicy);
  } else if (['policy_distribution_create', 'policy_deployment_rollback'].includes(purpose)) {
    normalized.desiredOverlay = policyState.normalizePolicyOverlay(command.desiredOverlay);
  } else if (purpose === 'policy_emergency_deny') {
    normalized.rules = policyState.normalizePolicyOverlay(command.rules);
  }
  return digest(normalized);
}

function globalPublishCommand(harness, expectedGlobalVersion, globalPolicy) {
  return confirmedCommand(
    harness.storage,
    'policy_global_publish',
    'vendor_owner',
    ({ authEventId, confirmationId }) => {
      const core = { authEventId, confirmationId, expectedGlobalVersion, globalPolicy };
      return {
        ...core,
        ownerApprovalAttestation: ownerApprovalArtifact(
          harness, 'policy_global_publish', digest({
            ...core, globalPolicy: policyState.normalizeVendorPolicy(globalPolicy),
          }),
        ),
      };
    },
  );
}

function rollbackCommand(harness, expectedGlobalVersion, rollbackOfGlobalVersion) {
  return confirmedCommand(
    harness.storage,
    'policy_global_rollback',
    'vendor_owner',
    ({ authEventId, confirmationId }) => {
      const core = { authEventId, confirmationId, expectedGlobalVersion, rollbackOfGlobalVersion };
      return {
        ...core,
        ownerApprovalAttestation: ownerApprovalArtifact(
          harness, 'policy_global_rollback', digest(core),
        ),
      };
    },
  );
}

function ownerApprovalArtifact(harness, purpose, operationDigest) {
  return policyProtocol.signOwnerApproval({
    schemaVersion: policyProtocol.POLICY_CONTROL_SCHEMA_VERSION,
    kind: policyProtocol.OWNER_APPROVAL_KIND,
    approvalId: crypto.randomUUID(),
    purpose,
    operationDigest,
    approverActorId: 'actor:owner-approver',
    approvedAt: new Date(NOW - 10_000).toISOString(),
    expiresAt: new Date(NOW + 4 * 60_000).toISOString(),
    keyEpoch: 1,
  }, {
    keyId: harness.approvalKeyId,
    privateKey: harness.approvalKeys.privateKey,
    keyEpoch: 1,
  });
}

function distributionCommand(harness, scope, expectedDistributionSequence, globalVersion,
  rollout, desiredOverlay = {}, options = {}) {
  return confirmedCommand(
    harness.storage,
    'policy_distribution_create',
    'policy_publisher',
    ({ authEventId, confirmationId }) => ({
      authEventId,
      confirmationId,
      ...scope,
      expectedDistributionSequence,
      globalVersion,
      desiredOverlay,
      rollout,
      rollbackOfDistributionSequence: null,
      ownerApprovalAttestation: null,
      supersession: options.supersession || null,
      expiresAt: options.expiresAt || new Date(NOW + 60 * 60_000).toISOString(),
    }),
    scope,
  );
}

function deploymentRollbackCommand(harness, scope, expectedDistributionSequence,
  globalVersion, rollbackOfDistributionSequence, rollout = 'required', options = {}) {
  const purpose = 'policy_deployment_rollback';
  return confirmedCommand(
    harness.storage,
    purpose,
    'vendor_owner',
    ({ authEventId, confirmationId }) => {
      const core = {
        authEventId,
        confirmationId,
        ...scope,
        expectedDistributionSequence,
        globalVersion,
        desiredOverlay: {},
        rollout,
        rollbackOfDistributionSequence,
        supersession: options.supersession || null,
        expiresAt: options.expiresAt || new Date(NOW + 60 * 60_000).toISOString(),
      };
      return {
        ...core,
        ownerApprovalAttestation: ownerApprovalArtifact(
          harness,
          purpose,
          digest({ ...core, desiredOverlay: policyState.normalizePolicyOverlay(core.desiredOverlay) }),
        ),
      };
    },
    scope,
  );
}

function deliveryCommand(harness, distribution, expectedRevision = 1, scope = null) {
  const bound = scope || {
    customerId: distribution.customerId,
    deploymentId: distribution.deploymentId,
  };
  return confirmedCommand(
    harness.storage,
    'policy_distribution_deliver',
    'policy_publisher',
    ({ authEventId, confirmationId }) => ({
      authEventId,
      confirmationId,
      ...bound,
      distributionSequence: distribution.distributionSequence,
      expectedRevision,
      targetDigest: distribution.targetDigest,
    }),
    bound,
  );
}

function customerAckCommand(harness, acknowledgement) {
  return {
    channelAuthEventId: authorization(
      harness.storage,
      'policy_customer_ack',
      'customer_connector',
      { customerId: acknowledgement.customerId, deploymentId: acknowledgement.deploymentId },
    ),
    acknowledgement,
  };
}

async function publishGenesis(harness, policy = basePolicy('stable')) {
  return harness.authority.publishGlobalPolicy(globalPublishCommand(harness, 0, policy));
}

test('global releases are signed, monotonic, replay-safe, and rollback republishes exact known content', async () => {
  const harness = createHarness();
  const stable = basePolicy('stable');
  const firstCommand = globalPublishCommand(harness, 0, stable);
  const first = await harness.authority.publishGlobalPolicy(firstCommand);
  assert.deepEqual(await harness.authority.publishGlobalPolicy(firstCommand), first);
  const verified = policyProtocol.verifyGlobalPolicyRelease(first.globalArtifact, harness.policyTrust);
  assert.equal(verified.payload.globalVersion, 1);
  assert.equal(verified.payload.bundleDigest, first.bundleDigest);

  const second = await harness.authority.publishGlobalPolicy(globalPublishCommand(
    harness, 1, basePolicy('changed', { blockRiskScore: 40 }),
  ));
  const rollback = await harness.authority.rollbackGlobalPolicy(rollbackCommand(harness, 2, 1));
  assert.equal(second.globalVersion, 2);
  assert.equal(rollback.globalVersion, 3);
  assert.equal(rollback.rollbackOfGlobalVersion, 1);
  assert.equal(rollback.bundleDigest, first.bundleDigest);
  assert.notEqual(rollback.globalArtifactDigest, first.globalArtifactDigest);
  await expectCode(
    harness.authority.publishGlobalPolicy(globalPublishCommand(harness, 1, stable)),
    'global_version_conflict',
  );
});

test('preview and staged deliveries cache only; required delivery needs exact explicit activation', async () => {
  const harness = createHarness();
  await publishGenesis(harness);
  const preview = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 0, 1, 'preview', { alwaysBlockAdd: ['VENDOR_PREVIEW'] }),
  );
  assert.throws(() => policyState.applySignedPolicy(
    policyState.initialState(SCOPE_A.customerId, SCOPE_A.deploymentId),
    preview.artifact,
    { policyTrust: harness.policyTrust, vendorBundle: preview.vendorBundle, nowMs: NOW },
  ), (error) => error.code === 'explicit_rollout_api_required');
  let customer = policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId);
  const receivedPreview = policyState.receiveSignedPolicyRollout(customer, preview.artifact, {
    ...SCOPE_A,
    policyTrust: harness.policyTrust,
    vendorBundle: preview.vendorBundle,
    nowMs: NOW,
  });
  customer = receivedPreview.state;
  assert.equal(receivedPreview.activationRequired, false);
  assert.equal(customer.active, null);
  const validationReceipt = policyState.buildPolicyValidationReceipt(customer, {
    messageId: crypto.randomUUID(),
    recordedAt: new Date(NOW).toISOString(),
  });
  assert.equal(validationReceipt.kind, 'policy.cached-validation-receipt.v1');
  assert.equal(validationReceipt.lifecycleStage, 'cached');
  await expectCode(harness.authority.recordCustomerAcknowledgement({
    channelAuthEventId: authorization(harness.storage, 'policy_customer_ack', 'customer_connector', SCOPE_A),
    acknowledgement: validationReceipt,
  }), 'acknowledgement_invalid');
  assert.throws(() => policyState.activateRequiredPolicy(customer, {
    distributionSequence: preview.distributionSequence,
    targetDigest: preview.targetDigest,
    deliveryDigest: preview.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }),
  (error) => error.code === 'activation_not_required');

  const staged = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 1, 1, 'staged', { alwaysBlockAdd: ['VENDOR_STAGED'] }),
  );
  const receivedStaged = policyState.receiveSignedPolicyRollout(customer, staged.artifact, {
    ...SCOPE_A,
    policyTrust: harness.policyTrust,
    vendorBundle: staged.vendorBundle,
    nowMs: NOW,
  });
  customer = receivedStaged.state;
  assert.equal(receivedStaged.activationRequired, false);
  assert.equal(customer.active, null);
  assert.throws(() => policyState.activateRequiredPolicy(customer, {
    distributionSequence: staged.distributionSequence,
    targetDigest: staged.targetDigest,
    deliveryDigest: staged.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }),
  (error) => error.code === 'activation_not_required');

  const required = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 2, 1, 'required', { alwaysBlockAdd: ['VENDOR_REQUIRED'] }),
  );
  const receivedRequired = policyState.receiveSignedPolicyRollout(customer, required.artifact, {
    ...SCOPE_A,
    policyTrust: harness.policyTrust,
    vendorBundle: required.vendorBundle,
    nowMs: NOW,
  });
  customer = receivedRequired.state;
  assert.equal(receivedRequired.activationRequired, true);
  assert.equal(customer.active, null);
  const afterRequired = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 3, 1, 'preview'),
  );
  assert.throws(() => policyState.receiveSignedPolicyRollout(customer, afterRequired.artifact, {
    ...SCOPE_A,
    policyTrust: harness.policyTrust,
    vendorBundle: afterRequired.vendorBundle,
    nowMs: NOW,
  }), (error) => error.code === 'required_activation_pending');
  assert.throws(() => policyState.activateRequiredPolicy(customer, {
    distributionSequence: required.distributionSequence,
    targetDigest: '0'.repeat(64),
    deliveryDigest: required.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }),
  (error) => error.code === 'activation_target_mismatch');
  customer = policyState.setLocalPolicyOverride(customer, {
    expectedRevision: 0,
    override: { alwaysBlockAdd: ['CUSTOMER_LOCAL_ONLY'] },
    updatedAt: new Date(NOW).toISOString(),
  }, { ...SCOPE_A, nowMs: NOW }).state;
  const activated = policyState.activateRequiredPolicy(customer, {
    distributionSequence: required.distributionSequence,
    targetDigest: required.targetDigest,
    deliveryDigest: required.deliveryDigest,
  }, {
    ...SCOPE_A,
    policyTrust: harness.policyTrust,
    nowMs: NOW,
  });
  assert.equal(activated.state.active.distributionSequence, 3);
  assert.equal(activated.effectivePolicy.alwaysBlock.includes('VENDOR_REQUIRED'), true);
  assert.equal(activated.effectivePolicy.alwaysBlock.includes('CUSTOMER_LOCAL_ONLY'), true);
  assert.equal(JSON.stringify(required.vendorBundle).includes('CUSTOMER_LOCAL_ONLY'), false);
  assert.deepEqual(policyState.activateRequiredPolicy(activated.state, {
    distributionSequence: required.distributionSequence,
    targetDigest: required.targetDigest,
    deliveryDigest: required.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }), {
    state: activated.state,
    effectivePolicy: activated.effectivePolicy,
    idempotent: true,
  });
});

test('vendor owns delivery while authenticated customer applied and rejected ACKs are exact and replay-safe', async () => {
  const harness = createHarness();
  await publishGenesis(harness);
  const distribution = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 0, 1, 'required'),
  );
  let customer = policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId);
  customer = policyState.receiveSignedPolicyRollout(customer, distribution.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: distribution.vendorBundle, nowMs: NOW,
  }).state;
  customer = policyState.activateRequiredPolicy(customer, {
    distributionSequence: distribution.distributionSequence,
    targetDigest: distribution.targetDigest,
    deliveryDigest: distribution.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }).state;
  const acknowledgement = policyState.buildPolicyAcknowledgement(customer, {
    messageId: crypto.randomUUID(),
    target: 'active',
    outcome: 'success',
    reasonCode: 'applied',
    recordedAt: new Date(NOW).toISOString(),
  });
  await expectCode(
    harness.authority.recordCustomerAcknowledgement(customerAckCommand(harness, acknowledgement)),
    'acknowledgement_before_delivery',
  );
  const delivered = await harness.authority.markDelivered(deliveryCommand(harness, distribution));
  assert.equal(delivered.stage, 'delivered');
  const applied = await harness.authority.recordCustomerAcknowledgement(
    customerAckCommand(harness, acknowledgement),
  );
  assert.equal(applied.stage, 'applied');
  const auditCount = harness.storage.data.auditEvents.size;
  assert.deepEqual(await harness.authority.recordCustomerAcknowledgement(
    customerAckCommand(harness, acknowledgement),
  ), applied);
  assert.equal(harness.storage.data.auditEvents.size, auditCount);
  await expectCode(harness.authority.recordCustomerAcknowledgement(customerAckCommand(harness, {
    ...acknowledgement,
    outcome: 'rejected',
    reasonCode: 'invalid_signature',
  })), 'acknowledgement_conflict');

  const rejectedDistribution = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 1, 1, 'required'),
  );
  const rejectedAck = protocol.assertChannel({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: crypto.randomUUID(),
    ...SCOPE_A,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.POLICY_DESIRED_STATE,
    targetVersion: rejectedDistribution.distributionSequence,
    targetDigest: rejectedDistribution.targetDigest,
    lifecycleStage: 'applied',
    outcome: 'rejected',
    reasonCode: 'invalid_signature',
    recordedAt: new Date(NOW).toISOString(),
  }, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT);
  const rejected = await harness.authority.recordCustomerAcknowledgement(
    customerAckCommand(harness, rejectedAck),
  );
  assert.equal(rejected.stage, 'rejected');
  assert.equal(rejected.reasonCode, 'invalid_signature');
  const redelivered = await harness.authority.markDelivered(
    deliveryCommand(harness, rejectedDistribution, rejected.revision),
  );
  assert.equal(redelivered.stage, 'delivered');
  const recoveryAck = {
    ...rejectedAck,
    messageId: crypto.randomUUID(),
    outcome: 'success',
    reasonCode: 'applied',
  };
  const recovered = await harness.authority.recordCustomerAcknowledgement(
    customerAckCommand(harness, recoveryAck),
  );
  assert.equal(recovered.stage, 'applied');
  assert.notEqual(recovered.messageId, rejected.messageId);
});

test('emergency deny is dual-controlled, strictly additive, and included in later signed deliveries', async () => {
  const harness = createHarness();
  await publishGenesis(harness);
  const emergency = await harness.authority.publishEmergencyDeny(emergencyCommand(
    harness.storage,
    SCOPE_A,
    0,
    { alwaysBlockAdd: ['EMERGENCY_SECRET'], blockedDestinationsAdd: ['blocked.emergency.example'] },
  ));
  assert.equal(emergency.revision, 1);
  const distribution = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 0, 1, 'required'),
  );
  assert.equal(distribution.vendorBundle.alwaysBlock.includes('EMERGENCY_SECRET'), true);
  assert.equal(distribution.vendorBundle.blockedDestinations.includes('blocked.emergency.example'), true);
  await expectCode(harness.authority.publishEmergencyDeny(emergencyCommand(
    harness.storage, SCOPE_A, 1, { alwaysBlockAdd: ['DIFFERENT_ONLY'] },
  )), 'emergency_deny_not_additive');

  const sameActor = emergencyCommand(
    harness.storage,
    SCOPE_B,
    0,
    { alwaysBlockAdd: ['EMERGENCY_B'] },
    { initiator: 'actor:same', approver: 'actor:same' },
  );
  await expectCode(harness.authority.publishEmergencyDeny(sameActor), 'dual_control_invalid');
});

test('deployment rollback restores the exact immutable vendor target under signed Owner approval', async () => {
  const harness = createHarness();
  await publishGenesis(harness);
  let customer = policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId);
  customer = policyState.setLocalPolicyOverride(customer, {
    expectedRevision: 0,
    override: { alwaysBlockAdd: ['CUSTOMER_ROLLBACK_OVERRIDE'] },
    updatedAt: new Date(NOW).toISOString(),
  }, { ...SCOPE_A, nowMs: NOW }).state;

  await harness.authority.publishEmergencyDeny(emergencyCommand(
    harness.storage, SCOPE_A, 0, { alwaysBlockAdd: ['EMERGENCY_ONE'] },
  ));
  const first = await harness.authority.createDistribution(distributionCommand(
    harness, SCOPE_A, 0, 1, 'required', { alwaysBlockAdd: ['VENDOR_ONE'] },
  ));
  customer = policyState.receiveSignedPolicyRollout(customer, first.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: first.vendorBundle, nowMs: NOW,
  }).state;
  customer = policyState.activateRequiredPolicy(customer, {
    distributionSequence: first.distributionSequence,
    targetDigest: first.targetDigest,
    deliveryDigest: first.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }).state;

  await harness.authority.publishEmergencyDeny(emergencyCommand(
    harness.storage,
    SCOPE_A,
    1,
    { alwaysBlockAdd: ['EMERGENCY_ONE', 'EMERGENCY_TWO'] },
  ));
  const second = await harness.authority.createDistribution(distributionCommand(
    harness, SCOPE_A, 1, 1, 'required', { alwaysBlockAdd: ['VENDOR_TWO'] },
  ));
  customer = policyState.receiveSignedPolicyRollout(customer, second.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: second.vendorBundle, nowMs: NOW,
  }).state;
  customer = policyState.activateRequiredPolicy(customer, {
    distributionSequence: second.distributionSequence,
    targetDigest: second.targetDigest,
    deliveryDigest: second.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }).state;

  const tampered = clone(deploymentRollbackCommand(harness, SCOPE_A, 2, 1, 1));
  tampered.ownerApprovalAttestation.signature = `${tampered.ownerApprovalAttestation.signature.slice(0, -2)}AA`;
  harness.storage.data.confirmations.get(tampered.confirmationId).operationDigest = commandDigest(
    tampered,
    'policy_deployment_rollback',
  );
  await expectCode(harness.authority.rollbackDeploymentPolicy(tampered), 'owner_approval_invalid');
  const rollback = await harness.authority.rollbackDeploymentPolicy(
    deploymentRollbackCommand(harness, SCOPE_A, 2, 1, 1),
  );
  const firstControl = policyProtocol.createPolicyControlEnvelope(first.vendorBundle.vendorControl);
  const rollbackControl = policyProtocol.createPolicyControlEnvelope(rollback.vendorBundle.vendorControl);
  assert.equal(rollback.rollbackOfDistributionSequence, 1);
  assert.equal(rollbackControl.deliveryBinding.rollbackOfDistributionSequence, 1);
  assert.equal(rollbackControl.deliveryBinding.desiredOverlayDigest,
    firstControl.deliveryBinding.desiredOverlayDigest);
  assert.equal(rollbackControl.deliveryBinding.emergencyDenyDigest,
    firstControl.deliveryBinding.emergencyDenyDigest);
  assert.equal(rollbackControl.deliveryBinding.effectivePolicyDigest,
    firstControl.deliveryBinding.effectivePolicyDigest);
  assert.deepEqual(rollbackControl.desiredOverlay, firstControl.desiredOverlay);
  assert.deepEqual(rollbackControl.emergencyDenyOverlay, firstControl.emergencyDenyOverlay);

  customer = policyState.receiveSignedPolicyRollout(customer, rollback.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: rollback.vendorBundle, nowMs: NOW,
  }).state;
  customer = policyState.activateRequiredPolicy(customer, {
    distributionSequence: rollback.distributionSequence,
    targetDigest: rollback.targetDigest,
    deliveryDigest: rollback.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }).state;
  assert.equal(customer.active.effectivePolicy.alwaysBlock.includes('VENDOR_ONE'), true);
  assert.equal(customer.active.effectivePolicy.alwaysBlock.includes('VENDOR_TWO'), false);
  assert.equal(customer.active.effectivePolicy.alwaysBlock.includes('EMERGENCY_ONE'), true);
  assert.equal(customer.active.effectivePolicy.alwaysBlock.includes('EMERGENCY_TWO'), false);
  assert.equal(customer.active.effectivePolicy.alwaysBlock.includes('CUSTOMER_ROLLBACK_OVERRIDE'), true);
  assert.equal(customer.localOverrideRevision, 1);
});

test('required candidates advance only through exact signed expiry, rejection, or recovery supersession', async () => {
  for (const disposition of ['expired', 'recovery']) {
    const harness = createHarness();
    await publishGenesis(harness);
    const first = await harness.authority.createDistribution(distributionCommand(
      harness,
      SCOPE_A,
      0,
      1,
      'required',
      {},
      { expiresAt: new Date(NOW + 60 * 60_000).toISOString() },
    ));
    let customer = policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId);
    customer = policyState.receiveSignedPolicyRollout(customer, first.artifact, {
      ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: first.vendorBundle, nowMs: NOW,
    }).state;
    const supersession = {
      targetVersion: first.distributionSequence,
      targetDigest: first.targetDigest,
      deliveryDigest: first.deliveryDigest,
      disposition,
      rejectionDigest: null,
    };
    const second = await harness.authority.createDistribution(distributionCommand(
      harness,
      SCOPE_A,
      1,
      1,
      'required',
      {},
      {
        supersession,
        expiresAt: new Date(NOW + 2 * 60 * 60_000).toISOString(),
      },
    ));
    const received = policyState.receiveSignedPolicyRollout(customer, second.artifact, {
      ...SCOPE_A,
      policyTrust: harness.policyTrust,
      vendorBundle: second.vendorBundle,
      nowMs: NOW + 60 * 60_000 + 1,
    });
    assert.equal(received.state.candidate.distributionSequence, 2);
  }

  const harness = createHarness();
  await publishGenesis(harness);
  const first = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 0, 1, 'required'),
  );
  let customer = policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId);
  customer = policyState.receiveSignedPolicyRollout(customer, first.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: first.vendorBundle, nowMs: NOW,
  }).state;
  const rejection = policyState.buildPolicyAcknowledgement(customer, {
    messageId: crypto.randomUUID(),
    target: 'candidate',
    outcome: 'rejected',
    reasonCode: 'internal_failure',
    recordedAt: new Date(NOW).toISOString(),
  });
  const recorded = policyState.recordCandidateRejection(customer, rejection, {
    ...SCOPE_A, policyTrust: harness.policyTrust,
  });
  customer = recorded.state;
  const second = await harness.authority.createDistribution(distributionCommand(
    harness,
    SCOPE_A,
    1,
    1,
    'required',
    {},
    {
      supersession: {
        targetVersion: first.distributionSequence,
        targetDigest: first.targetDigest,
        deliveryDigest: first.deliveryDigest,
        disposition: 'customer_rejected',
        rejectionDigest: recorded.rejectionDigest,
      },
    },
  ));
  const received = policyState.receiveSignedPolicyRollout(customer, second.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: second.vendorBundle, nowMs: NOW,
  });
  assert.equal(received.state.candidate.distributionSequence, 2);
  assert.equal(received.state.candidate.rejectionDigest, null);
});

test('rollout history compacts by checkpoint while the exact active policy remains pinned', async () => {
  const harness = createHarness();
  await publishGenesis(harness);
  const first = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 0, 1, 'required'),
  );
  let customer = policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId);
  customer = policyState.receiveSignedPolicyRollout(customer, first.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: first.vendorBundle, nowMs: NOW,
  }).state;
  customer = policyState.activateRequiredPolicy(customer, {
    distributionSequence: first.distributionSequence,
    targetDigest: first.targetDigest,
    deliveryDigest: first.deliveryDigest,
  }, { ...SCOPE_A, policyTrust: harness.policyTrust, nowMs: NOW }).state;
  const activeDigest = customer.active.activeDigest;
  for (let sequence = 2; sequence <= 70; sequence += 1) {
    const distribution = await harness.authority.createDistribution(distributionCommand(
      harness, SCOPE_A, sequence - 1, 1, 'preview', { alwaysBlockAdd: [`PREVIEW_${sequence}`] },
    ));
    customer = policyState.receiveSignedPolicyRollout(customer, distribution.artifact, {
      ...SCOPE_A,
      policyTrust: harness.policyTrust,
      vendorBundle: distribution.vendorBundle,
      nowMs: NOW,
    }).state;
  }
  assert.equal(customer.history.length, policyState.MAX_ROLLOUT_HISTORY);
  assert.equal(customer.historyCheckpoint.throughSequence, 6);
  assert.equal(customer.history.some((entry) => entry.distributionSequence === 1), false);
  assert.equal(customer.active.distributionSequence, 1);
  assert.equal(customer.active.activeDigest, activeDigest);
  const restored = policyState.restoreRolloutState(customer, {
    ...SCOPE_A,
    policyTrust: harness.policyTrust,
  });
  assert.equal(restored.active.activeDigest, activeDigest);
});

test('deployment sequences, state, delivery, and customer credentials remain isolated across silos', async () => {
  const harness = createHarness();
  await publishGenesis(harness);
  const a = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_A, 0, 1, 'required', { alwaysBlockAdd: ['ONLY_A'] }),
  );
  const b = await harness.authority.createDistribution(
    distributionCommand(harness, SCOPE_B, 0, 1, 'required', { alwaysBlockAdd: ['ONLY_B'] }),
  );
  assert.equal(a.distributionSequence, 1);
  assert.equal(b.distributionSequence, 1);
  assert.equal(a.vendorBundle.alwaysBlock.includes('ONLY_B'), false);
  assert.equal(b.vendorBundle.alwaysBlock.includes('ONLY_A'), false);
  const cross = deliveryCommand(harness, a, 1, SCOPE_B);
  await expectCode(harness.authority.markDelivered(cross), 'delivery_target_mismatch');

  let stateA = policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId);
  assert.throws(() => policyState.receiveSignedPolicyRollout(stateA, b.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: b.vendorBundle, nowMs: NOW,
  }), (error) => error.code === 'customer_mismatch');
  stateA = policyState.receiveSignedPolicyRollout(stateA, a.artifact, {
    ...SCOPE_A, policyTrust: harness.policyTrust, vendorBundle: a.vendorBundle, nowMs: NOW,
  }).state;
  assert.equal(stateA.candidate.globalReleaseId, a.globalReleaseId);
});

test('policy signing rotates through independently trusted current and next keys', async () => {
  const harness = createHarness();
  const first = await publishGenesis(harness);
  harness.keyState.current = 'rw-policy-signing-2';
  harness.keyState.next = null;
  harness.keyState.epoch = 2;
  harness.refreshTrust();
  const second = await harness.authority.publishGlobalPolicy(globalPublishCommand(
    harness, 1, basePolicy('rotated'),
  ));
  assert.equal(first.signingKeyId, 'rw-policy-signing-1');
  assert.equal(second.signingKeyId, 'rw-policy-signing-2');
  assert.equal(policyProtocol.verifyPersistedGlobalPolicyRelease(
    first.globalArtifact, harness.policyTrust,
  ).keyId,
    'rw-policy-signing-1');
  assert.equal(policyProtocol.verifyGlobalPolicyRelease(second.globalArtifact, harness.policyTrust).keyId,
    'rw-policy-signing-2');
  const ready = await harness.authority.readiness();
  assert.equal(ready.currentSigningKeyId, 'rw-policy-signing-2');
  assert.equal(ready.nextSigningKeyId, null);
  assert.equal(ready.productionReady, false);
});

test('fresh desired state and Owner approval reject verify-only signing keys', async () => {
  const desiredHarness = createHarness();
  await publishGenesis(desiredHarness);
  const distribution = await desiredHarness.authority.createDistribution(distributionCommand(
    desiredHarness, SCOPE_A, 0, 1, 'required', {},
  ));
  const cached = policyState.receiveSignedPolicyRollout(
    policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId),
    distribution.artifact,
    {
      ...SCOPE_A,
      policyTrust: desiredHarness.policyTrust,
      vendorBundle: distribution.vendorBundle,
      nowMs: NOW,
    },
  );
  desiredHarness.keyState.current = 'rw-policy-signing-2';
  desiredHarness.keyState.next = null;
  desiredHarness.keyState.epoch = 2;
  desiredHarness.refreshTrust();
  assert.throws(() => policyState.receiveSignedPolicyRollout(
    policyState.initialRolloutState(SCOPE_A.customerId, SCOPE_A.deploymentId),
    distribution.artifact,
    {
      ...SCOPE_A,
      policyTrust: desiredHarness.policyTrust,
      vendorBundle: distribution.vendorBundle,
      nowMs: NOW,
    },
  ), (error) => error.code === 'policy_key_not_active');
  const activated = policyState.activateRequiredPolicy(cached.state, {
    distributionSequence: distribution.distributionSequence,
    targetDigest: distribution.targetDigest,
    deliveryDigest: distribution.deliveryDigest,
  }, {
    ...SCOPE_A,
    policyTrust: desiredHarness.policyTrust,
    nowMs: NOW,
  });
  assert.equal(activated.state.active.distributionSequence, distribution.distributionSequence);

  const approvalHarness = createHarness();
  await publishGenesis(approvalHarness);
  const nextApproval = crypto.generateKeyPairSync('ed25519');
  const activeApprovalKeyId = 'rw-owner-policy-approval-2';
  const historicalApprovalTrust = () => {
    const original = approvalHarness.policyApprovalTrust();
    return {
      ...original,
      currentEpoch: 2,
      publicKeys: {
        [approvalHarness.approvalKeyId]: approvalHarness.approvalKeys.publicKey,
        [activeApprovalKeyId]: nextApproval.publicKey,
      },
      keyEpochs: {
        [approvalHarness.approvalKeyId]: { validFromEpoch: 1, retireAfterEpoch: 1 },
        [activeApprovalKeyId]: { validFromEpoch: 2, retireAfterEpoch: null },
      },
    };
  };
  const approvalAuthority = createVendorPolicyAuthority(authorityOptions(approvalHarness, {
    storage: approvalHarness.storage,
    externalState: approvalHarness.externalState,
    policyApprovalTrust: historicalApprovalTrust,
    policyApprovalActiveKeyIds: () => [activeApprovalKeyId],
  }));
  const historicalApprovalReadback = await approvalAuthority.createDistribution(distributionCommand(
    approvalHarness, SCOPE_A, 0, 1, 'preview', {},
  ));
  assert.equal(historicalApprovalReadback.globalVersion, 1);
  await expectCode(approvalAuthority.publishGlobalPolicy(globalPublishCommand(
    approvalHarness, 1, basePolicy('retired-approval'),
  )), 'owner_approval_invalid');
});

test('shared Owner 20-purpose registry and supplemental policy authorities cannot reuse identity', async () => {
  const base = createHarness();
  assert.equal(Object.keys(AUTHORITY_DEFINITIONS).length, 20);
  for (const purpose of [
    KEY_PURPOSES.RECOVERY,
    KEY_PURPOSES.LICENSE_REGISTRY_INTEGRITY,
    KEY_PURPOSES.HEARTBEAT_CREDENTIAL,
    KEY_PURPOSES.ACKNOWLEDGEMENT_CREDENTIAL,
    KEY_PURPOSES.DIAGNOSTIC_CREDENTIAL,
    KEY_PURPOSES.SHADOW_CANDIDATE_CREDENTIAL,
  ]) {
    assert.equal(base.authorityManifest.registry().list(purpose).length, 1);
  }
  const originalManifest = base.authorityManifest;
  const collidingManifest = {
    registry() {
      const registry = originalManifest.registry();
      const policyRecord = registry.get(KEY_PURPOSES.POLICY);
      const collision = {
        ...registry.get(KEY_PURPOSES.OFFLINE_LICENSE),
        identity: policyRecord.identity,
        publicKeySpki: registry.list(KEY_PURPOSES.POLICY)
          .find((record) => record.keyId === policyRecord.keyId).publicKeySpki,
      };
      return {
        generation: registry.generation,
        get(purpose) {
          return purpose === KEY_PURPOSES.OFFLINE_LICENSE ? clone(collision) : registry.get(purpose);
        },
        list(purpose) {
          return purpose === KEY_PURPOSES.OFFLINE_LICENSE ? [clone(collision)] : registry.list(purpose);
        },
      };
    },
  };
  const service = createVendorPolicyAuthority({
    storage: memoryStorage(),
    externalState: createMemoryPolicyExternalState({ testOnly: true }),
    allowTestExternalState: true,
    clock: () => NOW,
    policyIntegrityAuthority: { keyId: 'rw-policy-integrity-v1', secret: INTEGRITY_SECRET },
    policyWitnessAuthority: { keyId: 'rw-policy-witness-v1', secret: PENDING_SECRET },
    policySigningAuthority: base.provider,
    authorityManifest: collidingManifest,
    policyApprovalTrust: base.policyApprovalTrust,
    policyApprovalActiveKeyIds: () => [base.approvalKeyId],
  });
  await expectCode(service.readiness(), 'policy_owner_authority_identity_reused');
  assert.throws(() => createVendorPolicyAuthority({
    storage: memoryStorage(),
    externalState: createMemoryPolicyExternalState({ testOnly: true }),
    allowTestExternalState: true,
    policyIntegrityAuthority: { keyId: 'rw-policy-integrity-v1', secret: INTEGRITY_SECRET },
    policyWitnessAuthority: { keyId: 'rw-policy-witness-v1', secret: INTEGRITY_SECRET },
    policySigningAuthority: base.provider,
    authorityManifest: base.authorityManifest,
    policyApprovalTrust: base.policyApprovalTrust,
    policyApprovalActiveKeyIds: () => [base.approvalKeyId],
  }), (error) => error.code === 'policy_authority_identity_reused');
});

test('policy verifier registry rejects private PEM, PKCS8 wrappers, and private KeyObjects', async () => {
  const base = createHarness();
  const keyId = base.keyState.current;
  const pair = base.keyPairs[keyId];
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateDer = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  for (const publicKey of [
    privatePem,
    { key: privateDer, format: 'der', type: 'pkcs8' },
    pair.privateKey,
  ]) {
    const provider = () => {
      const raw = base.provider();
      return {
        ...raw,
        archivedPublicKeys: {
          ...raw.archivedPublicKeys,
          [keyId]: { ...raw.archivedPublicKeys[keyId], publicKey },
        },
      };
    };
    const authority = createVendorPolicyAuthority(authorityOptions(base, {
      policySigningAuthority: provider,
    }));
    await expectCode(authority.readiness(), 'policy_key_authority_invalid');
  }
});

test('policy approval cannot alias Owner attestation or omit any reserved authority identity', async () => {
  const base = createHarness();
  const ownerAttestation = base.authorityManifest.registry().get(KEY_PURPOSES.OWNER_ATTESTATION);
  const ownerAttestationKey = crypto.createPublicKey({
    key: Buffer.from(ownerAttestation.publicKeySpki, 'base64'),
    format: 'der',
    type: 'spki',
  });
  const aliased = createVendorPolicyAuthority(authorityOptions(base, {
    policyApprovalTrust: () => approvalTrust(
      'rw-owner-policy-approval-alias', ownerAttestationKey, base.authorityManifest,
    ),
  }));
  await expectCode(aliased.readiness(), 'policy_authority_identity_reused');

  const recoveryFingerprint = base.authorityManifest.registry().get(KEY_PURPOSES.RECOVERY).identity;
  const incomplete = createVendorPolicyAuthority(authorityOptions(base, {
    policyApprovalTrust: () => {
      const trust = base.policyApprovalTrust();
      return {
        ...trust,
        forbiddenPublicKeyFingerprints: trust.forbiddenPublicKeyFingerprints
          .filter((value) => value !== recoveryFingerprint),
      };
    },
  }));
  await expectCode(incomplete.readiness(), 'policy_approval_trust_incomplete');
});

test('reserved external authority fingerprints are metadata-only and collide across key types', async () => {
  const base = createHarness();
  const reservedFingerprint = crypto.createHash('sha256')
    .update(Buffer.alloc(32, 0x73)).digest('hex');
  const reservedExternalAuthorityFingerprints = () => [{
    purpose: 'license_registry_witness',
    identityType: 'hmac_secret',
    keyId: 'rw-license-registry-witness-v1',
    fingerprint: reservedFingerprint,
  }];
  const accepted = createVendorPolicyAuthority(authorityOptions(base, {
    reservedExternalAuthorityFingerprints,
    policyApprovalTrust: () => {
      const trust = base.policyApprovalTrust();
      return {
        ...trust,
        forbiddenPublicKeyFingerprints: [
          ...trust.forbiddenPublicKeyFingerprints,
          reservedFingerprint,
        ],
      };
    },
  }));
  assert.equal((await accepted.readiness()).ready, true);

  const ownerAttestation = base.authorityManifest.registry().get(KEY_PURPOSES.OWNER_ATTESTATION);
  const crossTypeCollision = createVendorPolicyAuthority(authorityOptions(base, {
    reservedExternalAuthorityFingerprints: () => [{
      purpose: 'license_registry_witness',
      identityType: 'hmac_secret',
      keyId: 'rw-license-registry-witness-v1',
      fingerprint: ownerAttestation.identity,
    }],
  }));
  await expectCode(crossTypeCollision.readiness(), 'policy_authority_identity_reused');

  const rawMaterialRejected = createVendorPolicyAuthority(authorityOptions(base, {
    reservedExternalAuthorityFingerprints: () => [{
      purpose: 'license_registry_witness',
      identityType: 'hmac_secret',
      keyId: 'rw-license-registry-witness-v1',
      fingerprint: reservedFingerprint,
      secret: 'forbidden',
    }],
  }));
  await expectCode(rawMaterialRejected.readiness(), 'policy_reserved_authorities_invalid');

  const duplicateFingerprint = createVendorPolicyAuthority(authorityOptions(base, {
    reservedExternalAuthorityFingerprints: () => [
      ...reservedExternalAuthorityFingerprints(),
      {
        purpose: 'other_external_witness',
        identityType: 'opaque_credential',
        keyId: 'rw-other-external-witness-v1',
        fingerprint: reservedFingerprint,
      },
    ],
  }));
  await expectCode(duplicateFingerprint.readiness(), 'policy_reserved_authorities_invalid');
});

test('serializable storage CAS permits one concurrent distribution for an expected sequence', async () => {
  const harness = createHarness();
  await publishGenesis(harness);
  const left = distributionCommand(harness, SCOPE_A, 0, 1, 'preview', {
    alwaysBlockAdd: ['CONCURRENT_LEFT'],
  });
  const right = distributionCommand(harness, SCOPE_A, 0, 1, 'preview', {
    alwaysBlockAdd: ['CONCURRENT_RIGHT'],
  });
  const results = await Promise.allSettled([
    harness.authority.createDistribution(left),
    harness.authority.createDistribution(right),
  ]);
  assert.equal(results.filter((item) => item.status === 'fulfilled').length, 1);
  const rejected = results.find((item) => item.status === 'rejected');
  assert.equal(rejected.reason.code, 'control_plane_readiness_frozen');
  const winner = results.find((item) => item.status === 'fulfilled').value;
  assert.equal(winner.distributionSequence, 1);
  await expectCode(harness.authority.createDistribution(
    winner.targetDigest === results[0].value?.targetDigest ? right : left,
  ), 'distribution_sequence_conflict');
  assert.equal(harness.storage.data.auditEvents.size, 2);
});

test('canaries never enter records or audit and tamper freezes readiness', async () => {
  const harness = createHarness();
  const captured = captureConsole(async () => expectCode(
    harness.authority.publishGlobalPolicy(globalPublishCommand(
      harness, 0, {
        ...basePolicy('canary'),
        alwaysBlock: [...policyState.MANDATORY_ALWAYS_BLOCK, 'PROMPT_CANARY_DO_NOT_STORE'],
      },
    )),
    'sensitive_metadata_rejected',
  ));
  await captured.result;
  assert.equal(deepExposure(captured.records).includes('DO_NOT_STORE'), false);
  assert.equal(JSON.stringify(snapshot(harness.storage)).includes('DO_NOT_STORE'), false);

  await publishGenesis(harness);
  assert.equal((await harness.authority.readiness()).ready, true);
  harness.storage.data.auditHighWater.payload.headDigest = '0'.repeat(64);
  await expectCode(harness.authority.readiness(), 'policy_integrity_state_invalid');
});

test('independently retained audit anchor rejects a validly MACed database rewind', async () => {
  const harness = createHarness();
  await publishGenesis(harness);
  const afterGenesis = copyData(harness.storage.data);
  await harness.authority.publishGlobalPolicy(globalPublishCommand(
    harness, 1, basePolicy('second-release', { blockRiskScore: 58 }),
  ));
  harness.storage.data = afterGenesis;
  await expectCode(harness.authority.readiness(), 'policy_audit_anchor_invalid');
});

test('authenticated pending witness reconciles a committed mutation and rejects forged state', async () => {
  const harness = createHarness();
  harness.externalState.setFault('anchor');
  await expectCode(publishGenesis(harness), 'policy_commit_uncertain');
  await expectCode(harness.authority.readiness(), 'control_plane_readiness_frozen');
  harness.externalState.setFault(null);
  assert.deepEqual(await harness.authority.reconcileIntegrity(), {
    reconciled: 1,
    auditSequence: 1,
    outcome: 'committed',
  });
  assert.equal((await harness.authority.readiness()).ready, true);

  const pending = seal(INTEGRITY_DOMAINS.PENDING, 'rw-policy-witness-v1', PENDING_SECRET, {
    schemaVersion: 2,
    namespace: 'global',
    operationDigest: '1'.repeat(64),
    auditBody: {},
    auditBodyDigest: '2'.repeat(64),
    auditIntentDigest: '2'.repeat(64),
    expectedAuditSequence: 1,
    targetAuditSequence: 2,
    headType: 'global_head',
    headId: 'global',
    headRevision: 2,
    previousHeadRevision: 1,
    headRecordDigest: '3'.repeat(64),
    result: {},
    resultDigest: digest({}),
    targetAnchor: { schemaVersion: 1, sequence: 2, count: 2, headDigest: '4'.repeat(64) },
    preparedAt: new Date(NOW).toISOString(),
  });
  harness.externalState.replacePending({
    ...pending,
    mac: '0'.repeat(64),
  });
  await expectCode(harness.authority.reconcileIntegrity(), 'policy_integrity_state_invalid');
});

test('reconcile completes after anchor CAS commits but pending cleanup fails', async () => {
  const harness = createHarness();
  harness.externalState.setFault('clear');
  await expectCode(publishGenesis(harness), 'policy_commit_uncertain');
  const uncertain = harness.externalState.snapshot();
  assert.equal(uncertain.anchor.payload.sequence, 1);
  assert.equal(uncertain.pending.payload.targetAuditSequence, 1);
  harness.externalState.setFault(null);
  assert.deepEqual(await harness.authority.reconcileIntegrity(), {
    reconciled: 1,
    auditSequence: 1,
    outcome: 'committed',
  });
  assert.equal(harness.externalState.snapshot().pending, null);
  assert.equal((await harness.authority.readiness()).ready, true);
});

test('storage callback substitution and double invocation are rejected', async () => {
  const harness = createHarness();
  const options = {
    clock: () => NOW,
    externalState: createMemoryPolicyExternalState({ testOnly: true }),
    allowTestExternalState: true,
    policyIntegrityAuthority: { keyId: 'rw-policy-integrity-v1', secret: INTEGRITY_SECRET },
    policyWitnessAuthority: { keyId: 'rw-policy-witness-v1', secret: PENDING_SECRET },
    policySigningAuthority: harness.provider,
    authorityManifest: harness.authorityManifest,
    policyApprovalTrust: harness.policyApprovalTrust,
    policyApprovalActiveKeyIds: () => [harness.approvalKeyId],
  };
  const substitute = createVendorPolicyAuthority({
    ...options,
    storage: { transaction: async (callback) => { await callback({}); return { value: 'forged' }; } },
  });
  await expectCode(substitute.readiness(), 'storage_contract_invalid');
  const twice = createVendorPolicyAuthority({
    ...options,
    storage: { transaction: async (callback) => { await callback({}); return callback({}); } },
  });
  await expectCode(twice.readiness(), 'storage_contract_invalid');
});

function memoryStorage() {
  let tail = Promise.resolve();
  const storage = {
    data: newData(),
    transaction(callback) {
      const run = tail.then(async () => {
      const working = copyData(storage.data);
      const result = await callback(transactionMethods(working));
      storage.data = working;
      return result;
      });
      tail = run.catch(() => undefined);
      return run;
    },
  };
  return storage;
}

function transactionMethods(data) {
  const claim = (map, id, value) => {
    if (!map.has(id)) { map.set(id, value); return 'claimed'; }
    return map.get(id) === value ? 'replay' : 'conflict';
  };
  return {
    resolveAuthorization: (id) => clone(data.authorizations.get(id)),
    claimAuthorization: (id, value) => claim(data.authorizationClaims, id, value),
    resolveConfirmation: (id) => clone(data.confirmations.get(id)),
    claimConfirmation: (id, value) => claim(data.confirmationClaims, id, value),
    resolveDualApproval: (id) => clone(data.approvals.get(id)),
    claimDualApproval: (id, value) => claim(data.approvalClaims, id, value),
    readPolicyRecord: (type, id) => clone(data.records.get(recordKey(type, id))),
    insertPolicyRecord: (type, id, wrapped) => {
      const key = recordKey(type, id);
      if (data.records.has(key)) return false;
      data.records.set(key, clone(wrapped));
      return true;
    },
    compareAndSetPolicyRecord: (type, id, expectedRevision, wrapped) => {
      const key = recordKey(type, id);
      const current = data.records.get(key);
      if ((current?.payload?.revision || 0) !== expectedRevision) return false;
      data.records.set(key, clone(wrapped));
      return true;
    },
    readPolicyOperation: (id) => clone(data.operations.get(id)),
    insertPolicyOperation: (id, wrapped) => {
      if (data.operations.has(id)) return false;
      data.operations.set(id, clone(wrapped));
      return true;
    },
    readPolicyPending: (namespace) => clone(data.pending.get(namespace)),
    writePolicyPending: (namespace, wrapped) => {
      if (data.pending.has(namespace)) return false;
      data.pending.set(namespace, clone(wrapped));
      return true;
    },
    clearPolicyPending: (namespace, expectedDigest) => {
      const current = data.pending.get(namespace);
      if (!current || digest(current) !== expectedDigest) return false;
      data.pending.delete(namespace);
      return true;
    },
    listPolicyPending: (limit) => [...data.pending.values()].slice(0, limit).map(clone),
    readPolicyAuditHighWater: () => clone(data.auditHighWater),
    compareAndSetPolicyAuditHighWater: (expected, wrapped) => {
      if ((data.auditHighWater?.payload?.sequence || 0) !== expected) return false;
      data.auditHighWater = clone(wrapped);
      return true;
    },
    readPolicyAuditAnchor: () => clone(data.auditAnchor),
    compareAndSetPolicyAuditAnchor: (expected, wrapped) => {
      if ((data.auditAnchor?.payload?.sequence || 0) !== expected) return false;
      data.auditAnchor = clone(wrapped);
      return true;
    },
    readPolicyAuditEvent: (sequence) => clone(data.auditEvents.get(sequence)),
    appendPolicyAuditEvent: (sequence, eventDigest, wrapped) => {
      if (data.auditEvents.has(sequence) || wrapped.payload.eventDigest !== eventDigest) return false;
      data.auditEvents.set(sequence, clone(wrapped));
      return true;
    },
  };
}

function newData() {
  return {
    authorizations: new Map(),
    authorizationClaims: new Map(),
    confirmations: new Map(),
    confirmationClaims: new Map(),
    approvals: new Map(),
    approvalClaims: new Map(),
    records: new Map(),
    operations: new Map(),
    pending: new Map(),
    auditHighWater: null,
    auditAnchor: null,
    auditEvents: new Map(),
  };
}

function copyData(data) {
  return {
    authorizations: cloneMap(data.authorizations),
    authorizationClaims: cloneMap(data.authorizationClaims),
    confirmations: cloneMap(data.confirmations),
    confirmationClaims: cloneMap(data.confirmationClaims),
    approvals: cloneMap(data.approvals),
    approvalClaims: cloneMap(data.approvalClaims),
    records: cloneMap(data.records),
    operations: cloneMap(data.operations),
    pending: cloneMap(data.pending),
    auditHighWater: clone(data.auditHighWater),
    auditAnchor: clone(data.auditAnchor),
    auditEvents: cloneMap(data.auditEvents),
  };
}

function cloneMap(value) {
  return new Map([...value].map(([key, item]) => [key, clone(item)]));
}

function recordKey(type, id) {
  return `${type}\0${id}`;
}

function seal(domain, keyId, secret, payload) {
  return {
    integrityVersion: 1,
    keyId,
    domain,
    payload: clone(payload),
    mac: crypto.createHmac('sha256', secret)
      .update(Buffer.from(`${domain}\0${keyId}\0${protocol.canonicalJson(payload)}`, 'utf8'))
      .digest('hex'),
  };
}

function fingerprint(publicKey) {
  return crypto.createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}

function ownerAuthorityManifest(keyPairs, keyState, identityOverrides = {}) {
  const stable = new Map();
  for (const [purpose, definition] of Object.entries(AUTHORITY_DEFINITIONS)) {
    if (purpose === KEY_PURPOSES.POLICY) continue;
    const keyId = `${definition.keyPrefix}v1`;
    const record = {
      purpose,
      identityType: definition.identityType,
      keyId,
      identity: identityOverrides[purpose] || digest({ ownerPurpose: purpose, identityType: definition.identityType }),
      slot: 'current',
      references: 0,
    };
    if (definition.identityType === 'ed25519_public') {
      const generated = crypto.generateKeyPairSync('ed25519');
      record.identity = identityOverrides[purpose] || fingerprint(generated.publicKey);
      record.publicKeySpki = generated.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    }
    stable.set(purpose, Object.freeze(record));
  }
  return Object.freeze({
    registry() {
      const records = new Map(stable);
      records.set(KEY_PURPOSES.POLICY, Object.freeze(Object.entries(keyPairs).map(([keyId, pair]) => ({
        purpose: KEY_PURPOSES.POLICY,
        identityType: 'ed25519_public',
        keyId,
        identity: fingerprint(pair.publicKey),
        publicKeySpki: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        slot: keyId === keyState.current ? 'current'
          : keyId === keyState.next ? 'next' : 'verifyOnly',
        references: 0,
      }))));
      return Object.freeze({
        generation: keyState.epoch,
        get(purpose) {
          return clone(records.get(purpose)?.find?.((record) => record.slot === 'current')
            || records.get(purpose));
        },
        list(purpose) {
          const value = records.get(purpose);
          return clone(Array.isArray(value) ? value : value ? [value] : []);
        },
        activePublicKeys(purpose) {
          return publicKeysFor(this.list(purpose).filter(
            (record) => ['current', 'next'].includes(record.slot),
          ));
        },
        verificationPublicKey(purpose, keyId) {
          return publicKeysFor(this.list(purpose).filter((record) => record.keyId === keyId));
        },
        assertPublicKey(purpose, keyId, identity) {
          assertManifestKey(this.list(purpose), keyId, identity, false);
        },
        assertHistoricalPublicKey(purpose, keyId, identity) {
          assertManifestKey(this.list(purpose), keyId, identity, true);
        },
      });
    },
  });
}

function allOwnerRecords(authorityManifest) {
  const registry = authorityManifest.registry();
  return Object.keys(AUTHORITY_DEFINITIONS).flatMap((purpose) => registry.list(purpose));
}

function publicKeysFor(records) {
  if (records.length < 1) throw new Error('manifest public key missing');
  return new Map(records.map((record) => [record.keyId, crypto.createPublicKey({
    key: Buffer.from(record.publicKeySpki, 'base64'),
    format: 'der',
    type: 'spki',
  })]));
}

function assertManifestKey(records, keyId, identity, historical) {
  if (!records.some((record) => record.keyId === keyId && record.identity === identity
      && (historical || ['current', 'next'].includes(record.slot)))) {
    throw new Error('manifest key mismatch');
  }
}

function trustForPolicy(keyPairs, currentEpoch, authorityManifest, approvalPublicKey) {
  const authorityRegistry = authorityManifest.registry();
  const records = allOwnerRecords(authorityManifest);
  const policyIdentities = new Set(records
    .filter((record) => record.purpose === KEY_PURPOSES.POLICY)
    .map((record) => record.identity));
  const offlineKeyFingerprint = authorityManifest.registry()
    .get(KEY_PURPOSES.OFFLINE_LICENSE).identity;
  return {
    currentEpoch,
    publicKeys: authorityRegistry.activePublicKeys(KEY_PURPOSES.POLICY),
    keyEpochs: Object.fromEntries(Object.keys(keyPairs).map((keyId) => [keyId, {
      validFromEpoch: keyId.endsWith('1') ? 1 : 2,
      retireAfterEpoch: null,
    }])),
    offlineKeyFingerprint,
    forbiddenPublicKeyFingerprints: [
      ...records.map((record) => record.identity)
        .filter((identity) => identity !== offlineKeyFingerprint && !policyIdentities.has(identity)),
      crypto.createHash('sha256').update(INTEGRITY_SECRET).digest('hex'),
      crypto.createHash('sha256').update(PENDING_SECRET).digest('hex'),
      fingerprint(approvalPublicKey),
    ],
    authorityRegistry,
  };
}

function approvalTrust(keyId, publicKey, authorityManifest) {
  const records = allOwnerRecords(authorityManifest);
  const offlineKeyFingerprint = authorityManifest.registry()
    .get(KEY_PURPOSES.OFFLINE_LICENSE).identity;
  return {
    currentEpoch: 1,
    publicKeys: { [keyId]: publicKey },
    keyEpochs: { [keyId]: { validFromEpoch: 1, retireAfterEpoch: null } },
    offlineKeyFingerprint,
    forbiddenPublicKeyFingerprints: [
      ...records.map((record) => record.identity)
        .filter((identity) => identity !== offlineKeyFingerprint),
      crypto.createHash('sha256').update(INTEGRITY_SECRET).digest('hex'),
      crypto.createHash('sha256').update(PENDING_SECRET).digest('hex'),
    ],
  };
}

function digest(value) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

async function expectCode(promise, code) {
  await assert.rejects(promise, (error) => error && error.code === code);
}

function snapshot(storage) {
  const data = storage.data;
  return {
    authorizations: [...data.authorizations],
    confirmations: [...data.confirmations],
    approvals: [...data.approvals],
    records: [...data.records],
    operations: [...data.operations],
    pending: [...data.pending],
    auditHighWater: data.auditHighWater,
    auditAnchor: data.auditAnchor,
    auditEvents: [...data.auditEvents],
  };
}

function captureConsole(callback) {
  const originals = new Map(['debug', 'error', 'info', 'log', 'warn']
    .map((method) => [method, console[method]]));
  const records = [];
  for (const method of originals.keys()) console[method] = (...args) => records.push({ method, args });
  const result = Promise.resolve().then(callback).finally(() => {
    for (const [method, original] of originals) console[method] = original;
  });
  return { records, result };
}

function deepExposure(value, seen = new Set(), depth = 0) {
  if (value === null || value === undefined || typeof value !== 'object') return String(value);
  if (seen.has(value) || depth > 8) return '[bounded]';
  seen.add(value);
  const output = [];
  for (const key of Reflect.ownKeys(value)) {
    output.push(String(key));
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      output.push(deepExposure(descriptor.value, seen, depth + 1));
    }
  }
  seen.delete(value);
  return output.join('\n');
}
