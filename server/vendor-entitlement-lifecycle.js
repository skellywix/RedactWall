'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const {
  KEY_PURPOSES,
  keyFingerprint,
  normalizePublicKeys,
  parsePublicOnlyEd25519Key,
  validPurposeKeyBinding,
  validPurposeKeyId,
  verifySignedArtifact,
} = require('./vendor-signed-artifact');

const SCHEMA_VERSION = 4;
const INTEGRITY_PURPOSE = 'vendor_entitlement_lifecycle_integrity';
const WITNESS_PURPOSE = 'vendor_entitlement_lifecycle_witness';
const TARGET_CONFIRMATION_PURPOSE = 'vendor_entitlement_target_approval';
const OWNER_ATTESTATION_PURPOSE = 'vendor_entitlement_target_approval_attestation';
const OWNER_ATTESTATION_SIGNATURE_DOMAIN = 'redactwall.owner-entitlement-attestation.v1';
const CREDENTIAL_VERSION = 1;
const MAX_STEP_UP_AGE_MS = 5 * 60 * 1000;
const MAX_TARGET_CONFIRMATION_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_AUTH_EVENT_AGE_MS = 15 * 60 * 1000;
const MAX_ACK_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 60 * 1000;
const MIN_TIME_MS = Date.parse('2020-01-01T00:00:00.000Z');
const MAX_TIME_MS = Date.parse('2100-01-01T00:00:00.000Z');
const MAX_COMMAND_BYTES = 32 * 1024;
const MAX_RECORD_BYTES = 128 * 1024;
const MAX_EVENT_BYTES = 64 * 1024;
const MAX_WITNESS_BYTES = 64 * 1024;
const MAX_DEPTH = 16;
const STAGES = Object.freeze(['requested', 'issued', 'delivered', 'applied', 'acknowledged']);
const MANUAL_REASON_CODES = Object.freeze(['manual_pause', 'manual_revoke', 'manual_restore']);
const MANUAL_ACTOR_ROLES = Object.freeze([
  'vendor_owner', 'vendor_billing_admin', 'vendor_security_admin',
]);
const SERVICE_ACTOR_ROLES = Object.freeze(['billing_service', 'control_plane_service']);
const CUSTOMER_ACTOR_ROLE = 'customer_connector';
const ACTIONS = Object.freeze({
  REQUEST: 'entitlement.request',
  TARGET_CONFIRM: 'entitlement.target-confirm',
  ISSUE: 'entitlement.issue',
  DELIVER: 'entitlement.deliver',
  ACKNOWLEDGE: 'entitlement.acknowledge',
  ACCEPT: 'entitlement.accept',
  READ: 'entitlement.read',
});
const CREDENTIAL_PURPOSES = Object.freeze({
  REQUEST: 'vendor_entitlement_request',
  TARGET_CONFIRMATION: 'vendor_entitlement_target_approval',
  BREAK_GLASS: 'vendor_entitlement_break_glass',
  ISSUE: 'vendor_entitlement_issue',
  DELIVER: 'vendor_entitlement_delivery',
  ACKNOWLEDGE: 'customer_entitlement_ack',
  ACCEPT: 'vendor_entitlement_acceptance',
  READ: 'vendor_entitlement_read',
});
const ACTION_ROLES = Object.freeze({
  [ACTIONS.REQUEST]: new Set([...MANUAL_ACTOR_ROLES, ...SERVICE_ACTOR_ROLES]),
  [ACTIONS.TARGET_CONFIRM]: new Set(MANUAL_ACTOR_ROLES),
  [ACTIONS.ISSUE]: new Set(['vendor_owner', 'billing_service', 'control_plane_service']),
  [ACTIONS.DELIVER]: new Set(['control_plane_service']),
  [ACTIONS.ACKNOWLEDGE]: new Set([CUSTOMER_ACTOR_ROLE]),
  [ACTIONS.ACCEPT]: new Set(['vendor_owner', 'control_plane_service']),
  [ACTIONS.READ]: new Set([...MANUAL_ACTOR_ROLES, ...SERVICE_ACTOR_ROLES]),
});
const ACTION_CREDENTIALS = Object.freeze({
  [ACTIONS.REQUEST]: CREDENTIAL_PURPOSES.REQUEST,
  [ACTIONS.TARGET_CONFIRM]: CREDENTIAL_PURPOSES.TARGET_CONFIRMATION,
  [ACTIONS.ISSUE]: CREDENTIAL_PURPOSES.ISSUE,
  [ACTIONS.DELIVER]: CREDENTIAL_PURPOSES.DELIVER,
  [ACTIONS.ACKNOWLEDGE]: CREDENTIAL_PURPOSES.ACKNOWLEDGE,
  [ACTIONS.ACCEPT]: CREDENTIAL_PURPOSES.ACCEPT,
  [ACTIONS.READ]: CREDENTIAL_PURPOSES.READ,
});
const TX_METHODS = Object.freeze([
  'advanceCurrentEntitlement', 'claimAcceptanceId', 'claimAckMessage',
  'claimAuthEvent', 'claimTargetConfirmation',
  'clearPendingWitness', 'findByAckMessageId',
  'findByIdempotencyKey', 'findByTargetVersion', 'findByWitnessOperationId',
  'get', 'getAcceptanceClaim', 'getAckClaim', 'getAuthClaim',
  'getOwnerAttestation', 'getPendingWitness',
  'getTargetConfirmationClaim',
  'insertLifecycle', 'listEvents', 'listPendingWitnesses', 'lockAuthEvent',
  'lockCurrentEntitlement', 'lockOwnerAttestation', 'lockTargetConfirmation',
  'updateLifecycle',
]);
const WITNESS_METHODS = Object.freeze([
  'abort', 'finalize', 'identity', 'listPrepared', 'prepare', 'readFinal',
  'readOperation', 'readScope', 'verify',
]);
const BUSINESS_KEYS = Object.freeze([
  'acceptance', 'currentState', 'customerAck', 'customerId', 'deploymentId',
  'entitlementDigest', 'entitlementVersion', 'idempotencyKey', 'issuance',
  'lifecycleId', 'operationDigests', 'proposedState', 'revision', 'schemaVersion',
  'stage', 'targetConfirmation', 'timestamps', 'updatedAt', 'delivery',
]);
const RECORD_KEYS = Object.freeze([
  ...BUSINESS_KEYS, 'eventCount', 'eventHead', 'macKeyId', 'recordMac',
  'stateDigest', 'tailAuthorityDigest', 'tailClaimDigest', 'tailOperationDigest',
  'witnessOperationId',
]);
const EVENT_KEYS = Object.freeze([
  'authority', 'authorityDigest', 'claimDigest', 'claimEvidence', 'customerId',
  'deploymentId', 'entitlementDigest', 'entitlementVersion', 'eventDigest',
  'eventId', 'eventMac', 'fromStage', 'lifecycleId', 'macKeyId',
  'operationDigest', 'previousEventDigest', 'recordedAt', 'revision',
  'schemaVersion', 'stateDigest', 'toStage', 'witnessOperationId',
]);
const OPERATION_KEYS = Object.freeze(STAGES);
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_-]{16,128}$/;
const WITNESS_KEY_ID_RE = /^rw-lifecycle-witness-[a-z0-9][a-z0-9_.-]{0,63}$/;
const SAFE_SLUG_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECORD_DOMAIN = 'redactwall.vendor-entitlement-lifecycle.record.v4';
const EVENT_DOMAIN = 'redactwall.vendor-entitlement-lifecycle.event.v4';
const PENDING_DOMAIN = 'redactwall.vendor-entitlement-lifecycle.pending.v1';
const ACK_CLAIM_DOMAIN = 'redactwall.vendor-entitlement-lifecycle.ack-claim.v1';
const AUTHORITY_MANIFEST_VERSION = 1;
const MAX_AUTHORITY_MANIFEST_BYTES = 128 * 1024;
const AUTHORITY_PURPOSES = Object.freeze({
  OFFLINE_LICENSE: KEY_PURPOSES.OFFLINE_LICENSE,
  ONLINE_VERDICT: KEY_PURPOSES.ONLINE_VERDICT,
  ENTITLEMENT: KEY_PURPOSES.ENTITLEMENT,
  PLATFORM_AUDIT: KEY_PURPOSES.PLATFORM_AUDIT,
  RECOVERY: KEY_PURPOSES.RECOVERY,
  LICENSE_REGISTRY_INTEGRITY:
    KEY_PURPOSES.LICENSE_REGISTRY_INTEGRITY || 'license_registry_integrity',
  COMMAND_IDEMPOTENCY:
    KEY_PURPOSES.COMMAND_IDEMPOTENCY || 'command_idempotency',
  PAGINATION_CURSOR:
    KEY_PURPOSES.PAGINATION_CURSOR || 'pagination_cursor',
  DIAGNOSTIC_INTEGRITY: KEY_PURPOSES.DIAGNOSTIC_INTEGRITY,
  AUDIT_REQUEST: KEY_PURPOSES.AUDIT_REQUEST,
  POLICY: KEY_PURPOSES.POLICY,
  LIFECYCLE_INTEGRITY: KEY_PURPOSES.LIFECYCLE,
  CATALOG_GLOBAL: KEY_PURPOSES.CATALOG_GLOBAL,
  CATALOG_DISTRIBUTION: KEY_PURPOSES.CATALOG_DISTRIBUTION,
  OWNER_ATTESTATION: 'owner_attestation',
  WITNESS_INTEGRITY: 'witness_integrity',
  HEARTBEAT_CREDENTIAL: 'heartbeat_credential',
  ACKNOWLEDGEMENT_CREDENTIAL: 'acknowledgement_credential',
  DIAGNOSTIC_CREDENTIAL: 'diagnostic_credential',
  SHADOW_CANDIDATE_CREDENTIAL: 'shadow_candidate_credential',
});
const AUTHORITY_MANIFEST_DEFINITIONS = Object.freeze({
  [AUTHORITY_PURPOSES.OFFLINE_LICENSE]: authorityDefinition(
    'ed25519_public', 'rw-offline-license-', false,
  ),
  [AUTHORITY_PURPOSES.ONLINE_VERDICT]: authorityDefinition(
    'ed25519_public', 'rw-online-verdict-', false,
  ),
  [AUTHORITY_PURPOSES.ENTITLEMENT]: authorityDefinition(
    'ed25519_public', 'rw-entitlement-', true,
  ),
  [AUTHORITY_PURPOSES.PLATFORM_AUDIT]: authorityDefinition(
    'hmac_secret', 'rw-platform-audit-', false,
  ),
  [AUTHORITY_PURPOSES.RECOVERY]: authorityDefinition(
    'hmac_secret', 'rw-recovery-', false,
  ),
  [AUTHORITY_PURPOSES.LICENSE_REGISTRY_INTEGRITY]: authorityDefinition(
    'hmac_secret', 'rw-license-registry-integrity-', false,
  ),
  [AUTHORITY_PURPOSES.COMMAND_IDEMPOTENCY]: authorityDefinition(
    'hmac_secret', 'rw-command-idempotency-', false,
  ),
  [AUTHORITY_PURPOSES.PAGINATION_CURSOR]: authorityDefinition(
    'hmac_secret', 'rw-pagination-cursor-', false,
  ),
  [AUTHORITY_PURPOSES.DIAGNOSTIC_INTEGRITY]: authorityDefinition(
    'hmac_secret', 'rw-diagnostic-integrity-', false,
  ),
  [AUTHORITY_PURPOSES.AUDIT_REQUEST]: authorityDefinition(
    'ed25519_public', 'rw-audit-request-', true,
  ),
  [AUTHORITY_PURPOSES.POLICY]: authorityDefinition(
    'ed25519_public', 'rw-policy-', true,
  ),
  [AUTHORITY_PURPOSES.LIFECYCLE_INTEGRITY]: authorityDefinition(
    'hmac_secret', 'rw-lifecycle-', false,
  ),
  [AUTHORITY_PURPOSES.CATALOG_GLOBAL]: authorityDefinition(
    'ed25519_public', 'rw-catalog-global-', true,
  ),
  [AUTHORITY_PURPOSES.CATALOG_DISTRIBUTION]: authorityDefinition(
    'ed25519_public', 'rw-catalog-distribution-', true,
  ),
  [AUTHORITY_PURPOSES.OWNER_ATTESTATION]: authorityDefinition(
    'ed25519_public', 'rw-owner-attestation-', true,
  ),
  [AUTHORITY_PURPOSES.WITNESS_INTEGRITY]: authorityDefinition(
    'hmac_secret', 'rw-lifecycle-witness-', false,
  ),
  [AUTHORITY_PURPOSES.HEARTBEAT_CREDENTIAL]: authorityDefinition(
    'opaque_credential', 'rw-heartbeat-credential-', false,
  ),
  [AUTHORITY_PURPOSES.ACKNOWLEDGEMENT_CREDENTIAL]: authorityDefinition(
    'opaque_credential', 'rw-ack-credential-', false,
  ),
  [AUTHORITY_PURPOSES.DIAGNOSTIC_CREDENTIAL]: authorityDefinition(
    'opaque_credential', 'rw-diagnostic-credential-', false,
  ),
  [AUTHORITY_PURPOSES.SHADOW_CANDIDATE_CREDENTIAL]: authorityDefinition(
    'opaque_credential', 'rw-shadow-candidate-credential-', false,
  ),
});

function authorityDefinition(identityType, keyPrefix, allowNext) {
  return Object.freeze({ identityType, keyPrefix, allowNext });
}

function createVendorEntitlementLifecycle(options = {}) {
  const authorityRegistry = checkedAuthorityManifest(options.authorityManifest);
  const keyring = checkedIntegrityKeyring(options.integrityKeyring, authorityRegistry);
  const witness = checkedWitness(options.witness, keyring, authorityRegistry);
  const context = Object.freeze({
    storage: checkedStorage(options.storage),
    witness,
    witnessCurrentIdentity: witness.currentIdentity,
    witnessIdentities: witness.identities,
    authorityRegistry,
    ownerAuditVerifier: checkedOwnerAuditVerifier(options.ownerAuditVerifier, authorityRegistry),
    keyring,
    randomUUID: checkedOptionalFunction(options.randomUUID, crypto.randomUUID, 'uuid_generator_invalid'),
    now: checkedOptionalFunction(options.now, Date.now, 'clock_invalid'),
  });
  return Object.freeze({
    request: (command) => runReady(context, 'mutation', () => requestLifecycle(context, command)),
    issue: (command) => runReady(context, 'mutation', () => issueLifecycle(context, command)),
    markDelivered: () => runReady(context, 'mutation', forbiddenExternalTransition),
    acceptCustomerAcknowledgement: (command) => runReady(
      context, 'acknowledgement', () => acceptCustomerAcknowledgement(context, command), command,
    ),
    acknowledgeApplied: () => runReady(context, 'mutation', forbiddenExternalTransition),
    get: (query) => runReady(context, 'read', () => readLifecycle(context, query)),
    portalStatus: (query) => runReady(context, 'read', () => readLifecycle(context, query)),
    readiness: () => runReady(context, 'readiness', null),
  });
}

function forbiddenExternalTransition() {
  throw lifecycleError('external_transition_forbidden');
}

async function runReady(context, mode, operation, command = null) {
  return coordinate(context.storage, async () => {
    const readiness = await reconcileLocked(context);
    if (!readiness.ready) {
      if (mode === 'readiness') return readiness;
      if (mode === 'acknowledgement') {
        const pending = await pendingAcknowledgementDuringReconciliation(context, command);
        if (pending) return pending;
      }
      if (mode === 'mutation') return pendingResult(null, readiness.code);
      if (mode === 'acknowledgement') return pendingResult(null, readiness.code);
      throw lifecycleError('lifecycle_readiness_frozen');
    }
    if (mode === 'readiness') return readiness;
    return operation();
  });
}

async function pendingAcknowledgementDuringReconciliation(context, commandValue) {
  try {
    const command = checkedAckCommand(commandValue);
    const nowMs = checkedNow(context.now());
    return await readTransaction(context.storage, async (tx) => {
      const auth = await trustedAuth(tx, command.authEventId, nowMs);
      authorizeBase(
        auth, ACTIONS.ACKNOWLEDGE, auth, [CREDENTIAL_PURPOSES.ACKNOWLEDGE], nowMs,
      );
      const acknowledgement = checkedAcknowledgement(command.acknowledgement);
      if (acknowledgement.lifecycleStage !== 'applied'
          || acknowledgement.outcome !== 'success') return null;
      authorizeScope(auth, acknowledgement, 'customer_ack_not_found');
      const ackDigest = protocol.payloadDigest(
        acknowledgement, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
      );
      const operationDigest = acknowledgementOperationDigest(acknowledgement, ackDigest);
      const claim = checkedAckClaim(
        context, await tx.findByAckMessageId(acknowledgement.messageId),
      );
      assertAcknowledgementClaimMatch(
        claim, auth, acknowledgement, ackDigest, operationDigest,
      );
      const pendingValues = await tx.listPendingWitnesses();
      if (!Array.isArray(pendingValues) || pendingValues.length > 1_000) return null;
      const matches = [];
      for (const value of pendingValues) {
        const pending = checkedPending(context, value);
        if (pending.descriptor.lifecycleId === claim.lifecycleId
            && pending.descriptor.customerId === claim.customerId
            && pending.descriptor.deploymentId === claim.deploymentId
            && pending.descriptor.entitlementVersion === claim.targetVersion
            && ['applied', 'acknowledged'].includes(pending.descriptor.stage)) {
          matches.push(pending);
        }
      }
      if (matches.length !== 1) return null;
      const pending = matches[0];
      const stored = await tx.findByWitnessOperationId(pending.descriptor.operationId);
      if (!stored) return null;
      const restored = await restoreRecord(context, tx, stored, claim, {
        descriptor: pending.descriptor,
        allowPreparedTail: true,
      });
      if (restored.record.stage !== pending.descriptor.stage
          || restored.record.customerAck.acknowledgement.messageId !== claim.messageId
          || restored.record.customerAck.payloadDigest !== claim.payloadDigest
          || restored.record.operationDigests.applied !== claim.operationDigest) return null;
      const envelope = await checkedWitnessEnvelope(
        context,
        await context.witness.readOperation(pending.descriptor.operationId),
        pending.descriptor,
        'prepared',
      );
      if (envelope.state !== 'prepared' || !await witnessPositionMatches(context, envelope)) {
        return null;
      }
      const current = await tx.lockCurrentEntitlement(claim.customerId, claim.deploymentId);
      if (!exactStoredBinding(
        current, expectedCurrentEntitlement(restored.record, pending.descriptor), 32 * 1024,
      )) return null;
      return acknowledgementPendingResult({
        operationRef: digest(pending.descriptor.operationId).slice(0, 24),
      });
    });
  } catch {
    return null;
  }
}

async function reconcileLocked(context) {
  try {
    const pendingEntries = await readTransaction(
      context.storage, (tx) => tx.listPendingWitnesses(),
    );
    if (!Array.isArray(pendingEntries) || pendingEntries.length > 1_000) {
      return frozenReadiness('pending_witness_invalid');
    }
    const pendingByOperation = new Map();
    for (const value of pendingEntries) {
      const pending = checkedPending(context, value);
      if (pendingByOperation.has(pending.descriptor.operationId)) {
        return frozenReadiness('pending_witness_invalid');
      }
      pendingByOperation.set(pending.descriptor.operationId, pending);
      if (!await reconcileCommittedPending(context, pending)) {
        return frozenReadiness('pending_witness_unresolved');
      }
    }

    const preparedValues = await context.witness.listPrepared();
    const prepared = boundedSnapshot(
      preparedValues, MAX_WITNESS_BYTES * 1_000, MAX_DEPTH, 'witness_invalid',
    );
    if (!Array.isArray(prepared) || prepared.length > 1_000) {
      return frozenReadiness('witness_invalid');
    }
    for (const value of prepared) {
      const envelope = await checkedWitnessEnvelope(context, value, null, 'prepared');
      if (pendingByOperation.has(envelope.descriptor.operationId)) continue;
      if (!await reconcileOrphanPrepare(context, envelope)) {
        return frozenReadiness('pending_witness_unresolved');
      }
    }

    const remaining = await readTransaction(
      context.storage, (tx) => tx.listPendingWitnesses(),
    );
    if (!Array.isArray(remaining) || remaining.length !== 0) {
      return frozenReadiness('pending_witness_unresolved');
    }
    return Object.freeze({ ok: true, ready: true, retryable: false, pendingCount: 0 });
  } catch {
    return frozenReadiness('lifecycle_reconciliation_failed');
  }
}

async function reconcileCommittedPending(context, pending) {
  const committed = await verifyCommittedDescriptor(context, pending.descriptor);
  if (!committed) return false;
  const envelopeValue = await context.witness.readOperation(pending.descriptor.operationId);
  if (!envelopeValue) return false;
  const envelope = await checkedWitnessEnvelope(
    context, envelopeValue, pending.descriptor, null,
  );
  if (envelope.state === 'prepared') {
    if (!await witnessPositionMatches(context, envelope)
        || !await finalizeDescriptor(context, pending.descriptor)) return false;
  }
  const finalized = await verifyFinalizedCommit(context, pending.descriptor);
  if (!finalized) return false;
  await clearPendingBestEffort(context, pending);
  return true;
}

async function reconcileOrphanPrepare(context, envelope) {
  const committed = await findCommittedDescriptor(context, envelope.descriptor);
  if (committed) {
    return finalizeDescriptor(context, envelope.descriptor);
  }
  return abortDescriptor(context, envelope.descriptor);
}

async function verifyCommittedDescriptor(context, descriptor) {
  return readTransaction(context.storage, async (tx) => {
    const stored = await tx.findByWitnessOperationId(descriptor.operationId);
    if (!stored) return null;
    const pending = await tx.getPendingWitness(descriptor.operationId);
    const checked = checkedPending(context, pending);
    if (!canonicalEqual(checked.descriptor, descriptor)) {
      throw lifecycleError('pending_witness_invalid');
    }
    const restored = await restoreRecord(context, tx, stored, scopeOf(descriptor), {
      descriptor,
      allowPreparedTail: true,
    });
    const record = restored.record;
    const [direct, idempotency, target, current] = await Promise.all([
      tx.get(record.lifecycleId),
      tx.findByIdempotencyKey(
        record.customerId, record.deploymentId, record.idempotencyKey,
      ),
      tx.findByTargetVersion(
        record.customerId, record.deploymentId, record.entitlementVersion,
      ),
      tx.lockCurrentEntitlement(record.customerId, record.deploymentId),
    ]);
    if (![direct, idempotency, target].every((value) => exactStoredBinding(value, record))
        || !exactStoredBinding(
          current, expectedCurrentEntitlement(record, descriptor), 32 * 1024,
        )) {
      throw lifecycleError('committed_binding_invalid');
    }
    return restored;
  });
}

async function findCommittedDescriptor(context, descriptor) {
  return verifyCommittedDescriptor(context, descriptor);
}

async function finalizeDescriptor(context, descriptor) {
  try {
    const value = await context.witness.finalize(
      descriptor.operationId, digest(descriptor),
    );
    const envelope = await checkedWitnessEnvelope(context, value, descriptor, 'final');
    return envelope.state === 'final';
  } catch {
    return isDescriptorFinal(context, descriptor);
  }
}

async function isDescriptorFinal(context, descriptor) {
  try {
    const value = await context.witness.readOperation(descriptor.operationId);
    if (!value) return false;
    const envelope = await checkedWitnessEnvelope(context, value, descriptor, null);
    return envelope.state === 'final';
  } catch {
    return false;
  }
}

async function witnessPositionMatches(context, envelope) {
  try {
    const scopeValue = await context.witness.readScope(
      envelope.descriptor.customerId, envelope.descriptor.deploymentId,
    );
    if (envelope.state === 'final') {
      if (!scopeValue) return false;
      const scope = await checkedWitnessEnvelope(context, scopeValue, null, 'final');
      return canonicalEqual(scope, envelope);
    }
    if (envelope.descriptor.previousWitnessDigest === null) return scopeValue === null;
    if (!scopeValue) return false;
    const scope = await checkedWitnessEnvelope(context, scopeValue, null, 'final');
    return scope.descriptorDigest === envelope.descriptor.previousWitnessDigest;
  } catch {
    return false;
  }
}

async function verifyFinalizedCommit(context, descriptor) {
  try {
    const committed = await verifyCommittedDescriptor(context, descriptor);
    if (!committed) return null;
    const operationValue = await context.witness.readOperation(descriptor.operationId);
    if (!operationValue) return null;
    const operation = await checkedWitnessEnvelope(
      context, operationValue, descriptor, 'final',
    );
    if (!await witnessPositionMatches(context, operation)) return null;
    return committed;
  } catch {
    return null;
  }
}

function expectedCurrentEntitlement(record, descriptor) {
  return record.stage === 'acknowledged'
    ? currentStateFromTransition(record, descriptor)
    : clone(record.currentState);
}

function exactStoredBinding(value, expected, maxBytes = MAX_RECORD_BYTES) {
  try {
    return canonicalEqual(
      boundedSnapshot(value, maxBytes, MAX_DEPTH, 'committed_binding_invalid'),
      expected,
    );
  } catch {
    return false;
  }
}

async function abortDescriptor(context, descriptor) {
  try {
    await context.witness.abort(descriptor.operationId, digest(descriptor));
    return (await context.witness.readOperation(descriptor.operationId)) === null;
  } catch {
    try { return (await context.witness.readOperation(descriptor.operationId)) === null; }
    catch { return false; }
  }
}

async function clearPendingBestEffort(context, pending) {
  try {
    await readTransaction(context.storage, async (tx) => {
      const cleared = await tx.clearPendingWitness(
        pending.descriptor.operationId, pending.descriptorDigest,
      );
      if (cleared !== true) throw lifecycleError('pending_witness_conflict');
      return true;
    }, true);
  } catch {
    // The independently final witness is authoritative; reconciliation will retry cleanup.
  }
}

async function mutateWithWitness(context, work) {
  const operationId = checkedGeneratedUuid(context.randomUUID());
  let prepared = null;
  const attempt = await transactionAttempt(context.storage, async (tx) => {
    const candidate = await work(tx, operationId);
    if (candidate.kind === 'idempotent') return candidate;
    prepared = candidate;
    await prepareDescriptor(context, candidate.descriptor);
    await candidate.commit();
    return {
      kind: 'transition',
      descriptor: candidate.descriptor,
      pending: candidate.pending,
      record: candidate.record,
    };
  });

  if (attempt.status === 'committed') {
    if (attempt.value.kind === 'idempotent') return attempt.value.result;
    return confirmPurportedCommit(context, attempt.value);
  }
  if (!prepared) throw normalizedRollbackError(attempt.error);
  return resolveTransactionFailure(context, prepared, attempt.error);
}

async function confirmPurportedCommit(context, candidate) {
  let committed;
  try { committed = await verifyCommittedDescriptor(context, candidate.descriptor); }
  catch { return pendingResult(candidate.descriptor, 'commit_pending_reconciliation'); }
  if (!committed) {
    return pendingResult(candidate.descriptor, 'commit_pending_reconciliation');
  }
  return finishCommittedTransition(context, {
    descriptor: candidate.descriptor,
    pending: candidate.pending,
    record: committed.record,
  });
}

async function prepareDescriptor(context, descriptor) {
  let value;
  try { value = await context.witness.prepare(deepFreeze(clone(descriptor))); }
  catch {
    try { value = await context.witness.readOperation(descriptor.operationId); }
    catch { throw lifecycleError('witness_prepare_uncertain'); }
  }
  if (!value) throw lifecycleError('witness_prepare_failed');
  const envelope = await checkedWitnessEnvelope(context, value, descriptor, 'prepared');
  if (envelope.state !== 'prepared'
      || !canonicalEqual(envelope.witnessIdentity, context.witnessCurrentIdentity)) {
    throw lifecycleError('witness_prepare_failed');
  }
}

async function finishCommittedTransition(context, committed) {
  if (!await finalizeDescriptor(context, committed.descriptor)) {
    return pendingResult(committed.descriptor, 'witness_finalize_pending');
  }
  const finalized = await verifyFinalizedCommit(context, committed.descriptor);
  if (!finalized) {
    return pendingResult(committed.descriptor, 'finalized_binding_pending');
  }
  await clearPendingBestEffort(context, committed.pending);
  return operationResult(finalized.record, false);
}

async function resolveTransactionFailure(context, candidate, error) {
  let committed;
  try { committed = await findCommittedDescriptor(context, candidate.descriptor); }
  catch { return pendingResult(candidate.descriptor, 'commit_pending_reconciliation'); }
  if (committed) {
    return finishCommittedTransition(context, {
      descriptor: candidate.descriptor,
      pending: candidate.pending,
      record: committed.record,
    });
  }
  if (!await abortDescriptor(context, candidate.descriptor)) {
    return pendingResult(candidate.descriptor, 'commit_pending_reconciliation');
  }
  throw normalizedRollbackError(error);
}

async function transactionAttempt(storage, work) {
  let invocations = 0;
  let callbackCompleted = false;
  let expectedEnvelope = null;
  let expectedError = null;
  let workRejected = false;
  let acceptingInvocation = true;
  const nonce = Object.freeze({});
  try {
    const returned = await storage.transaction((tx) => {
      if (!acceptingInvocation || ++invocations !== 1) throw lifecycleError('storage_invalid');
      checkedTransaction(tx);
      return Promise.resolve().then(() => work(tx)).then(
        (value) => {
          callbackCompleted = true;
          expectedEnvelope = Object.freeze({ nonce, value });
          return expectedEnvelope;
        },
        (error) => {
          callbackCompleted = true;
          workRejected = true;
          expectedError = error;
          throw error;
        },
      );
    });
    acceptingInvocation = false;
    if (invocations !== 1 || !callbackCompleted || returned !== expectedEnvelope
        || returned.nonce !== nonce) {
      return { status: 'error', error: lifecycleError('storage_result_uncertain') };
    }
    return { status: 'committed', value: returned.value };
  } catch (error) {
    acceptingInvocation = false;
    return {
      status: 'error',
      error,
      callbackCompleted,
      trustedWorkError: invocations === 1 && workRejected && error === expectedError,
    };
  }
}

async function readTransaction(storage, work, mutating = false) {
  const attempt = await transactionAttempt(storage, work);
  if (attempt.status === 'committed') return attempt.value;
  if (attempt.trustedWorkError) throw normalizedRollbackError(attempt.error);
  if (mutating) throw lifecycleError('storage_result_uncertain');
  throw lifecycleError('storage_invalid');
}

async function coordinate(storage, work) {
  let invocations = 0;
  let expectedEnvelope = null;
  let acceptingInvocation = true;
  const nonce = Object.freeze({});
  try {
    const returned = await storage.coordinate(() => {
      if (!acceptingInvocation || ++invocations !== 1) throw lifecycleError('storage_invalid');
      return Promise.resolve().then(work).then((value) => {
        expectedEnvelope = Object.freeze({ nonce, value });
        return expectedEnvelope;
      });
    });
    acceptingInvocation = false;
    if (invocations !== 1 || returned !== expectedEnvelope || returned.nonce !== nonce) {
      throw lifecycleError('storage_invalid');
    }
    return returned.value;
  } finally {
    acceptingInvocation = false;
  }
}

function pendingResult(descriptor, code) {
  return deepFreeze({
    ok: false,
    pending: true,
    retryable: false,
    code,
    operationRef: descriptor ? digest(descriptor.operationId).slice(0, 24) : null,
  });
}

function frozenReadiness(code) {
  return Object.freeze({ ok: false, ready: false, retryable: false, pendingCount: null, code });
}

function normalizedRollbackError(error) {
  if (error && typeof error.code === 'string' && /^[a-z0-9_]{3,64}$/.test(error.code)) {
    return lifecycleError(error.code);
  }
  return lifecycleError('transaction_rolled_back');
}

async function requestLifecycle(context, commandValue) {
  const command = checkedRequestCommand(commandValue);
  const nowMs = checkedNow(context.now());
  return mutateWithWitness(context, async (tx, witnessOperationId) => {
    const auth = await trustedAuth(tx, command.authEventId, nowMs);
    authorizeBase(auth, ACTIONS.REQUEST, auth, [
      CREDENTIAL_PURPOSES.REQUEST, CREDENTIAL_PURPOSES.BREAK_GLASS,
    ], nowMs);
    const entitlement = checkedEntitlement(command.entitlement);
    const scope = scopeOf(entitlement);
    authorizeScope(auth, scope, 'scope_mismatch');
    const entitlementDigest = protocol.payloadDigest(
      entitlement, protocol.CHANNEL_KINDS.ENTITLEMENT,
    );
    const operationDigest = requestOperationDigest(command, entitlementDigest);
    const existing = await tx.findByIdempotencyKey(
      scope.customerId, scope.deploymentId, command.idempotencyKey,
    );
    if (existing) {
      const restored = await restoreRecord(context, tx, existing, scope);
      authorizeStoredRequestMode(auth, restored.record, nowMs);
      if (restored.record.operationDigests.requested !== operationDigest) {
        throw lifecycleError('idempotency_conflict');
      }
      return idempotentCandidate(restored.record);
    }
    const target = await tx.findByTargetVersion(
      scope.customerId, scope.deploymentId, entitlement.entitlementVersion,
    );
    if (target) {
      await restoreRecord(context, tx, target, scope);
      throw lifecycleError('lifecycle_target_conflict');
    }
    const currentState = await trustedCurrentState(context, tx, entitlement);
    requireRestrictionPrecedence(entitlement, currentState);
    const dualControl = requiresDualControl(entitlement, currentState);
    const targetConfirmation = await trustedTargetConfirmation(
      context, tx, command.targetConfirmationId, entitlement, entitlementDigest, auth,
      dualControl, nowMs,
    );
    authorizeNewRequestMode(auth, entitlement, dualControl, targetConfirmation, nowMs);
    const lifecycleId = checkedGeneratedUuid(context.randomUUID());
    const business = requestedBusiness(
      lifecycleId, command, entitlement, entitlementDigest, currentState,
      targetConfirmation, operationDigest, nowMs,
    );
    const claims = transitionClaims(auth, lifecycleId, operationDigest, {
      approvalAuth: targetConfirmation && targetConfirmation.approverAuthority,
      targetConfirmation: targetConfirmationClaim(targetConfirmation, lifecycleId),
    });
    const sealed = sealTransition(
      context, business, null, null, 'requested', auth, claims, operationDigest,
      witnessOperationId,
    );
    const candidate = transitionCandidate(
      context,
      sealed,
      currentState ? currentState.provenance.witnessDescriptorDigest : null,
      witnessOperationId,
    );
    return {
      ...candidate,
      commit: async () => {
        await claimAuth(tx, claims.authClaim);
        if (claims.approvalAuthClaim) await claimAuth(tx, claims.approvalAuthClaim);
        if (claims.targetConfirmationClaim
            && await tx.claimTargetConfirmation(clone(claims.targetConfirmationClaim)) !== true) {
          throw lifecycleError('target_confirmation_reused');
        }
        const inserted = await tx.insertLifecycle(
          clone(sealed.record), clone(sealed.event), clone(candidate.pending),
        );
        if (inserted !== true) throw lifecycleError('lifecycle_conflict');
      },
    };
  });
}

async function issueLifecycle(context, commandValue) {
  const command = checkedMutationCommand(commandValue, ['artifact']);
  const nowMs = checkedNow(context.now());
  return mutateWithWitness(context, async (tx, witnessOperationId) => {
    const auth = await trustedAuth(tx, command.authEventId, nowMs);
    authorizeBase(auth, ACTIONS.ISSUE, auth, [CREDENTIAL_PURPOSES.ISSUE], nowMs);
    const restored = await loadRecord(context, tx, command.lifecycleId, auth);
    authorizeScope(auth, restored.record, 'scope_mismatch');
    const artifact = checkedSignedArtifact(command.artifact);
    const verified = verifiedEntitlementArtifact(context, artifact);
    assertArtifactMatchesRecord(verified, restored.record);
    const artifactDigest = digest(artifact);
    const operationDigest = digest({
      stage: 'issued', lifecycleId: restored.record.lifecycleId, artifactDigest,
    });
    const replay = transitionReplay(restored.record, 'issued', operationDigest);
    if (replay) return idempotentCandidate(restored.record);
    assertRevisionAndStage(restored.record, command.expectedRevision, 'requested');
    const business = nextBusiness(restored.record, 'issued', operationDigest, nowMs);
    business.issuance = {
      artifact,
      artifactDigest,
      issuedAt: business.updatedAt,
      keyId: verified.keyId,
      signatureDomain: verified.signatureDomain,
      verificationKeyFingerprint: verified.verificationKeyFingerprint,
      verificationKeySpki: verified.verificationKeySpki,
    };
    const claims = transitionClaims(
      auth, restored.record.lifecycleId, operationDigest,
    );
    return updateCandidate(
      context, tx, restored, business, 'requested', 'issued', auth, claims,
      operationDigest, witnessOperationId,
    );
  });
}

async function acceptCustomerAcknowledgement(context, commandValue) {
  const command = checkedAckCommand(commandValue);
  const acknowledgement = await authenticatedAcknowledgement(context, command);
  if (acknowledgement.outcome === 'rejected') {
    return recordRejectedAcknowledgement(context, command, acknowledgement);
  }
  const accepted = await acceptSuccessfulAcknowledgement(context, command, acknowledgement);
  if (acknowledgement.lifecycleStage === 'delivered'
      || accepted.lifecycle && accepted.lifecycle.stage === 'acknowledged') {
    return accepted;
  }
  if (accepted.pending) return acknowledgementPendingResult(accepted);
  let finalized;
  try {
    finalized = await finalizeAppliedAcknowledgement(context, command, acknowledgement);
  } catch {
    return acknowledgementPendingResult(null);
  }
  return finalized.pending ? acknowledgementPendingResult(finalized) : finalized;
}

async function authenticatedAcknowledgement(context, command) {
  const nowMs = checkedNow(context.now());
  return readTransaction(context.storage, async (tx) => {
    const auth = await trustedAuth(tx, command.authEventId, nowMs);
    authorizeBase(
      auth, ACTIONS.ACKNOWLEDGE, auth, [CREDENTIAL_PURPOSES.ACKNOWLEDGE], nowMs,
    );
    const acknowledgement = checkedAcknowledgement(command.acknowledgement);
    const scope = scopeOf(acknowledgement);
    authorizeScope(auth, scope, 'customer_ack_not_found');
    return acknowledgement;
  });
}

async function acceptSuccessfulAcknowledgement(context, command, expectedAcknowledgement) {
  const nowMs = checkedNow(context.now());
  return mutateWithWitness(context, async (tx, witnessOperationId) => {
    const auth = await trustedAuth(tx, command.authEventId, nowMs);
    authorizeBase(
      auth, ACTIONS.ACKNOWLEDGE, auth, [CREDENTIAL_PURPOSES.ACKNOWLEDGE], nowMs,
    );
    const acknowledgement = checkedAcknowledgement(command.acknowledgement);
    if (!canonicalEqual(acknowledgement, expectedAcknowledgement)
        || acknowledgement.outcome !== 'success') {
      throw lifecycleError('ack_message_conflict');
    }
    const scope = scopeOf(acknowledgement);
    authorizeScope(auth, scope, 'customer_ack_not_found');
    const ackDigest = protocol.payloadDigest(
      acknowledgement, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    );
    const operationDigest = acknowledgementOperationDigest(acknowledgement, ackDigest);
    const priorClaim = await tx.findByAckMessageId(acknowledgement.messageId);
    if (priorClaim) {
      return replayAcknowledgement(
        context, tx, priorClaim, auth, acknowledgement, ackDigest, operationDigest,
      );
    }
    assertAckFresh(acknowledgement, nowMs);
    const target = await tx.findByTargetVersion(
      scope.customerId, scope.deploymentId, acknowledgement.targetVersion,
    );
    if (!target) throw lifecycleError('customer_ack_not_found');
    const restored = await restoreRecord(context, tx, target, scope);
    if (restored.record.entitlementDigest !== acknowledgement.targetDigest) {
      throw lifecycleError('customer_ack_not_found');
    }
    const stage = acknowledgement.lifecycleStage;
    if (transitionReplay(restored.record, stage, operationDigest)) {
      return idempotentCandidate(restored.record);
    }
    const fromStage = stage === 'delivered' ? 'issued' : 'delivered';
    if (restored.record.stage !== fromStage) throw lifecycleError('ack_stage_out_of_order');
    assertAckTiming(acknowledgement, restored.record, nowMs, fromStage + 'At');
    const business = nextBusiness(restored.record, stage, operationDigest, nowMs);
    const receipt = {
      acknowledgement: clone(acknowledgement),
      acceptedAt: business.updatedAt,
      payloadDigest: ackDigest,
    };
    if (stage === 'delivered') business.delivery = receipt;
    else business.customerAck = receipt;
    const acknowledgementClaim = acknowledgementClaimFor(
      context, restored.record, acknowledgement, ackDigest, operationDigest, auth,
    );
    const claims = transitionClaims(auth, restored.record.lifecycleId, operationDigest, {
      acknowledgement: acknowledgementClaim,
    });
    const candidate = updateCandidate(
      context, tx, restored, business, fromStage, stage, auth, claims,
      operationDigest, witnessOperationId,
    );
    const commitUpdate = candidate.commit;
    return {
      ...candidate,
      commit: async () => {
        if (await tx.claimAckMessage(clone(acknowledgementClaim)) !== true) {
          throw lifecycleError('customer_ack_not_found');
        }
        await commitUpdate();
      },
    };
  });
}

async function finalizeAppliedAcknowledgement(context, command, expectedAcknowledgement) {
  const nowMs = checkedNow(context.now());
  return mutateWithWitness(context, async (tx, witnessOperationId) => {
    const auth = await trustedAuth(tx, command.authEventId, nowMs);
    authorizeBase(
      auth, ACTIONS.ACKNOWLEDGE, auth, [CREDENTIAL_PURPOSES.ACKNOWLEDGE], nowMs,
    );
    const acknowledgement = checkedAcknowledgement(command.acknowledgement);
    if (!canonicalEqual(acknowledgement, expectedAcknowledgement)
        || acknowledgement.lifecycleStage !== 'applied'
        || acknowledgement.outcome !== 'success') {
      throw lifecycleError('ack_message_conflict');
    }
    const target = await tx.findByTargetVersion(
      acknowledgement.customerId, acknowledgement.deploymentId,
      acknowledgement.targetVersion,
    );
    if (!target) throw lifecycleError('customer_ack_not_found');
    const restored = await restoreRecord(context, tx, target, acknowledgement);
    authorizeScope(auth, restored.record, 'customer_ack_not_found');
    const operationDigest = digest({
      stage: 'acknowledged', lifecycleId: restored.record.lifecycleId,
      appliedAckDigest: restored.record.customerAck && restored.record.customerAck.payloadDigest,
      messageId: acknowledgement.messageId,
    });
    if (transitionReplay(restored.record, 'acknowledged', operationDigest)) {
      return idempotentCandidate(restored.record);
    }
    if (restored.record.stage !== 'applied'
        || !restored.record.customerAck
        || restored.record.customerAck.acknowledgement.messageId !== acknowledgement.messageId) {
      throw lifecycleError('ack_stage_out_of_order');
    }
    const acceptanceId = checkedGeneratedUuid(context.randomUUID());
    const business = nextBusiness(restored.record, 'acknowledged', operationDigest, nowMs);
    business.acceptance = {
      acceptanceId,
      acceptedAt: business.updatedAt,
      appliedAckDigest: restored.record.customerAck.payloadDigest,
      messageId: acknowledgement.messageId,
    };
    const acceptanceClaim = {
      acceptanceId,
      lifecycleId: restored.record.lifecycleId,
      customerId: restored.record.customerId,
      deploymentId: restored.record.deploymentId,
      appliedAckDigest: restored.record.customerAck.payloadDigest,
      messageId: acknowledgement.messageId,
      operationDigest,
      credentialPurpose: CREDENTIAL_PURPOSES.ACKNOWLEDGE,
      credentialVersion: CREDENTIAL_VERSION,
    };
    const appliedAuthClaim = clone(restored.events.at(-1).claimEvidence.authClaim);
    const reuseAppliedAuth = appliedAuthClaim.authEventId === auth.authEventId;
    const claims = transitionClaims(auth, restored.record.lifecycleId, operationDigest, {
      acceptance: acceptanceClaim,
    });
    if (reuseAppliedAuth) claims.authClaim = appliedAuthClaim;
    const candidate = updateCandidate(
      context, tx, restored, business, 'applied', 'acknowledged', auth, claims,
      operationDigest, witnessOperationId, !reuseAppliedAuth,
    );
    const commitUpdate = candidate.commit;
    return {
      ...candidate,
      commit: async () => {
        if (await tx.claimAcceptanceId(clone(acceptanceClaim)) !== true) {
          throw lifecycleError('acceptance_conflict');
        }
        const advanced = await tx.advanceCurrentEntitlement({
          customerId: restored.record.customerId,
          deploymentId: restored.record.deploymentId,
          expectedPreviousVersion: restored.record.currentState
            ? restored.record.currentState.entitlementVersion : 0,
          lifecycleId: restored.record.lifecycleId,
          nextState: currentStateFromTransition(candidate.record, candidate.descriptor),
        });
        if (advanced !== true) throw lifecycleError('current_state_conflict');
        await commitUpdate();
      },
    };
  });
}

async function recordRejectedAcknowledgement(context, command, expectedAcknowledgement) {
  const nowMs = checkedNow(context.now());
  return readTransaction(context.storage, async (tx) => {
    const auth = await trustedAuth(tx, command.authEventId, nowMs);
    authorizeBase(
      auth, ACTIONS.ACKNOWLEDGE, auth, [CREDENTIAL_PURPOSES.ACKNOWLEDGE], nowMs,
    );
    const acknowledgement = checkedAcknowledgement(command.acknowledgement);
    if (!canonicalEqual(acknowledgement, expectedAcknowledgement)
        || acknowledgement.outcome !== 'rejected') {
      throw lifecycleError('ack_message_conflict');
    }
    authorizeScope(auth, acknowledgement, 'customer_ack_not_found');
    const ackDigest = protocol.payloadDigest(
      acknowledgement, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    );
    const operationDigest = acknowledgementOperationDigest(acknowledgement, ackDigest);
    const priorClaim = await tx.findByAckMessageId(acknowledgement.messageId);
    if (priorClaim) {
      return replayAcknowledgement(
        context, tx, priorClaim, auth, acknowledgement, ackDigest, operationDigest,
      );
    }
    assertAckFresh(acknowledgement, nowMs);
    const target = await tx.findByTargetVersion(
      acknowledgement.customerId, acknowledgement.deploymentId,
      acknowledgement.targetVersion,
    );
    if (!target) throw lifecycleError('customer_ack_not_found');
    const restored = await restoreRecord(context, tx, target, acknowledgement);
    if (restored.record.entitlementDigest !== acknowledgement.targetDigest) {
      throw lifecycleError('customer_ack_not_found');
    }
    const claim = acknowledgementClaimFor(
      context, restored.record, acknowledgement, ackDigest, operationDigest, auth,
    );
    const authClaim = authClaimFor(
      authorityEvidence(auth), restored.record, restored.record.lifecycleId, operationDigest,
    );
    await claimAuth(tx, authClaim);
    if (await tx.claimAckMessage(clone(claim)) !== true) {
      throw lifecycleError('ack_message_conflict');
    }
    return rejectionResult(claim, false);
  }, true);
}

async function readLifecycle(context, queryValue) {
  const query = checkedReadCommand(queryValue);
  const nowMs = checkedNow(context.now());
  return readTransaction(context.storage, async (tx) => {
    const auth = await trustedAuth(tx, query.authEventId, nowMs);
    authorizeBase(auth, ACTIONS.READ, auth, [CREDENTIAL_PURPOSES.READ], nowMs);
    const restored = await loadRecord(context, tx, query.lifecycleId, auth);
    authorizeScope(auth, restored.record, 'lifecycle_not_found');
    return portalRecord(restored.record);
  });
}

async function replayAcknowledgement(
  context, tx, claimValue, auth, acknowledgement, ackDigest, operationDigest,
) {
  let claim;
  try { claim = checkedAckClaim(context, claimValue); }
  catch { throw lifecycleError('ack_message_conflict'); }
  assertAcknowledgementClaimMatch(
    claim, auth, acknowledgement, ackDigest, operationDigest,
  );
  const restored = await loadRecord(context, tx, claim.lifecycleId, auth);
  if (claim.outcome === 'rejected') {
    const storedAuthClaim = checkedAuthClaim(await tx.getAuthClaim(claim.authEventId));
    if (storedAuthClaim.lifecycleId !== claim.lifecycleId
        || storedAuthClaim.operationDigest !== claim.operationDigest
        || storedAuthClaim.authEventId !== claim.authEventId
        || storedAuthClaim.authorityDigest !== claim.authorityDigest) {
      throw lifecycleError('ack_message_conflict');
    }
    return rejectionResult(claim, true);
  }
  if (!transitionReplay(restored.record, claim.lifecycleStage, operationDigest)) {
    throw lifecycleError('ack_message_conflict');
  }
  if (restored.record.stage === 'acknowledged') {
    await requireCurrentProjectionDescendant(context, tx, restored.record);
  }
  return idempotentCandidate(restored.record);
}

function assertAcknowledgementClaimMatch(
  claim, auth, acknowledgement, ackDigest, operationDigest,
) {
  if (claim.customerId !== auth.customerId || claim.deploymentId !== auth.deploymentId) {
    throw lifecycleError('customer_ack_not_found');
  }
  if (claim.messageId !== acknowledgement.messageId
      || claim.targetVersion !== acknowledgement.targetVersion
      || claim.targetDigest !== acknowledgement.targetDigest
      || claim.payloadDigest !== ackDigest
      || claim.operationDigest !== operationDigest
      || claim.lifecycleStage !== acknowledgement.lifecycleStage
      || claim.outcome !== acknowledgement.outcome
      || claim.reasonCode !== acknowledgement.reasonCode) {
    throw lifecycleError('ack_message_conflict');
  }
}

function acknowledgementOperationDigest(acknowledgement, payloadDigest) {
  return digest({
    stage: acknowledgement.lifecycleStage,
    outcome: acknowledgement.outcome,
    reasonCode: acknowledgement.reasonCode,
    payloadDigest,
    targetVersion: acknowledgement.targetVersion,
    targetDigest: acknowledgement.targetDigest,
  });
}

function acknowledgementClaimFor(
  context, record, acknowledgement, payloadDigest, operationDigest, auth,
) {
  const authority = authorityEvidence(auth);
  const base = {
    authEventId: auth.authEventId,
    authorityDigest: digest(authority),
    messageId: acknowledgement.messageId,
    lifecycleId: record.lifecycleId,
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    targetVersion: record.entitlementVersion,
    targetDigest: record.entitlementDigest,
    lifecycleStage: acknowledgement.lifecycleStage,
    outcome: acknowledgement.outcome,
    reasonCode: acknowledgement.reasonCode,
    payloadDigest,
    operationDigest,
    credentialPurpose: auth.credentialPurpose,
    credentialVersion: auth.credentialVersion,
  };
  const macKeyId = context.keyring.currentKeyId;
  const withKey = { ...base, macKeyId };
  return {
    ...withKey,
    claimMac: keyringHmac(context.keyring, macKeyId, ACK_CLAIM_DOMAIN, withKey),
  };
}

function requestedBusiness(
  lifecycleId, command, entitlement, entitlementDigest, currentState,
  targetConfirmation, operationDigest, nowMs,
) {
  const timestamp = canonicalTime(nowMs);
  return {
    schemaVersion: SCHEMA_VERSION,
    lifecycleId,
    customerId: entitlement.customerId,
    deploymentId: entitlement.deploymentId,
    idempotencyKey: command.idempotencyKey,
    revision: 1,
    stage: 'requested',
    entitlementVersion: entitlement.entitlementVersion,
    entitlementDigest,
    currentState: clone(currentState),
    proposedState: proposedStateFor(entitlement, entitlementDigest),
    targetConfirmation: clone(targetConfirmation),
    issuance: null,
    delivery: null,
    customerAck: null,
    acceptance: null,
    operationDigests: {
      requested: operationDigest,
      issued: null,
      delivered: null,
      applied: null,
      acknowledged: null,
    },
    timestamps: {
      requestedAt: timestamp,
      issuedAt: null,
      deliveredAt: null,
      appliedAt: null,
      acknowledgedAt: null,
    },
    updatedAt: timestamp,
  };
}

function nextBusiness(record, stage, operationDigest, nowMs) {
  if (nowMs < Date.parse(record.updatedAt)) throw lifecycleError('clock_rollback');
  const business = businessRecord(record);
  business.stage = stage;
  business.revision += 1;
  business.updatedAt = canonicalTime(nowMs);
  business.timestamps[stage + 'At'] = business.updatedAt;
  business.operationDigests[stage] = operationDigest;
  return business;
}

function updateCandidate(
  context, tx, restored, business, fromStage, toStage, auth, claims,
  operationDigest, witnessOperationId, claimAuthEvent = true,
) {
  const sealed = sealTransition(
    context, business, restored.record, fromStage, toStage, auth, claims,
    operationDigest, witnessOperationId,
  );
  const candidate = transitionCandidate(
    context, sealed, restored.witness.descriptorDigest, witnessOperationId,
  );
  return {
    ...candidate,
    commit: async () => {
      if (claimAuthEvent) await claimAuth(tx, claims.authClaim);
      const updated = await tx.updateLifecycle(
        restored.record.lifecycleId,
        restored.record.revision,
        clone(sealed.record),
        clone(sealed.event),
        clone(candidate.pending),
      );
      if (updated !== true) throw lifecycleError('version_conflict');
    },
  };
}

function transitionCandidate(context, sealed, previousWitnessDigest, witnessOperationId) {
  const descriptor = descriptorFor(
    sealed.record, previousWitnessDigest, witnessOperationId,
  );
  return {
    kind: 'transition',
    record: sealed.record,
    descriptor,
    pending: sealPending(context, descriptor),
  };
}

function idempotentCandidate(record) {
  return { kind: 'idempotent', result: operationResult(record, true) };
}

function sealTransition(
  context, businessValue, previous, fromStage, toStage, auth, claimEvidence,
  operationDigest, witnessOperationId,
) {
  const business = clone(businessValue);
  const stateDigest = digest(business);
  const authority = authorityEvidence(auth);
  const authorityDigest = digest(authority);
  const claimDigest = digest(claimEvidence);
  const macKeyId = context.keyring.currentKeyId;
  const eventBase = {
    schemaVersion: SCHEMA_VERSION,
    eventId: checkedGeneratedUuid(context.randomUUID()),
    witnessOperationId,
    lifecycleId: business.lifecycleId,
    customerId: business.customerId,
    deploymentId: business.deploymentId,
    revision: business.revision,
    fromStage,
    toStage,
    entitlementVersion: business.entitlementVersion,
    entitlementDigest: business.entitlementDigest,
    stateDigest,
    previousEventDigest: previous ? previous.eventHead : null,
    recordedAt: business.updatedAt,
    authority,
    authorityDigest,
    operationDigest,
    claimEvidence: clone(claimEvidence),
    claimDigest,
    macKeyId,
  };
  const eventDigest = digest(eventBase);
  const eventWithDigest = { ...eventBase, eventDigest };
  const event = {
    ...eventWithDigest,
    eventMac: keyringHmac(context.keyring, macKeyId, EVENT_DOMAIN, eventWithDigest),
  };
  const recordWithoutMac = {
    ...business,
    stateDigest,
    eventCount: previous ? previous.eventCount + 1 : 1,
    eventHead: eventDigest,
    tailAuthorityDigest: authorityDigest,
    tailOperationDigest: operationDigest,
    tailClaimDigest: claimDigest,
    witnessOperationId,
    macKeyId,
  };
  const record = {
    ...recordWithoutMac,
    recordMac: keyringHmac(context.keyring, macKeyId, RECORD_DOMAIN, recordWithoutMac),
  };
  return { record, event };
}

function descriptorFor(record, previousWitnessDigest, operationId) {
  return {
    schemaVersion: 1,
    operationId,
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    lifecycleId: record.lifecycleId,
    entitlementVersion: record.entitlementVersion,
    stage: record.stage,
    revision: record.revision,
    previousWitnessDigest,
    checkpoint: checkpointFor(record),
    preparedAt: record.updatedAt,
  };
}

function sealPending(context, descriptor) {
  const macKeyId = context.keyring.currentKeyId;
  const value = {
    schemaVersion: 1,
    descriptor: clone(descriptor),
    descriptorDigest: digest(descriptor),
    macKeyId,
  };
  return {
    ...value,
    pendingMac: keyringHmac(context.keyring, macKeyId, PENDING_DOMAIN, value),
  };
}

function checkpointFor(record) {
  return {
    schemaVersion: SCHEMA_VERSION,
    lifecycleId: record.lifecycleId,
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    entitlementVersion: record.entitlementVersion,
    revision: record.revision,
    stage: record.stage,
    stateDigest: record.stateDigest,
    eventCount: record.eventCount,
    eventHead: record.eventHead,
    tailAuthorityDigest: record.tailAuthorityDigest,
    tailOperationDigest: record.tailOperationDigest,
    tailClaimDigest: record.tailClaimDigest,
    witnessOperationId: record.witnessOperationId,
    macKeyId: record.macKeyId,
    recordMac: record.recordMac,
    updatedAt: record.updatedAt,
  };
}

function transitionClaims(auth, lifecycleId, operationDigest, extras = {}) {
  const authority = authorityEvidence(auth);
  const authClaim = authClaimFor(authority, auth, lifecycleId, operationDigest);
  const approvalAuthority = extras.approvalAuth || null;
  const withOperation = (value) => value ? { ...clone(value), operationDigest } : null;
  return {
    authClaim,
    approvalAuthClaim: approvalAuthority
      ? authClaimFor(approvalAuthority, auth, lifecycleId, operationDigest)
      : null,
    targetConfirmationClaim: withOperation(extras.targetConfirmation || null),
    acknowledgementClaim: withOperation(extras.acknowledgement || null),
    acceptanceClaim: withOperation(extras.acceptance || null),
  };
}

function authClaimFor(authority, scope, lifecycleId, operationDigest) {
  return {
    authEventId: authority.authEventId,
    action: authority.action,
    credentialPurpose: authority.credentialPurpose,
    credentialVersion: authority.credentialVersion,
    principalRef: authority.principalRef,
    customerId: scope.customerId,
    deploymentId: scope.deploymentId,
    lifecycleId,
    operationDigest,
    authority: clone(authority),
    authorityDigest: digest(authority),
  };
}

function targetConfirmationClaim(confirmation, lifecycleId) {
  return confirmation ? { ...clone(confirmation), lifecycleId } : null;
}

async function claimAuth(tx, claim) {
  if (await tx.claimAuthEvent(clone(claim)) !== true) {
    throw lifecycleError('auth_event_reused');
  }
}

function authorityEvidence(auth) {
  return {
    authEventId: auth.authEventId,
    action: auth.action,
    role: auth.role,
    principalRef: auth.principalRef,
    authenticatedAt: auth.authenticatedAt,
    stepUpAt: auth.stepUpAt,
    credentialPurpose: auth.credentialPurpose,
    credentialVersion: auth.credentialVersion,
  };
}

async function trustedAuth(tx, authEventId, nowMs) {
  const value = await tx.lockAuthEvent(authEventId);
  const auth = boundedSnapshot(value, 8 * 1024, 4, 'auth_event_invalid');
  assertObjectKeys(auth, [
    'action', 'authEventId', 'authenticatedAt', 'credentialPurpose',
    'credentialVersion', 'customerId', 'deploymentId', 'principalRef', 'role',
    'stepUpAt',
  ], 'auth_event_invalid');
  const authenticatedMs = checkedIso(auth.authenticatedAt, 'auth_event_invalid');
  const stepUpMs = auth.stepUpAt === null
    ? null : checkedIso(auth.stepUpAt, 'auth_event_invalid');
  if (auth.authEventId !== authEventId
      || !UUID_RE.test(String(auth.authEventId || ''))
      || !Object.values(ACTIONS).includes(auth.action)
      || ![...MANUAL_ACTOR_ROLES, ...SERVICE_ACTOR_ROLES, CUSTOMER_ACTOR_ROLE].includes(auth.role)
      || !SHA256_RE.test(String(auth.principalRef || ''))
      || !CUSTOMER_ID_RE.test(String(auth.customerId || ''))
      || !isDeploymentId(auth.deploymentId)
      || !SAFE_SLUG_RE.test(String(auth.credentialPurpose || ''))
      || auth.credentialVersion !== CREDENTIAL_VERSION
      || authenticatedMs > nowMs + MAX_FUTURE_SKEW_MS
      || nowMs - authenticatedMs > MAX_AUTH_EVENT_AGE_MS
      || (stepUpMs !== null && stepUpMs > authenticatedMs)) {
    throw lifecycleError('auth_event_invalid');
  }
  return auth;
}

function authorizeBase(auth, action, scope, purposes, nowMs) {
  if (auth.action !== action || !ACTION_ROLES[action].has(auth.role)
      || !purposes.includes(auth.credentialPurpose)
      || auth.credentialVersion !== CREDENTIAL_VERSION) {
    throw lifecycleError('authorization_denied');
  }
  authorizeScope(auth, scope, 'scope_mismatch');
  if (auth.stepUpAt !== null
      && Date.parse(auth.stepUpAt) > nowMs + MAX_FUTURE_SKEW_MS) {
    throw lifecycleError('auth_event_invalid');
  }
}

function authorizeScope(auth, scope, code) {
  if (auth.customerId !== scope.customerId || auth.deploymentId !== scope.deploymentId) {
    throw lifecycleError(code);
  }
}

function authorizeStoredRequestMode(auth, record, nowMs) {
  if (record.proposedState.reasonCode === 'emergency_revoke') {
    requireBreakGlass(auth, nowMs);
  } else if (record.targetConfirmation) {
    requireDualControlActor(auth, nowMs);
  } else if (!SERVICE_ACTOR_ROLES.includes(auth.role)
      || auth.credentialPurpose !== CREDENTIAL_PURPOSES.REQUEST) {
    throw lifecycleError('automated_authority_invalid');
  }
}

function authorizeNewRequestMode(auth, entitlement, dualControl, confirmation, nowMs) {
  if (entitlement.reasonCode === 'emergency_revoke') {
    if (confirmation) throw lifecycleError('break_glass_confirmation_forbidden');
    requireBreakGlass(auth, nowMs);
    return;
  }
  if (dualControl) {
    if (!confirmation) throw lifecycleError('target_confirmation_required');
    requireDualControlActor(auth, nowMs);
    return;
  }
  if (confirmation || !SERVICE_ACTOR_ROLES.includes(auth.role)
      || auth.credentialPurpose !== CREDENTIAL_PURPOSES.REQUEST) {
    throw lifecycleError('automated_authority_invalid');
  }
}

function requireBreakGlass(auth, nowMs) {
  if (!['vendor_owner', 'vendor_security_admin'].includes(auth.role)
      || auth.credentialPurpose !== CREDENTIAL_PURPOSES.BREAK_GLASS) {
    throw lifecycleError('break_glass_authority_required');
  }
  requireFreshStepUp(auth, nowMs);
}

function requireDualControlActor(auth, nowMs) {
  if (!MANUAL_ACTOR_ROLES.includes(auth.role)
      || auth.credentialPurpose !== CREDENTIAL_PURPOSES.REQUEST) {
    throw lifecycleError('dual_control_authority_required');
  }
  requireFreshStepUp(auth, nowMs);
}

function requireFreshStepUp(auth, nowMs) {
  const stepUpMs = Date.parse(auth.stepUpAt);
  if (!Number.isFinite(stepUpMs) || stepUpMs > nowMs + MAX_FUTURE_SKEW_MS
      || nowMs - stepUpMs > MAX_STEP_UP_AGE_MS) throw lifecycleError('step_up_required');
}

function requiresDualControl(entitlement, currentState) {
  if (entitlement.reasonCode === 'emergency_revoke') return false;
  return MANUAL_REASON_CODES.includes(entitlement.reasonCode)
    || Boolean(currentState && (currentState.plan !== entitlement.plan
      || currentState.seats !== entitlement.seats));
}

function requireRestrictionPrecedence(entitlement, currentState) {
  if (!currentState || currentState.status === 'active') return;
  if (entitlement.status === 'active') {
    if (entitlement.reasonCode !== 'manual_restore') {
      throw lifecycleError('explicit_restore_required');
    }
    return;
  }
  if (entitlement.status === currentState.status
      || (currentState.status === 'paused' && entitlement.status === 'revoked')) return;
  throw lifecycleError('restriction_precedence_violation');
}

async function trustedTargetConfirmation(
  context, tx, confirmationId, entitlement, entitlementDigest, auth, required, nowMs,
) {
  if (!required) {
    if (confirmationId !== null) throw lifecycleError('target_confirmation_forbidden');
    return null;
  }
  if (!confirmationId) throw lifecycleError('target_confirmation_required');
  const raw = await tx.lockTargetConfirmation(confirmationId);
  const value = boundedSnapshot(raw, 16 * 1024, 5, 'target_confirmation_required');
  assertObjectKeys(value, [
    'approverAuthEventId', 'confirmationRef', 'confirmedAt', 'customerId',
    'deploymentId', 'entitlementDigest', 'entitlementVersion', 'ownerAttestationId',
    'purpose', 'targetConfirmationId',
  ], 'target_confirmation_required');
  const confirmedMs = checkedIso(value.confirmedAt, 'target_confirmation_required');
  if (value.targetConfirmationId !== confirmationId
      || !UUID_RE.test(String(value.targetConfirmationId || ''))
      || !UUID_RE.test(String(value.approverAuthEventId || ''))
      || !UUID_RE.test(String(value.ownerAttestationId || ''))
      || !SHA256_RE.test(String(value.confirmationRef || ''))
      || value.purpose !== TARGET_CONFIRMATION_PURPOSE
      || confirmedMs > nowMs + MAX_FUTURE_SKEW_MS
      || nowMs - confirmedMs > MAX_TARGET_CONFIRMATION_AGE_MS
      || value.customerId !== entitlement.customerId
      || value.deploymentId !== entitlement.deploymentId
      || value.entitlementVersion !== entitlement.entitlementVersion
      || value.entitlementDigest !== entitlementDigest) {
    throw lifecycleError('target_confirmation_required');
  }
  let approver;
  try {
    approver = await trustedAuth(tx, value.approverAuthEventId, nowMs);
    authorizeBase(
      approver, ACTIONS.TARGET_CONFIRM, approver,
      [CREDENTIAL_PURPOSES.TARGET_CONFIRMATION], nowMs,
    );
    requireFreshStepUp(approver, nowMs);
  } catch {
    throw lifecycleError('target_confirmation_required');
  }
  if (approver.principalRef === auth.principalRef
      || approver.customerId !== entitlement.customerId
      || approver.deploymentId !== entitlement.deploymentId
      || Date.parse(approver.authenticatedAt) > confirmedMs) {
    throw lifecycleError('target_confirmation_required');
  }
  const ownerAttestation = await trustedOwnerAttestation(
    context, tx, value, entitlement, entitlementDigest, approver, confirmedMs, nowMs,
  );
  return deepFreeze({
    ...value,
    approverAuthority: authorityEvidence(approver),
    ownerAttestation,
  });
}

async function trustedOwnerAttestation(
  context, tx, confirmation, entitlement, entitlementDigest, approver, confirmedMs, nowMs,
) {
  const raw = await tx.lockOwnerAttestation(confirmation.ownerAttestationId);
  const value = checkedOwnerAttestation(
    boundedSnapshot(raw, 16 * 1024, 5, 'target_confirmation_required'),
    'target_confirmation_required',
  );
  const issuedMs = Date.parse(value.issuedAt);
  const expiresMs = Date.parse(value.expiresAt);
  if (value.attestationId !== confirmation.ownerAttestationId
      || value.targetConfirmationId !== confirmation.targetConfirmationId
      || value.approverAuthEventId !== approver.authEventId
      || value.customerId !== entitlement.customerId
      || value.deploymentId !== entitlement.deploymentId
      || value.entitlementVersion !== entitlement.entitlementVersion
      || value.entitlementDigest !== entitlementDigest
      || issuedMs > confirmedMs || expiresMs < confirmedMs
      || issuedMs > nowMs + MAX_FUTURE_SKEW_MS
      || nowMs - issuedMs > MAX_TARGET_CONFIRMATION_AGE_MS
      || expiresMs < nowMs) {
    throw lifecycleError('target_confirmation_required');
  }
  verifyOwnerAttestationProof(context, value, 'target_confirmation_required');
  await verifyOwnerHistory(context, value, 'target_confirmation_required');
  return value;
}

async function trustedCurrentState(context, tx, entitlement) {
  const raw = await tx.lockCurrentEntitlement(
    entitlement.customerId, entitlement.deploymentId,
  );
  const scopeWitnessValue = await context.witness.readScope(
    entitlement.customerId, entitlement.deploymentId,
  );
  if (entitlement.previousVersion === 0) {
    if (raw !== null || scopeWitnessValue !== null) throw lifecycleError('current_state_invalid');
    return null;
  }
  const projection = await trustedCurrentProjection(
    context, tx, scopeOf(entitlement), raw, scopeWitnessValue,
  );
  if (projection.state.entitlementVersion !== entitlement.previousVersion) {
    throw lifecycleError('current_state_invalid');
  }
  return projection.state;
}

async function trustedCurrentProjection(
  context, tx, scope, rawValue = undefined, scopeWitnessValue = undefined,
) {
  const raw = rawValue === undefined
    ? await tx.lockCurrentEntitlement(scope.customerId, scope.deploymentId) : rawValue;
  const witnessValue = scopeWitnessValue === undefined
    ? await context.witness.readScope(scope.customerId, scope.deploymentId) : scopeWitnessValue;
  const state = checkedCurrentStateShape(raw);
  if (state.customerId !== scope.customerId || state.deploymentId !== scope.deploymentId
      || !witnessValue) throw lifecycleError('current_state_invalid');
  const scopeWitness = await checkedWitnessEnvelope(context, witnessValue, null, 'final');
  const restored = await loadRecord(context, tx, state.provenance.lifecycleId, state);
  assertProjectionRecordBinding(state, restored);
  if (scopeWitness.descriptorDigest !== restored.witness.descriptorDigest
      || scopeWitness.descriptor.stage !== 'acknowledged') {
    throw lifecycleError('current_state_invalid');
  }
  return { state, restored };
}

function assertProjectionRecordBinding(state, restored) {
  if (restored.record.stage !== 'acknowledged'
      || state.provenance.witnessDescriptorDigest !== restored.witness.descriptorDigest
      || state.provenance.revision !== restored.record.revision
      || state.provenance.eventHead !== restored.record.eventHead
      || state.provenance.stateDigest !== restored.record.stateDigest
      || state.provenance.recordMac !== restored.record.recordMac
      || state.provenance.macKeyId !== restored.record.macKeyId
      || state.provenance.acceptanceId !== restored.record.acceptance.acceptanceId
      || !currentFieldsMatchRecord(state, restored.record)) {
    throw lifecycleError('current_state_invalid');
  }
}

async function requireCurrentProjectionDescendant(context, tx, targetRecord) {
  const projection = await trustedCurrentProjection(context, tx, targetRecord);
  if (projection.state.entitlementVersion < targetRecord.entitlementVersion) {
    throw lifecycleError('current_state_invalid');
  }
  let cursor = projection.restored;
  for (let depth = 0; cursor.record.entitlementVersion > targetRecord.entitlementVersion;
    depth += 1) {
    if (depth >= 1_000 || cursor.record.currentState === null) {
      throw lifecycleError('current_state_invalid');
    }
    const previous = checkedCurrentStateShape(cursor.record.currentState);
    const prior = await loadRecord(
      context, tx, previous.provenance.lifecycleId, previous,
    );
    assertProjectionRecordBinding(previous, prior);
    if (previous.entitlementVersion !== cursor.record.proposedState.previousVersion
        || previous.entitlementVersion >= cursor.record.entitlementVersion) {
      throw lifecycleError('current_state_invalid');
    }
    cursor = prior;
  }
  if (cursor.record.entitlementVersion !== targetRecord.entitlementVersion
      || cursor.record.lifecycleId !== targetRecord.lifecycleId
      || cursor.record.entitlementDigest !== targetRecord.entitlementDigest) {
    throw lifecycleError('current_state_invalid');
  }
}

function checkedCurrentStateShape(value) {
  const state = boundedSnapshot(value, 32 * 1024, 7, 'current_state_invalid');
  assertObjectKeys(state, [
    'customerId', 'deploymentId', 'entitlementDigest', 'entitlementVersion',
    'features', 'plan', 'provenance', 'reasonCode', 'seats', 'status',
  ], 'current_state_invalid');
  assertObjectKeys(state.provenance, [
    'acceptanceId', 'eventHead', 'lifecycleId', 'macKeyId', 'recordMac',
    'revision', 'stateDigest', 'witnessDescriptorDigest',
  ], 'current_state_invalid');
  if (!CUSTOMER_ID_RE.test(String(state.customerId || ''))
      || !isDeploymentId(state.deploymentId)
      || !Number.isSafeInteger(state.entitlementVersion) || state.entitlementVersion < 1
      || !SHA256_RE.test(String(state.entitlementDigest || ''))
      || !['active', 'paused', 'revoked'].includes(state.status)
      || !['standard', 'enterprise'].includes(state.plan)
      || !Number.isSafeInteger(state.seats) || state.seats < 0 || state.seats > 1_000_000
      || !validFeatures(state.features)
      || !validReason(state.status, state.reasonCode)
      || !UUID_RE.test(String(state.provenance.lifecycleId || ''))
      || !UUID_RE.test(String(state.provenance.acceptanceId || ''))
      || !Number.isSafeInteger(state.provenance.revision) || state.provenance.revision < 5
      || !validPurposeKeyId(state.provenance.macKeyId, KEY_PURPOSES.LIFECYCLE)
      || ![state.provenance.eventHead, state.provenance.stateDigest,
        state.provenance.recordMac, state.provenance.witnessDescriptorDigest]
        .every((item) => SHA256_RE.test(String(item || '')))) {
    throw lifecycleError('current_state_invalid');
  }
  return state;
}

function currentFieldsMatchRecord(state, record) {
  return state.customerId === record.customerId
    && state.deploymentId === record.deploymentId
    && state.entitlementVersion === record.entitlementVersion
    && state.entitlementDigest === record.entitlementDigest
    && state.status === record.proposedState.status
    && state.plan === record.proposedState.plan
    && state.seats === record.proposedState.seats
    && state.reasonCode === record.proposedState.reasonCode
    && canonicalEqual(state.features, record.proposedState.features);
}

function currentStateFromTransition(record, descriptor) {
  return {
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    status: record.proposedState.status,
    plan: record.proposedState.plan,
    seats: record.proposedState.seats,
    features: [...record.proposedState.features],
    reasonCode: record.proposedState.reasonCode,
    entitlementVersion: record.entitlementVersion,
    entitlementDigest: record.entitlementDigest,
    provenance: {
      lifecycleId: record.lifecycleId,
      revision: record.revision,
      eventHead: record.eventHead,
      stateDigest: record.stateDigest,
      recordMac: record.recordMac,
      macKeyId: record.macKeyId,
      acceptanceId: record.acceptance.acceptanceId,
      witnessDescriptorDigest: digest(descriptor),
    },
  };
}

function checkedEntitlement(value) {
  try {
    const snapshot = boundedSnapshot(
      value, protocol.MAX_CHANNEL_BYTES[protocol.CHANNEL_KINDS.ENTITLEMENT],
      8, 'request_invalid',
    );
    const entitlement = protocol.assertChannel(
      snapshot, protocol.CHANNEL_KINDS.ENTITLEMENT,
    );
    checkedIso(entitlement.issuedAt, 'request_invalid');
    checkedIso(entitlement.expiresAt, 'request_invalid');
    if (entitlement.fallbackUntil !== null) {
      checkedIso(entitlement.fallbackUntil, 'request_invalid');
    }
    return entitlement;
  } catch {
    throw lifecycleError('request_invalid');
  }
}

function checkedAcknowledgement(value) {
  try {
    const snapshot = boundedSnapshot(
      value, protocol.MAX_CHANNEL_BYTES[protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT],
      8, 'customer_ack_not_found',
    );
    const acknowledgement = protocol.assertChannel(
      snapshot, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    );
    checkedIso(acknowledgement.recordedAt, 'customer_ack_not_found');
    if (acknowledgement.targetKind !== protocol.CHANNEL_KINDS.ENTITLEMENT) {
      throw lifecycleError('customer_ack_not_found');
    }
    return acknowledgement;
  } catch {
    throw lifecycleError('customer_ack_not_found');
  }
}

function assertAckFresh(acknowledgement, nowMs) {
  const recordedMs = Date.parse(acknowledgement.recordedAt);
  if (recordedMs > nowMs + MAX_FUTURE_SKEW_MS
      || nowMs - recordedMs > MAX_ACK_AGE_MS) {
    throw lifecycleError('customer_ack_not_found');
  }
}

function assertAckTiming(acknowledgement, record, nowMs, minimumTimestamp) {
  const recordedMs = Date.parse(acknowledgement.recordedAt);
  if (recordedMs < Date.parse(record.timestamps[minimumTimestamp])
      || recordedMs > nowMs + MAX_FUTURE_SKEW_MS
      || nowMs - recordedMs > MAX_ACK_AGE_MS) {
    throw lifecycleError('customer_ack_not_found');
  }
}

function checkedSignedArtifact(value) {
  return boundedSnapshot(
    value,
    protocol.MAX_CHANNEL_BYTES[protocol.CHANNEL_KINDS.ENTITLEMENT] + 1024,
    10,
    'invalid_schema',
  );
}

function verifiedEntitlementArtifact(context, artifact) {
  const offline = context.authorityRegistry.get(AUTHORITY_PURPOSES.OFFLINE_LICENSE);
  const forbiddenPublicKeyFingerprints = context.authorityRegistry.allRecords()
    .filter((record) => record.identityType === 'ed25519_public'
      && record.purpose !== AUTHORITY_PURPOSES.ENTITLEMENT)
    .map((record) => record.identity);
  const keyOptions = {
    purpose: KEY_PURPOSES.ENTITLEMENT,
    strictPurpose: true,
    authorityRegistry: context.authorityRegistry,
    offlineKeyFingerprint: offline.identity,
    forbiddenPublicKeyFingerprints,
  };
  const publicKeys = normalizePublicKeys(
    context.authorityRegistry.publicKeys(AUTHORITY_PURPOSES.ENTITLEMENT), keyOptions,
  );
  const verified = verifySignedArtifact(
    artifact, publicKeys, protocol.CHANNEL_KINDS.ENTITLEMENT, keyOptions,
  );
  const verificationKey = publicKeys.get(verified.keyId);
  return Object.freeze({
    ...verified,
    verificationKeyFingerprint: keyFingerprint(verificationKey),
    verificationKeySpki: verificationKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  });
}

function assertArtifactMatchesRecord(verified, record) {
  if (verified.payload.customerId !== record.customerId
      || verified.payload.deploymentId !== record.deploymentId) {
    throw lifecycleError('scope_mismatch');
  }
  if (verified.payload.entitlementVersion !== record.entitlementVersion
      || verified.payloadDigest !== record.entitlementDigest) {
    throw lifecycleError('entitlement_mismatch');
  }
}

function requestOperationDigest(command, entitlementDigest) {
  return digest({
    stage: 'requested',
    idempotencyKey: command.idempotencyKey,
    entitlementDigest,
    targetConfirmationId: command.targetConfirmationId,
  });
}

function transitionReplay(record, stage, operationDigest) {
  if (STAGES.indexOf(record.stage) < STAGES.indexOf(stage)) return false;
  if (record.operationDigests[stage] === operationDigest) return true;
  throw lifecycleError('transition_conflict');
}

function assertRevisionAndStage(record, expectedRevision, expectedStage) {
  if (record.revision !== expectedRevision) throw lifecycleError('version_conflict');
  if (record.stage !== expectedStage) throw lifecycleError('transition_invalid');
}

async function loadRecord(context, tx, lifecycleId, scope) {
  if (!UUID_RE.test(String(lifecycleId || ''))) throw lifecycleError('lifecycle_not_found');
  const stored = await tx.get(lifecycleId);
  if (!stored) throw lifecycleError('lifecycle_not_found');
  return restoreRecord(context, tx, stored, scope);
}

async function restoreRecord(context, tx, storedValue, scope, options = {}) {
  const record = checkedStoredRecord(context, storedValue);
  if (scope && (record.customerId !== scope.customerId
      || record.deploymentId !== scope.deploymentId)) {
    throw lifecycleError('lifecycle_not_found');
  }
  const eventValues = boundedSnapshot(
    await tx.listEvents(record.lifecycleId), MAX_EVENT_BYTES * 8, MAX_DEPTH,
    'lifecycle_integrity_invalid',
  );
  if (!Array.isArray(eventValues) || eventValues.length !== record.eventCount
      || eventValues.length !== record.revision || eventValues.length > STAGES.length) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  const events = [];
  let previousEvent = null;
  let previousWitness = null;
  for (let index = 0; index < eventValues.length; index += 1) {
    const restored = await restoreEvent(
      context, tx, eventValues[index], record, index, previousEvent, previousWitness,
      options.allowPreparedTail === true && index === eventValues.length - 1,
    );
    events.push(restored.event);
    previousEvent = restored.event;
    previousWitness = restored.witness;
  }
  const tail = events.at(-1);
  if (!tail || tail.eventDigest !== record.eventHead
      || tail.stateDigest !== record.stateDigest
      || tail.authorityDigest !== record.tailAuthorityDigest
      || tail.operationDigest !== record.tailOperationDigest
      || tail.claimDigest !== record.tailClaimDigest
      || tail.witnessOperationId !== record.witnessOperationId) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  const exactDescriptor = descriptorFor(
    record,
    previousWitness.descriptor.previousWitnessDigest,
    record.witnessOperationId,
  );
  if (!previousWitness || !canonicalEqual(previousWitness.descriptor, exactDescriptor)) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  if (options.descriptor && !canonicalEqual(previousWitness.descriptor, options.descriptor)) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  return deepFreeze({ record, events, witness: previousWitness });
}

async function restoreEvent(
  context, tx, eventValue, record, index, previousEvent, previousWitness,
  allowPrepared,
) {
  const event = checkedStoredEvent(context, eventValue);
  const toStage = STAGES[index];
  const fromStage = index === 0 ? null : STAGES[index - 1];
  if (event.lifecycleId !== record.lifecycleId
      || event.customerId !== record.customerId
      || event.deploymentId !== record.deploymentId
      || event.entitlementVersion !== record.entitlementVersion
      || event.entitlementDigest !== record.entitlementDigest
      || event.revision !== index + 1
      || event.fromStage !== fromStage
      || event.toStage !== toStage
      || event.previousEventDigest !== (previousEvent ? previousEvent.eventDigest : null)
      || event.operationDigest !== record.operationDigests[toStage]
      || event.recordedAt !== record.timestamps[toStage + 'At']) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  await verifyArchivedClaims(context, tx, event, record);
  const witnessValue = await context.witness.readOperation(event.witnessOperationId);
  if (!witnessValue) throw lifecycleError('lifecycle_integrity_invalid');
  const witness = await checkedWitnessEnvelope(
    context, witnessValue, null, allowPrepared ? null : 'final',
  );
  if (!allowPrepared && witness.state !== 'final') {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  const checkpoint = witness.descriptor.checkpoint;
  const expectedPrevious = previousWitness
    ? previousWitness.descriptorDigest
    : record.currentState && record.currentState.provenance.witnessDescriptorDigest;
  if (witness.descriptor.customerId !== record.customerId
      || witness.descriptor.deploymentId !== record.deploymentId
      || witness.descriptor.lifecycleId !== record.lifecycleId
      || witness.descriptor.entitlementVersion !== record.entitlementVersion
      || witness.descriptor.stage !== toStage
      || witness.descriptor.revision !== index + 1
      || witness.descriptor.previousWitnessDigest !== (expectedPrevious || null)
      || checkpoint.eventHead !== event.eventDigest
      || checkpoint.stateDigest !== event.stateDigest
      || checkpoint.tailAuthorityDigest !== event.authorityDigest
      || checkpoint.tailOperationDigest !== event.operationDigest
      || checkpoint.tailClaimDigest !== event.claimDigest
      || checkpoint.witnessOperationId !== event.witnessOperationId) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  return { event, witness };
}

function checkedStoredRecord(context, value) {
  try { return parseStoredRecord(context, value); }
  catch { throw lifecycleError('lifecycle_integrity_invalid'); }
}

function parseStoredRecord(context, value) {
  const record = boundedSnapshot(value, MAX_RECORD_BYTES, MAX_DEPTH, 'lifecycle_integrity_invalid');
  assertObjectKeys(record, RECORD_KEYS, 'lifecycle_integrity_invalid');
  validateBusinessRecord(record);
  if (!SHA256_RE.test(String(record.stateDigest || ''))
      || !Number.isSafeInteger(record.eventCount) || record.eventCount !== record.revision
      || ![record.eventHead, record.tailAuthorityDigest, record.tailOperationDigest,
        record.tailClaimDigest].every((item) => SHA256_RE.test(String(item || '')))
      || !UUID_RE.test(String(record.witnessOperationId || ''))
      || !validPurposeKeyId(record.macKeyId, KEY_PURPOSES.LIFECYCLE)
      || !SHA256_RE.test(String(record.recordMac || ''))) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  const unsigned = omit(record, ['recordMac']);
  verifyKeyringMac(
    context.keyring, record.macKeyId, RECORD_DOMAIN, unsigned, record.recordMac,
    'lifecycle_integrity_invalid',
  );
  if (digest(businessRecord(record)) !== record.stateDigest) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  verifyStoredIssuance(record);
  return record;
}

function checkedStoredEvent(context, value) {
  const event = boundedSnapshot(value, MAX_EVENT_BYTES, MAX_DEPTH, 'lifecycle_integrity_invalid');
  assertObjectKeys(event, EVENT_KEYS, 'lifecycle_integrity_invalid');
  if (event.schemaVersion !== SCHEMA_VERSION
      || !UUID_RE.test(String(event.eventId || ''))
      || !UUID_RE.test(String(event.witnessOperationId || ''))
      || !UUID_RE.test(String(event.lifecycleId || ''))
      || !CUSTOMER_ID_RE.test(String(event.customerId || ''))
      || !isDeploymentId(event.deploymentId)
      || !Number.isSafeInteger(event.revision) || event.revision < 1 || event.revision > STAGES.length
      || !STAGES.includes(event.toStage)
      || !(event.fromStage === null || STAGES.includes(event.fromStage))
      || !Number.isSafeInteger(event.entitlementVersion) || event.entitlementVersion < 1
      || ![event.entitlementDigest, event.stateDigest, event.authorityDigest,
        event.operationDigest, event.claimDigest, event.eventDigest, event.eventMac]
        .every((item) => SHA256_RE.test(String(item || '')))
      || !(event.previousEventDigest === null
        || SHA256_RE.test(String(event.previousEventDigest || '')))
      || !validPurposeKeyId(event.macKeyId, KEY_PURPOSES.LIFECYCLE)) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  checkedIso(event.recordedAt, 'lifecycle_integrity_invalid');
  const authority = checkedAuthorityEvidence(event.authority);
  const claims = checkedClaimEvidence(event.claimEvidence);
  if (digest(authority) !== event.authorityDigest || digest(claims) !== event.claimDigest) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  const eventWithDigest = omit(event, ['eventMac']);
  verifyKeyringMac(
    context.keyring, event.macKeyId, EVENT_DOMAIN, eventWithDigest, event.eventMac,
    'lifecycle_integrity_invalid',
  );
  const eventBase = omit(event, ['eventDigest', 'eventMac']);
  if (digest(eventBase) !== event.eventDigest) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  return event;
}

async function verifyArchivedClaims(context, tx, event, record) {
  const claims = event.claimEvidence;
  const authClaim = checkedAuthClaim(claims.authClaim);
  validateArchivedAuthority(event, record);
  const reusedAppliedAuth = event.toStage === 'acknowledged'
    && authClaim.operationDigest === record.operationDigests.applied;
  if (authClaim.lifecycleId !== event.lifecycleId
      || authClaim.customerId !== event.customerId
      || authClaim.deploymentId !== event.deploymentId
      || (!reusedAppliedAuth && authClaim.operationDigest !== event.operationDigest)
      || authClaim.action !== event.authority.action
      || authClaim.authEventId !== event.authority.authEventId
      || authClaim.authorityDigest !== event.authorityDigest
      || !canonicalEqual(authClaim.authority, event.authority)) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  await requireArchivedClaim(
    tx.getAuthClaim(authClaim.authEventId), authClaim, 'lifecycle_integrity_invalid',
  );
  const expectedKinds = {
    requested: 'targetConfirmationClaim', delivered: 'acknowledgementClaim',
    applied: 'acknowledgementClaim', acknowledged: 'acceptanceClaim',
  };
  for (const key of [
    'targetConfirmationClaim', 'acknowledgementClaim', 'acceptanceClaim',
  ]) {
    if (key !== expectedKinds[event.toStage] && claims[key] !== null) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
  }
  if (event.toStage === 'requested') {
    if (record.targetConfirmation === null) {
      if (claims.targetConfirmationClaim !== null || claims.approvalAuthClaim !== null) {
        throw lifecycleError('lifecycle_integrity_invalid');
      }
    } else {
      const claim = checkedTargetConfirmationClaim(claims.targetConfirmationClaim);
      const approval = checkedAuthClaim(claims.approvalAuthClaim);
      const approvalAuthority = record.targetConfirmation.approverAuthority;
      if (!canonicalEqual(
        omit(claim, ['lifecycleId', 'operationDigest']), record.targetConfirmation,
      ) || claim.lifecycleId !== event.lifecycleId
          || claim.operationDigest !== event.operationDigest
          || approval.lifecycleId !== event.lifecycleId
          || approval.customerId !== event.customerId
          || approval.deploymentId !== event.deploymentId
          || approval.operationDigest !== event.operationDigest
          || approval.authEventId !== approvalAuthority.authEventId
          || approval.action !== ACTIONS.TARGET_CONFIRM
          || approval.credentialPurpose !== CREDENTIAL_PURPOSES.TARGET_CONFIRMATION
          || approval.credentialVersion !== CREDENTIAL_VERSION
          || approval.authorityDigest !== digest(approvalAuthority)
          || !canonicalEqual(approval.authority, approvalAuthority)
          || approval.principalRef === event.authority.principalRef) {
        throw lifecycleError('lifecycle_integrity_invalid');
      }
      await Promise.all([
        requireArchivedClaim(
          tx.getTargetConfirmationClaim(claim.targetConfirmationId), claim,
          'lifecycle_integrity_invalid',
        ),
        requireArchivedClaim(
          tx.getAuthClaim(approval.authEventId), approval, 'lifecycle_integrity_invalid',
        ),
        requireArchivedClaim(
          tx.getOwnerAttestation(record.targetConfirmation.ownerAttestationId),
          record.targetConfirmation.ownerAttestation,
          'lifecycle_integrity_invalid',
        ),
        verifyArchivedOwnerAttestation(context, record.targetConfirmation.ownerAttestation),
      ]);
    }
  } else if (claims.approvalAuthClaim !== null) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  if (event.toStage === 'delivered') {
    await verifyArchivedAcknowledgementClaim(
      context, tx, claims.acknowledgementClaim, record.delivery, event, 'delivered',
    );
  }
  if (event.toStage === 'applied') {
    await verifyArchivedAcknowledgementClaim(
      context, tx, claims.acknowledgementClaim, record.customerAck, event, 'applied',
    );
  }
  if (event.toStage === 'acknowledged') {
    const claim = checkedAcceptanceClaim(claims.acceptanceClaim);
    if (!record.acceptance || claim.acceptanceId !== record.acceptance.acceptanceId
        || claim.lifecycleId !== event.lifecycleId
        || claim.customerId !== event.customerId
        || claim.deploymentId !== event.deploymentId
        || claim.appliedAckDigest !== record.customerAck.payloadDigest
        || claim.messageId !== record.customerAck.acknowledgement.messageId
        || claim.operationDigest !== event.operationDigest) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
    await requireArchivedClaim(
      tx.getAcceptanceClaim(claim.acceptanceId), claim, 'lifecycle_integrity_invalid',
    );
  }
}

async function verifyArchivedAcknowledgementClaim(context, tx, value, receipt, event, stage) {
  const claim = checkedAckClaim(context, value);
  if (!receipt
      || claim.messageId !== receipt.acknowledgement.messageId
      || claim.lifecycleId !== event.lifecycleId
      || claim.customerId !== event.customerId
      || claim.deploymentId !== event.deploymentId
      || claim.authEventId !== event.authority.authEventId
      || claim.authorityDigest !== event.authorityDigest
      || claim.targetVersion !== event.entitlementVersion
      || claim.targetDigest !== event.entitlementDigest
      || claim.payloadDigest !== receipt.payloadDigest
      || claim.operationDigest !== event.operationDigest
      || claim.lifecycleStage !== stage
      || claim.outcome !== 'success') {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  await requireArchivedClaim(
    tx.getAckClaim(claim.messageId), claim, 'lifecycle_integrity_invalid',
  );
}

function validateArchivedAuthority(event, record) {
  const expectedAction = {
    requested: ACTIONS.REQUEST,
    issued: ACTIONS.ISSUE,
    delivered: ACTIONS.ACKNOWLEDGE,
    applied: ACTIONS.ACKNOWLEDGE,
    acknowledged: ACTIONS.ACKNOWLEDGE,
  }[event.toStage];
  const authority = event.authority;
  const recordedMs = Date.parse(event.recordedAt);
  const authenticatedMs = Date.parse(authority.authenticatedAt);
  if (authority.action !== expectedAction
      || !ACTION_ROLES[expectedAction].has(authority.role)
      || authenticatedMs > recordedMs + MAX_FUTURE_SKEW_MS
      || recordedMs - authenticatedMs > MAX_AUTH_EVENT_AGE_MS) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  if (event.toStage !== 'requested') {
    if (authority.credentialPurpose !== ACTION_CREDENTIALS[expectedAction]) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
    return;
  }
  if (record.proposedState.reasonCode === 'emergency_revoke') {
    if (!['vendor_owner', 'vendor_security_admin'].includes(authority.role)
        || authority.credentialPurpose !== CREDENTIAL_PURPOSES.BREAK_GLASS
        || !archivedStepUpFresh(authority.stepUpAt, recordedMs)) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
    return;
  }
  if (record.targetConfirmation !== null) {
    if (!MANUAL_ACTOR_ROLES.includes(authority.role)
        || authority.credentialPurpose !== CREDENTIAL_PURPOSES.REQUEST
        || !archivedStepUpFresh(authority.stepUpAt, recordedMs)) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
    return;
  }
  if (!SERVICE_ACTOR_ROLES.includes(authority.role)
      || authority.credentialPurpose !== CREDENTIAL_PURPOSES.REQUEST) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
}

function archivedStepUpFresh(value, recordedMs) {
  if (value === null) return false;
  const stepUpMs = Date.parse(value);
  return Number.isFinite(stepUpMs)
    && stepUpMs <= recordedMs + MAX_FUTURE_SKEW_MS
    && recordedMs - stepUpMs <= MAX_STEP_UP_AGE_MS;
}

async function requireArchivedClaim(promise, expected, code) {
  const stored = boundedSnapshot(await promise, 32 * 1024, 8, code);
  if (!canonicalEqual(stored, expected)) throw lifecycleError(code);
}

async function verifyArchivedOwnerAttestation(context, value) {
  checkedOwnerAttestation(value, 'lifecycle_integrity_invalid');
  verifyOwnerAttestationProof(context, value, 'lifecycle_integrity_invalid', false);
  await verifyOwnerHistory(context, value, 'lifecycle_integrity_invalid');
}

function checkedPending(context, value) {
  const pending = boundedSnapshot(value, MAX_WITNESS_BYTES, MAX_DEPTH, 'pending_witness_invalid');
  assertObjectKeys(
    pending, ['descriptor', 'descriptorDigest', 'macKeyId', 'pendingMac', 'schemaVersion'],
    'pending_witness_invalid',
  );
  const descriptor = checkedDescriptor(pending.descriptor, 'pending_witness_invalid');
  if (pending.schemaVersion !== 1 || pending.descriptorDigest !== digest(descriptor)
      || !validPurposeKeyId(pending.macKeyId, KEY_PURPOSES.LIFECYCLE)
      || !SHA256_RE.test(String(pending.pendingMac || ''))) {
    throw lifecycleError('pending_witness_invalid');
  }
  verifyKeyringMac(
    context.keyring, pending.macKeyId, PENDING_DOMAIN, omit(pending, ['pendingMac']),
    pending.pendingMac, 'pending_witness_invalid',
  );
  return pending;
}

async function checkedWitnessEnvelope(context, value, expectedDescriptor, expectedState) {
  const envelope = boundedSnapshot(value, MAX_WITNESS_BYTES, MAX_DEPTH, 'witness_invalid');
  assertObjectKeys(envelope, [
    'descriptor', 'descriptorDigest', 'finalizedAt', 'preparedAt', 'schemaVersion',
    'state', 'witnessIdentity', 'witnessMac',
  ], 'witness_invalid');
  const descriptor = checkedDescriptor(envelope.descriptor, 'witness_invalid');
  const registeredIdentity = envelope.witnessIdentity
    && context.witnessIdentities.get(envelope.witnessIdentity.keyId);
  if (envelope.schemaVersion !== 1
      || !['prepared', 'final'].includes(envelope.state)
      || envelope.descriptorDigest !== digest(descriptor)
      || !registeredIdentity
      || !canonicalEqual(envelope.witnessIdentity, registeredIdentity)
      || envelope.preparedAt !== descriptor.preparedAt
      || !SHA256_RE.test(String(envelope.witnessMac || ''))
      || expectedDescriptor && !canonicalEqual(descriptor, expectedDescriptor)
      || expectedState && envelope.state !== expectedState) {
    throw lifecycleError('witness_invalid');
  }
  const preparedMs = checkedIso(envelope.preparedAt, 'witness_invalid');
  if (envelope.state === 'prepared') {
    if (envelope.finalizedAt !== null) throw lifecycleError('witness_invalid');
  } else {
    const finalizedMs = checkedIso(envelope.finalizedAt, 'witness_invalid');
    if (finalizedMs < preparedMs) throw lifecycleError('witness_invalid');
  }
  if (await context.witness.verify(clone(envelope)) !== true) {
    throw lifecycleError('witness_invalid');
  }
  return envelope;
}

function checkedDescriptor(value, code) {
  const descriptor = boundedSnapshot(value, MAX_WITNESS_BYTES, MAX_DEPTH, code);
  assertObjectKeys(descriptor, [
    'checkpoint', 'customerId', 'deploymentId', 'entitlementVersion', 'lifecycleId',
    'operationId', 'preparedAt', 'previousWitnessDigest', 'revision', 'schemaVersion',
    'stage',
  ], code);
  if (descriptor.schemaVersion !== 1
      || !UUID_RE.test(String(descriptor.operationId || ''))
      || !UUID_RE.test(String(descriptor.lifecycleId || ''))
      || !CUSTOMER_ID_RE.test(String(descriptor.customerId || ''))
      || !isDeploymentId(descriptor.deploymentId)
      || !Number.isSafeInteger(descriptor.entitlementVersion)
      || descriptor.entitlementVersion < 1
      || !Number.isSafeInteger(descriptor.revision) || descriptor.revision < 1
      || descriptor.revision > STAGES.length
      || descriptor.stage !== STAGES[descriptor.revision - 1]
      || !(descriptor.previousWitnessDigest === null
        || SHA256_RE.test(String(descriptor.previousWitnessDigest || '')))) {
    throw lifecycleError(code);
  }
  checkedIso(descriptor.preparedAt, code);
  checkedCheckpoint(descriptor.checkpoint, descriptor, code);
  return descriptor;
}

function checkedCheckpoint(value, descriptor, code) {
  const checkpoint = value;
  assertObjectKeys(checkpoint, [
    'customerId', 'deploymentId', 'entitlementVersion', 'eventCount', 'eventHead',
    'lifecycleId', 'macKeyId', 'recordMac', 'revision', 'schemaVersion', 'stage',
    'stateDigest', 'tailAuthorityDigest', 'tailClaimDigest', 'tailOperationDigest',
    'updatedAt', 'witnessOperationId',
  ], code);
  if (checkpoint.schemaVersion !== SCHEMA_VERSION
      || checkpoint.lifecycleId !== descriptor.lifecycleId
      || checkpoint.customerId !== descriptor.customerId
      || checkpoint.deploymentId !== descriptor.deploymentId
      || checkpoint.entitlementVersion !== descriptor.entitlementVersion
      || checkpoint.revision !== descriptor.revision
      || checkpoint.eventCount !== descriptor.revision
      || checkpoint.stage !== descriptor.stage
      || checkpoint.witnessOperationId !== descriptor.operationId
      || !validPurposeKeyId(checkpoint.macKeyId, KEY_PURPOSES.LIFECYCLE)
      || ![checkpoint.stateDigest, checkpoint.eventHead, checkpoint.tailAuthorityDigest,
        checkpoint.tailClaimDigest, checkpoint.tailOperationDigest, checkpoint.recordMac]
        .every((item) => SHA256_RE.test(String(item || '')))) {
    throw lifecycleError(code);
  }
  checkedIso(checkpoint.updatedAt, code);
}

function validateBusinessRecord(record) {
  if (record.schemaVersion !== SCHEMA_VERSION
      || !UUID_RE.test(String(record.lifecycleId || ''))
      || !CUSTOMER_ID_RE.test(String(record.customerId || ''))
      || !isDeploymentId(record.deploymentId)
      || !IDEMPOTENCY_KEY_RE.test(String(record.idempotencyKey || ''))
      || !Number.isSafeInteger(record.revision) || record.revision < 1
      || record.revision > STAGES.length || record.stage !== STAGES[record.revision - 1]
      || !Number.isSafeInteger(record.entitlementVersion) || record.entitlementVersion < 1
      || !SHA256_RE.test(String(record.entitlementDigest || ''))) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  checkedProposedState(record.proposedState, record, 'lifecycle_integrity_invalid');
  if (record.currentState !== null) {
    const current = checkedCurrentStateShape(record.currentState);
    if (current.customerId !== record.customerId
        || current.deploymentId !== record.deploymentId
        || current.entitlementVersion !== record.proposedState.previousVersion) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
  } else if (record.proposedState.previousVersion !== 0) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  checkedStoredTargetConfirmation(record.targetConfirmation, record);
  const storedDualControl = record.proposedState.reasonCode !== 'emergency_revoke'
    && (MANUAL_REASON_CODES.includes(record.proposedState.reasonCode)
      || Boolean(record.currentState
        && (record.currentState.plan !== record.proposedState.plan
          || record.currentState.seats !== record.proposedState.seats)));
  if (Boolean(record.targetConfirmation) !== storedDualControl) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  assertObjectKeys(record.operationDigests, OPERATION_KEYS, 'lifecycle_integrity_invalid');
  assertObjectKeys(record.timestamps, STAGES.map((stage) => stage + 'At'),
    'lifecycle_integrity_invalid');
  const stageIndex = STAGES.indexOf(record.stage);
  for (let index = 0; index < STAGES.length; index += 1) {
    const stage = STAGES[index];
    const operation = record.operationDigests[stage];
    const timestamp = record.timestamps[stage + 'At'];
    if (index <= stageIndex) {
      if (!SHA256_RE.test(String(operation || ''))) {
        throw lifecycleError('lifecycle_integrity_invalid');
      }
      checkedIso(timestamp, 'lifecycle_integrity_invalid');
      if (index > 0 && Date.parse(timestamp) < Date.parse(
        record.timestamps[STAGES[index - 1] + 'At'],
      )) throw lifecycleError('lifecycle_integrity_invalid');
    } else if (operation !== null || timestamp !== null) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
  }
  if (record.updatedAt !== record.timestamps[record.stage + 'At']) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  checkedIso(record.updatedAt, 'lifecycle_integrity_invalid');
  checkedStoredIssuanceShape(record.issuance, stageIndex >= 1);
  checkedStoredDelivery(record.delivery, record, stageIndex >= 2);
  checkedStoredCustomerAck(record.customerAck, record, stageIndex >= 3);
  checkedStoredAcceptance(record.acceptance, record, stageIndex >= 4);
}

function checkedProposedState(value, record, code) {
  assertObjectKeys(value, [
    'entitlementDigest', 'entitlementVersion', 'features', 'plan', 'previousVersion',
    'reasonCode', 'seats', 'status',
  ], code);
  if (value.entitlementVersion !== record.entitlementVersion
      || value.entitlementDigest !== record.entitlementDigest
      || !Number.isSafeInteger(value.previousVersion) || value.previousVersion < 0
      || value.previousVersion >= value.entitlementVersion
      || !['active', 'paused', 'revoked'].includes(value.status)
      || !['standard', 'enterprise'].includes(value.plan)
      || !Number.isSafeInteger(value.seats) || value.seats < 0 || value.seats > 1_000_000
      || !validFeatures(value.features) || !validReason(value.status, value.reasonCode)) {
    throw lifecycleError(code);
  }
}

function checkedStoredTargetConfirmation(value, record) {
  if (value === null) return;
  const confirmation = checkedTargetConfirmation(value, 'lifecycle_integrity_invalid');
  if (confirmation.customerId !== record.customerId
      || confirmation.deploymentId !== record.deploymentId
      || confirmation.entitlementVersion !== record.entitlementVersion
      || confirmation.entitlementDigest !== record.entitlementDigest) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
}

function checkedStoredIssuanceShape(value, required) {
  if (!required) {
    if (value !== null) throw lifecycleError('lifecycle_integrity_invalid');
    return;
  }
  assertObjectKeys(value, [
    'artifact', 'artifactDigest', 'issuedAt', 'keyId', 'signatureDomain',
    'verificationKeyFingerprint', 'verificationKeySpki',
  ], 'lifecycle_integrity_invalid');
  if (!SHA256_RE.test(String(value.artifactDigest || ''))
      || !validPurposeKeyBinding(
        value.keyId, KEY_PURPOSES.ENTITLEMENT, value.verificationKeyFingerprint,
      )
      || value.signatureDomain !== protocol.SIGNATURE_DOMAINS[protocol.CHANNEL_KINDS.ENTITLEMENT]
      || !SHA256_RE.test(String(value.verificationKeyFingerprint || ''))
      || typeof value.verificationKeySpki !== 'string'
      || value.verificationKeySpki.length < 40 || value.verificationKeySpki.length > 512) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  checkedIso(value.issuedAt, 'lifecycle_integrity_invalid');
  checkedSignedArtifact(value.artifact);
}

function checkedStoredDelivery(value, record, required) {
  if (!required) {
    if (value !== null) throw lifecycleError('lifecycle_integrity_invalid');
    return;
  }
  assertObjectKeys(value, ['acceptedAt', 'acknowledgement', 'payloadDigest'],
    'lifecycle_integrity_invalid');
  const acknowledgement = protocol.assertChannel(
    value.acknowledgement, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
  );
  if (acknowledgement.customerId !== record.customerId
      || acknowledgement.deploymentId !== record.deploymentId
      || acknowledgement.targetVersion !== record.entitlementVersion
      || acknowledgement.targetDigest !== record.entitlementDigest
      || acknowledgement.lifecycleStage !== 'delivered'
      || acknowledgement.outcome !== 'success'
      || value.payloadDigest !== protocol.payloadDigest(
        acknowledgement, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
      )) throw lifecycleError('lifecycle_integrity_invalid');
  checkedIso(value.acceptedAt, 'lifecycle_integrity_invalid');
}

function checkedStoredCustomerAck(value, record, required) {
  if (!required) {
    if (value !== null) throw lifecycleError('lifecycle_integrity_invalid');
    return;
  }
  assertObjectKeys(value, ['acceptedAt', 'acknowledgement', 'payloadDigest'],
    'lifecycle_integrity_invalid');
  const acknowledgement = protocol.assertChannel(
    value.acknowledgement, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
  );
  if (acknowledgement.customerId !== record.customerId
      || acknowledgement.deploymentId !== record.deploymentId
      || acknowledgement.targetVersion !== record.entitlementVersion
      || acknowledgement.targetDigest !== record.entitlementDigest
      || acknowledgement.lifecycleStage !== 'applied'
      || acknowledgement.outcome !== 'success'
      || value.payloadDigest !== protocol.payloadDigest(
        acknowledgement, protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
      )) throw lifecycleError('lifecycle_integrity_invalid');
  checkedIso(value.acceptedAt, 'lifecycle_integrity_invalid');
}

function checkedStoredAcceptance(value, record, required) {
  if (!required) {
    if (value !== null) throw lifecycleError('lifecycle_integrity_invalid');
    return;
  }
  assertObjectKeys(value, ['acceptanceId', 'acceptedAt', 'appliedAckDigest', 'messageId'],
    'lifecycle_integrity_invalid');
  if (!UUID_RE.test(String(value.acceptanceId || ''))
      || value.messageId !== record.customerAck.acknowledgement.messageId
      || value.appliedAckDigest !== record.customerAck.payloadDigest) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  checkedIso(value.acceptedAt, 'lifecycle_integrity_invalid');
}

function verifyStoredIssuance(record) {
  if (!record.issuance) return;
  try {
    const der = Buffer.from(record.issuance.verificationKeySpki, 'base64');
    if (der.length < 32 || der.length > 256
        || der.toString('base64') !== record.issuance.verificationKeySpki) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
    const publicKey = parsePublicOnlyEd25519Key({
      key: der, format: 'der', type: 'spki',
    });
    if (keyFingerprint(publicKey) !== record.issuance.verificationKeyFingerprint) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
    const verified = verifySignedArtifact(
      record.issuance.artifact,
      new Map([[record.issuance.keyId, publicKey]]),
      protocol.CHANNEL_KINDS.ENTITLEMENT,
    );
    if (verified.payloadDigest !== record.entitlementDigest
        || verified.keyId !== record.issuance.keyId
        || digest(record.issuance.artifact) !== record.issuance.artifactDigest) {
      throw lifecycleError('lifecycle_integrity_invalid');
    }
    assertArtifactMatchesRecord(verified, record);
  } catch (error) {
    if (error && error.code === 'lifecycle_integrity_invalid') throw error;
    throw lifecycleError('lifecycle_integrity_invalid');
  }
}

function checkedAuthorityEvidence(value) {
  assertObjectKeys(value, [
    'action', 'authEventId', 'authenticatedAt', 'credentialPurpose',
    'credentialVersion', 'principalRef', 'role', 'stepUpAt',
  ], 'lifecycle_integrity_invalid');
  const authenticatedMs = checkedIso(value.authenticatedAt, 'lifecycle_integrity_invalid');
  const stepUpMs = value.stepUpAt === null
    ? null : checkedIso(value.stepUpAt, 'lifecycle_integrity_invalid');
  if (!Object.values(ACTIONS).includes(value.action)
      || !UUID_RE.test(String(value.authEventId || ''))
      || ![...MANUAL_ACTOR_ROLES, ...SERVICE_ACTOR_ROLES, CUSTOMER_ACTOR_ROLE]
        .includes(value.role)
      || !SHA256_RE.test(String(value.principalRef || ''))
      || !SAFE_SLUG_RE.test(String(value.credentialPurpose || ''))
      || value.credentialVersion !== CREDENTIAL_VERSION
      || (stepUpMs !== null && stepUpMs > authenticatedMs)) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  return value;
}

function checkedClaimEvidence(value) {
  assertObjectKeys(value, [
    'acceptanceClaim', 'acknowledgementClaim', 'approvalAuthClaim', 'authClaim',
    'targetConfirmationClaim',
  ], 'lifecycle_integrity_invalid');
  checkedAuthClaim(value.authClaim);
  return value;
}

function checkedAuthClaim(value) {
  assertObjectKeys(value, [
    'action', 'authEventId', 'authority', 'authorityDigest', 'credentialPurpose',
    'credentialVersion', 'customerId', 'deploymentId', 'lifecycleId',
    'operationDigest', 'principalRef',
  ], 'lifecycle_integrity_invalid');
  const authority = checkedAuthorityEvidence(value.authority);
  if (value.authEventId !== authority.authEventId || value.action !== authority.action
      || value.principalRef !== authority.principalRef
      || value.credentialPurpose !== authority.credentialPurpose
      || value.credentialVersion !== authority.credentialVersion
      || value.authorityDigest !== digest(authority)
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !UUID_RE.test(String(value.lifecycleId || ''))
      || !SHA256_RE.test(String(value.operationDigest || ''))) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  return value;
}

function checkedTargetConfirmation(value, code) {
  assertObjectKeys(value, [
    'approverAuthEventId', 'approverAuthority', 'confirmationRef', 'confirmedAt',
    'customerId', 'deploymentId', 'entitlementDigest', 'entitlementVersion',
    'ownerAttestation', 'ownerAttestationId', 'purpose', 'targetConfirmationId',
  ], code);
  const authority = checkedAuthorityEvidence(value.approverAuthority);
  const attestation = checkedOwnerAttestation(value.ownerAttestation, code);
  if (!UUID_RE.test(String(value.targetConfirmationId || ''))
      || !UUID_RE.test(String(value.approverAuthEventId || ''))
      || !UUID_RE.test(String(value.ownerAttestationId || ''))
      || !SHA256_RE.test(String(value.confirmationRef || ''))
      || value.purpose !== TARGET_CONFIRMATION_PURPOSE
      || authority.authEventId !== value.approverAuthEventId
      || authority.action !== ACTIONS.TARGET_CONFIRM
      || authority.credentialPurpose !== CREDENTIAL_PURPOSES.TARGET_CONFIRMATION
      || authority.credentialVersion !== CREDENTIAL_VERSION
      || !MANUAL_ACTOR_ROLES.includes(authority.role)
      || authority.stepUpAt === null
      || Date.parse(authority.authenticatedAt) > Date.parse(value.confirmedAt)
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !Number.isSafeInteger(value.entitlementVersion) || value.entitlementVersion < 1
      || !SHA256_RE.test(String(value.entitlementDigest || ''))
      || attestation.attestationId !== value.ownerAttestationId
      || attestation.targetConfirmationId !== value.targetConfirmationId
      || attestation.approverAuthEventId !== value.approverAuthEventId
      || attestation.customerId !== value.customerId
      || attestation.deploymentId !== value.deploymentId
      || attestation.entitlementVersion !== value.entitlementVersion
      || attestation.entitlementDigest !== value.entitlementDigest
      || Date.parse(attestation.issuedAt) > Date.parse(value.confirmedAt)
      || Date.parse(attestation.expiresAt) < Date.parse(value.confirmedAt)) {
    throw lifecycleError(code);
  }
  checkedIso(value.confirmedAt, code);
  return value;
}

function checkedOwnerAttestation(value, code) {
  assertObjectKeys(value, [
    'approverAuthEventId', 'attestationId', 'authorityPurpose', 'customerId',
    'deploymentId', 'entitlementDigest', 'entitlementVersion', 'evidenceDigest',
    'expiresAt', 'historyEventDigest', 'historyEventId', 'issuedAt', 'proof',
    'purpose', 'targetConfirmationId', 'verificationKeyFingerprint', 'version',
    'verificationKeySpki',
  ], code);
  assertObjectKeys(value.proof, ['keyId', 'signature'], code);
  const issuedMs = checkedIso(value.issuedAt, code);
  const expiresMs = checkedIso(value.expiresAt, code);
  const verificationKey = checkedPublicKeySpki(value.verificationKeySpki, code);
  if (!UUID_RE.test(String(value.attestationId || ''))
      || !UUID_RE.test(String(value.targetConfirmationId || ''))
      || !UUID_RE.test(String(value.approverAuthEventId || ''))
      || !UUID_RE.test(String(value.historyEventId || ''))
      || value.purpose !== OWNER_ATTESTATION_PURPOSE
      || value.version !== 1
      || value.authorityPurpose !== AUTHORITY_PURPOSES.OWNER_ATTESTATION
      || !validAuthorityKeyId(
        value.proof.keyId, AUTHORITY_MANIFEST_DEFINITIONS[AUTHORITY_PURPOSES.OWNER_ATTESTATION],
      )
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !Number.isSafeInteger(value.entitlementVersion) || value.entitlementVersion < 1
      || ![value.entitlementDigest, value.historyEventDigest, value.evidenceDigest,
        value.verificationKeyFingerprint].every((item) => SHA256_RE.test(String(item || '')))
      || keyFingerprint(verificationKey) !== value.verificationKeyFingerprint
      || issuedMs >= expiresMs
      || value.evidenceDigest !== digest(ownerAttestationEvidence(value))
      || !canonicalSignature(value.proof.signature)) {
    throw lifecycleError(code);
  }
  return value;
}

function ownerAttestationEvidence(value) {
  return omit(value, ['evidenceDigest', 'proof']);
}

function ownerAttestationSigningInput(value) {
  return Buffer.concat([
    Buffer.from(OWNER_ATTESTATION_SIGNATURE_DOMAIN + '\0', 'utf8'),
    Buffer.from(protocol.canonicalJson(omit(value, ['proof'])), 'utf8'),
  ]);
}

function verifyOwnerAttestationProof(context, value, code, requireLiveAuthority = true) {
  let key;
  try {
    key = checkedPublicKeySpki(value.verificationKeySpki, code);
    if (requireLiveAuthority) {
      context.authorityRegistry.assertPublicKey(
        AUTHORITY_PURPOSES.OWNER_ATTESTATION,
        value.proof.keyId,
        value.verificationKeyFingerprint,
      );
    }
  } catch { throw lifecycleError(code); }
  if (!crypto.verify(
    null, ownerAttestationSigningInput(value), key,
    Buffer.from(value.proof.signature, 'base64'),
  )) throw lifecycleError(code);
}

async function verifyOwnerHistory(context, value, code) {
  let verified;
  try {
    verified = await context.ownerAuditVerifier.verifyHistoryEvent(deepFreeze({
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
    }));
  } catch { throw lifecycleError(code); }
  if (verified !== true) throw lifecycleError(code);
}

function canonicalSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === 64 && decoded.toString('base64') === value;
}

function checkedTargetConfirmationClaim(value) {
  const claim = value;
  checkedTargetConfirmation(
    omit(claim, ['lifecycleId', 'operationDigest']), 'lifecycle_integrity_invalid',
  );
  if (!UUID_RE.test(String(claim.lifecycleId || ''))
      || !SHA256_RE.test(String(claim.operationDigest || ''))
      || Object.keys(claim).length !== 14) throw lifecycleError('lifecycle_integrity_invalid');
  return claim;
}

function checkedAckClaim(context, value) {
  assertObjectKeys(value, [
    'authEventId', 'authorityDigest', 'claimMac', 'credentialPurpose',
    'credentialVersion', 'customerId', 'deploymentId', 'lifecycleId',
    'lifecycleStage', 'macKeyId', 'messageId', 'operationDigest', 'outcome',
    'payloadDigest', 'reasonCode', 'targetDigest', 'targetVersion',
  ], 'lifecycle_integrity_invalid');
  if (!UUID_RE.test(String(value.authEventId || ''))
      || !UUID_RE.test(String(value.messageId || ''))
      || !UUID_RE.test(String(value.lifecycleId || ''))
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !Number.isSafeInteger(value.targetVersion) || value.targetVersion < 1
      || ![value.authorityDigest, value.targetDigest, value.payloadDigest,
        value.operationDigest, value.claimMac]
        .every((item) => SHA256_RE.test(String(item || '')))
      || !['delivered', 'applied'].includes(value.lifecycleStage)
      || !['success', 'rejected'].includes(value.outcome)
      || !SAFE_SLUG_RE.test(String(value.reasonCode || ''))
      || value.credentialPurpose !== CREDENTIAL_PURPOSES.ACKNOWLEDGE
      || value.credentialVersion !== CREDENTIAL_VERSION
      || !validPurposeKeyId(value.macKeyId, KEY_PURPOSES.LIFECYCLE)) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  const base = omit(value, ['claimMac']);
  verifyKeyringMac(
    context.keyring, value.macKeyId, ACK_CLAIM_DOMAIN, base, value.claimMac,
    'lifecycle_integrity_invalid',
  );
  return value;
}

function checkedAcceptanceClaim(value) {
  assertObjectKeys(value, [
    'acceptanceId', 'appliedAckDigest', 'credentialPurpose', 'credentialVersion',
    'customerId', 'deploymentId', 'lifecycleId', 'messageId', 'operationDigest',
  ], 'lifecycle_integrity_invalid');
  if (!UUID_RE.test(String(value.acceptanceId || ''))
      || !UUID_RE.test(String(value.lifecycleId || ''))
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !UUID_RE.test(String(value.messageId || ''))
      || !SHA256_RE.test(String(value.appliedAckDigest || ''))
      || !SHA256_RE.test(String(value.operationDigest || ''))
      || value.credentialPurpose !== CREDENTIAL_PURPOSES.ACKNOWLEDGE
      || value.credentialVersion !== CREDENTIAL_VERSION) {
    throw lifecycleError('lifecycle_integrity_invalid');
  }
  return value;
}

function checkedRequestCommand(value) {
  const command = boundedSnapshot(value, MAX_COMMAND_BYTES, MAX_DEPTH, 'request_invalid');
  assertObjectKeys(command, [
    'authEventId', 'entitlement', 'idempotencyKey', 'targetConfirmationId',
  ], 'request_invalid');
  if (!UUID_RE.test(String(command.authEventId || ''))
      || !IDEMPOTENCY_KEY_RE.test(String(command.idempotencyKey || ''))
      || !(command.targetConfirmationId === null
        || UUID_RE.test(String(command.targetConfirmationId || '')))) {
    throw lifecycleError('request_invalid');
  }
  return command;
}

function checkedMutationCommand(value, extraKeys) {
  const command = boundedSnapshot(
    value, MAX_COMMAND_BYTES, MAX_DEPTH, 'transition_command_invalid',
  );
  assertObjectKeys(command, [
    'authEventId', 'expectedRevision', 'lifecycleId', ...extraKeys,
  ], 'transition_command_invalid');
  if (!UUID_RE.test(String(command.authEventId || ''))
      || !UUID_RE.test(String(command.lifecycleId || ''))
      || !Number.isSafeInteger(command.expectedRevision)
      || command.expectedRevision < 1 || command.expectedRevision > STAGES.length) {
    throw lifecycleError('transition_command_invalid');
  }
  return command;
}

function checkedAckCommand(value) {
  const command = boundedSnapshot(value, MAX_COMMAND_BYTES, MAX_DEPTH, 'ack_command_invalid');
  assertObjectKeys(command, ['acknowledgement', 'authEventId'], 'ack_command_invalid');
  if (!UUID_RE.test(String(command.authEventId || ''))) {
    throw lifecycleError('ack_command_invalid');
  }
  return command;
}

function checkedReadCommand(value) {
  const query = boundedSnapshot(value, 8 * 1024, 4, 'read_command_invalid');
  assertObjectKeys(query, ['authEventId', 'lifecycleId'], 'read_command_invalid');
  if (!UUID_RE.test(String(query.authEventId || ''))
      || !UUID_RE.test(String(query.lifecycleId || ''))) {
    throw lifecycleError('read_command_invalid');
  }
  return query;
}

function proposedStateFor(entitlement, entitlementDigest) {
  return {
    status: entitlement.status,
    plan: entitlement.plan,
    seats: entitlement.seats,
    features: [...entitlement.features],
    reasonCode: entitlement.reasonCode,
    entitlementVersion: entitlement.entitlementVersion,
    previousVersion: entitlement.previousVersion,
    entitlementDigest,
  };
}

function businessRecord(record) {
  const business = {};
  for (const key of BUSINESS_KEYS) business[key] = clone(record[key]);
  return business;
}

function operationResult(record, idempotent) {
  return deepFreeze({
    ok: true,
    pending: false,
    retryable: false,
    idempotent: Boolean(idempotent),
    lifecycle: portalRecord(record),
  });
}

function acknowledgementPendingResult(value) {
  return deepFreeze({
    ok: false,
    pending: true,
    retryable: true,
    code: 'acknowledgement_finalization_pending',
    operationRef: value && value.operationRef || null,
  });
}

function rejectionResult(claim, idempotent) {
  return deepFreeze({
    ok: true,
    pending: false,
    retryable: false,
    idempotent: Boolean(idempotent),
    accepted: false,
    closed: true,
    rejection: {
      customerId: claim.customerId,
      deploymentId: claim.deploymentId,
      targetVersion: claim.targetVersion,
      lifecycleStage: claim.lifecycleStage,
      reasonCode: claim.reasonCode,
    },
  });
}

function portalRecord(record) {
  return deepFreeze({
    lifecycleId: record.lifecycleId,
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    entitlementVersion: record.entitlementVersion,
    entitlementDigest: record.entitlementDigest,
    stage: record.stage,
    revision: record.revision,
    completed: record.stage === 'acknowledged',
    status: record.proposedState.status,
    plan: record.proposedState.plan,
    seats: record.proposedState.seats,
    reasonCode: record.proposedState.reasonCode,
    timestamps: clone(record.timestamps),
  });
}

function scopeOf(value) {
  return { customerId: value.customerId, deploymentId: value.deploymentId };
}

function validFeatures(value) {
  return Array.isArray(value) && value.length <= 128
    && value.every((item) => SAFE_SLUG_RE.test(String(item || '')))
    && new Set(value).size === value.length
    && value.every((item, index) => index === 0 || value[index - 1].localeCompare(item) < 0);
}

function validReason(status, reasonCode) {
  const reasons = {
    active: new Set(['billing_active', 'trial_active', 'manual_restore']),
    paused: new Set(['manual_pause', 'payment_past_due']),
    revoked: new Set(['manual_revoke', 'subscription_ended', 'emergency_revoke']),
  };
  return reasons[status] instanceof Set && reasons[status].has(reasonCode);
}

function checkedAuthorityManifest(value) {
  const code = 'owner_authority_manifest_invalid';
  const manifest = boundedSnapshot(
    value, MAX_AUTHORITY_MANIFEST_BYTES, 6, 'owner_authority_manifest_required',
  );
  assertObjectKeys(manifest, ['authorities', 'schemaVersion'], code);
  if (manifest.schemaVersion !== AUTHORITY_MANIFEST_VERSION) throw lifecycleError(code);
  assertObjectKeys(manifest.authorities, Object.keys(AUTHORITY_MANIFEST_DEFINITIONS), code);
  const records = new Map();
  const identities = new Set();
  const keyIds = new Set();
  for (const [purpose, definition] of Object.entries(AUTHORITY_MANIFEST_DEFINITIONS)) {
    const authority = manifest.authorities[purpose];
    assertObjectKeys(authority, ['identities', 'identityType', 'purpose'], code);
    if (authority.purpose !== purpose || authority.identityType !== definition.identityType
        || !Array.isArray(authority.identities)
        || authority.identities.length < 1 || authority.identities.length > 2) {
      throw lifecycleError(code);
    }
    const normalized = authority.identities.map((identity) => checkedAuthorityIdentity(
      identity, purpose, definition, code,
    ));
    const slots = normalized.map((identity) => identity.slot);
    if (slots.filter((slot) => slot === 'current').length !== 1
        || (!definition.allowNext && normalized.length !== 1)
        || new Set(slots).size !== slots.length) throw lifecycleError(code);
    for (const identity of normalized) {
      if (identities.has(identity.identity) || keyIds.has(identity.keyId)) {
        throw lifecycleError('owner_authority_identity_reused');
      }
      identities.add(identity.identity);
      keyIds.add(identity.keyId);
    }
    records.set(purpose, deepFreeze(normalized));
  }
  return authorityManifestView(records, identities);
}

function checkedAuthorityIdentity(value, purpose, definition, code) {
  const publicMaterial = definition.identityType === 'ed25519_public';
  assertObjectKeys(
    value,
    publicMaterial ? ['identity', 'keyId', 'publicKeySpki', 'slot'] : ['identity', 'keyId', 'slot'],
    code,
  );
  if (!['current', 'next'].includes(value.slot)
      || (value.slot === 'next' && !definition.allowNext)
      || !validAuthorityKeyId(value.keyId, definition, purpose, value.identity)
      || !SHA256_RE.test(String(value.identity || ''))) throw lifecycleError(code);
  if (!publicMaterial) return deepFreeze(clone(value));
  const key = checkedPublicKeySpki(value.publicKeySpki, code);
  if (keyFingerprint(key) !== value.identity) throw lifecycleError(code);
  return deepFreeze(clone(value));
}

function checkedPublicKeySpki(value, code) {
  if (typeof value !== 'string' || value.length < 40 || value.length > 512) {
    throw lifecycleError(code);
  }
  const der = Buffer.from(value, 'base64');
  if (der.toString('base64') !== value) throw lifecycleError(code);
  let key;
  try {
    key = parsePublicOnlyEd25519Key({ key: der, format: 'der', type: 'spki' });
  }
  catch { throw lifecycleError(code); }
  if (key.export({ type: 'spki', format: 'der' }).toString('base64') !== value) {
    throw lifecycleError(code);
  }
  return key;
}

function validAuthorityKeyId(value, definition, purpose = null, identity = null) {
  const valid = /^[a-z0-9][a-z0-9_.-]{0,95}$/.test(String(value || ''))
    && String(value).startsWith(definition.keyPrefix);
  if (!valid || purpose !== AUTHORITY_PURPOSES.ENTITLEMENT) return valid;
  return validPurposeKeyBinding(value, KEY_PURPOSES.ENTITLEMENT, identity);
}

function authorityManifestView(records, identities) {
  const listed = (purpose) => records.get(purpose) || [];
  return Object.freeze({
    identities,
    get(purpose) {
      const record = listed(purpose).find((identity) => identity.slot === 'current');
      return record ? clone({ ...record, purpose,
        identityType: AUTHORITY_MANIFEST_DEFINITIONS[purpose].identityType }) : null;
    },
    list(purpose) {
      return listed(purpose).map((record) => clone({
        ...record, purpose, identityType: AUTHORITY_MANIFEST_DEFINITIONS[purpose].identityType,
      }));
    },
    allRecords() {
      return [...records.keys()].flatMap((purpose) => this.list(purpose));
    },
    publicKeys(purpose) {
      const output = {};
      for (const record of listed(purpose)) {
        if (!record.publicKeySpki) throw lifecycleError('owner_authority_manifest_mismatch');
        output[record.keyId] = checkedPublicKeySpki(
          record.publicKeySpki, 'owner_authority_manifest_mismatch',
        );
      }
      return output;
    },
    assertPublicKey(purpose, keyId, fingerprint) {
      const match = listed(purpose).find((record) => (
        record.keyId === keyId && record.identity === fingerprint && record.publicKeySpki
      ));
      if (!match) throw lifecycleError('owner_authority_manifest_mismatch');
    },
  });
}

function checkedIntegrityKeyring(value, authorityRegistry) {
  if (!isPlainObject(value)) throw lifecycleError('integrity_keyring_required');
  const allowed = new Set([
    'current', 'purpose', 'retiredVerifyOnly', 'version',
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))
      || value.purpose !== INTEGRITY_PURPOSE || value.version !== 1
      || !isPlainObject(value.current)
      || !isPlainObject(value.retiredVerifyOnly || {})) {
    throw lifecycleError('integrity_keyring_invalid');
  }
  assertObjectKeys(value.current, ['key', 'keyId'], 'integrity_keyring_invalid');
  const currentKeyId = checkedPurposeKeyId(
    value.current.keyId, KEY_PURPOSES.LIFECYCLE, 'integrity_keyring_invalid',
  );
  const currentKey = checkedMacKey(value.current.key);
  const keys = new Map([[currentKeyId, currentKey]]);
  for (const [keyIdValue, keyValue] of Object.entries(value.retiredVerifyOnly || {})) {
    const keyId = checkedPurposeKeyId(
      keyIdValue, KEY_PURPOSES.LIFECYCLE, 'integrity_keyring_invalid',
    );
    if (keys.has(keyId)) throw lifecycleError('integrity_keyring_invalid');
    keys.set(keyId, checkedMacKey(keyValue));
  }
  const fingerprints = new Map();
  for (const [keyId, key] of keys) {
    const fingerprint = digestBytes(key);
    if ([...fingerprints.values()].includes(fingerprint)) {
      throw lifecycleError('integrity_keyring_invalid');
    }
    fingerprints.set(keyId, fingerprint);
  }
  const registered = authorityRegistry.get(KEY_PURPOSES.LIFECYCLE);
  if (registered.keyId !== currentKeyId
      || registered.identity !== fingerprints.get(currentKeyId)
      || [...fingerprints.entries()].some(([keyId, fingerprint]) => (
        keyId !== currentKeyId && authorityRegistry.identities.has(fingerprint)
      ))) {
    throw lifecycleError('integrity_key_identity_conflict');
  }
  return Object.freeze({
    purpose: INTEGRITY_PURPOSE,
    version: 1,
    currentKeyId,
    keys,
    fingerprints,
  });
}

function checkedWitness(value, keyring, authorityRegistry) {
  if (!value || typeof value !== 'object') throw lifecycleError('witness_required');
  for (const method of WITNESS_METHODS) {
    if (typeof value[method] !== 'function') throw lifecycleError('witness_invalid');
  }
  let manifest;
  try { manifest = value.identity(); }
  catch { throw lifecycleError('witness_invalid'); }
  manifest = boundedSnapshot(manifest, 16 * 1024, 4, 'witness_invalid');
  assertObjectKeys(manifest, [
    'current', 'purpose', 'retiredVerifyOnly', 'version',
  ], 'witness_invalid');
  assertObjectKeys(manifest.current, ['keyFingerprint', 'keyId'], 'witness_invalid');
  if (manifest.purpose !== WITNESS_PURPOSE || manifest.version !== 1
      || !isPlainObject(manifest.retiredVerifyOnly)
      || Object.keys(manifest.retiredVerifyOnly).length > 8) {
    throw lifecycleError('witness_identity_invalid');
  }
  const identities = new Map();
  addWitnessIdentity(identities, manifest.current.keyId, manifest.current.keyFingerprint);
  for (const [keyId, fingerprint] of Object.entries(manifest.retiredVerifyOnly)) {
    addWitnessIdentity(identities, keyId, fingerprint);
  }
  const currentIdentity = identities.get(manifest.current.keyId);
  const registered = authorityRegistry.get(AUTHORITY_PURPOSES.WITNESS_INTEGRITY);
  if (!registered || registered.keyId !== currentIdentity.keyId
      || registered.identity !== currentIdentity.keyFingerprint
      || [...identities.values()].some((identity) => (
        (identity.keyId !== currentIdentity.keyId
          && authorityRegistry.identities.has(identity.keyFingerprint))
        || [...keyring.fingerprints.values()].includes(identity.keyFingerprint)
      ))) throw lifecycleError('witness_identity_invalid');
  const wrapped = { currentIdentity, identities };
  for (const method of WITNESS_METHODS.filter((name) => name !== 'identity')) {
    wrapped[method] = value[method].bind(value);
  }
  return Object.freeze(wrapped);
}

function addWitnessIdentity(identities, keyId, keyFingerprintValue) {
  if (!WITNESS_KEY_ID_RE.test(String(keyId || ''))
      || !SHA256_RE.test(String(keyFingerprintValue || ''))
      || identities.has(keyId)
      || [...identities.values()].some((value) => value.keyFingerprint === keyFingerprintValue)) {
    throw lifecycleError('witness_identity_invalid');
  }
  identities.set(keyId, deepFreeze({
    purpose: WITNESS_PURPOSE,
    version: 1,
    keyId,
    keyFingerprint: keyFingerprintValue,
  }));
}

function checkedOwnerAuditVerifier(value, authorityRegistry) {
  if (!value || typeof value !== 'object'
      || typeof value.identity !== 'function'
      || typeof value.verifyHistoryEvent !== 'function') {
    throw lifecycleError('owner_audit_verifier_required');
  }
  let identity;
  try { identity = boundedSnapshot(value.identity(), 4 * 1024, 3, 'owner_audit_verifier_invalid'); }
  catch { throw lifecycleError('owner_audit_verifier_invalid'); }
  assertObjectKeys(identity, ['identity', 'keyId', 'purpose'], 'owner_audit_verifier_invalid');
  const registered = authorityRegistry.get(AUTHORITY_PURPOSES.PLATFORM_AUDIT);
  if (identity.purpose !== AUTHORITY_PURPOSES.PLATFORM_AUDIT
      || !canonicalEqual(identity, {
        purpose: registered.purpose, keyId: registered.keyId, identity: registered.identity,
      })) throw lifecycleError('owner_audit_verifier_invalid');
  return Object.freeze({ verifyHistoryEvent: value.verifyHistoryEvent.bind(value) });
}

function checkedStorage(value) {
  if (!value || typeof value !== 'object') throw lifecycleError('storage_required');
  if (typeof value.coordinate !== 'function' || typeof value.transaction !== 'function') {
    throw lifecycleError('storage_invalid');
  }
  return Object.freeze({
    coordinate: value.coordinate.bind(value),
    transaction: value.transaction.bind(value),
  });
}

function checkedTransaction(tx) {
  if (!tx || (typeof tx !== 'object' && typeof tx !== 'function')) {
    throw lifecycleError('storage_invalid');
  }
  for (const method of TX_METHODS) {
    if (typeof tx[method] !== 'function') throw lifecycleError('storage_invalid');
  }
}

function keyringHmac(keyring, keyId, domain, value) {
  const key = keyring.keys.get(keyId);
  if (!key) throw lifecycleError('integrity_key_unknown');
  return crypto.createHmac('sha256', key)
    .update(domain, 'utf8').update('\0', 'utf8').update(canonicalStringify(value), 'utf8')
    .digest('hex');
}

function verifyKeyringMac(keyring, keyId, domain, value, actual, code) {
  let expected;
  try { expected = keyringHmac(keyring, keyId, domain, value); }
  catch { throw lifecycleError(code); }
  if (!safeHexEqual(expected, actual)) throw lifecycleError(code);
}

function checkedPurposeKeyId(value, purpose, code) {
  if (!validPurposeKeyId(String(value || ''), purpose)) throw lifecycleError(code);
  return value;
}

function checkedMacKey(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) {
    throw lifecycleError('integrity_keyring_invalid');
  }
  return Buffer.from(value);
}

function checkedFunction(value, code) {
  if (typeof value !== 'function') throw lifecycleError(code);
  return value;
}

function checkedOptionalFunction(value, fallback, code) {
  return value === undefined ? fallback : checkedFunction(value, code);
}

function boundedSnapshot(value, maxBytes, maxDepth, code) {
  try {
    preflightValue(value, maxBytes, maxDepth);
    const serialized = canonicalStringify(value);
    if (Buffer.byteLength(serialized, 'utf8') > maxBytes) throw new Error('too large');
    return JSON.parse(serialized);
  } catch {
    throw lifecycleError(code);
  }
}

function preflightValue(root, maxBytes, maxDepth) {
  const active = new Set();
  const state = { bytes: 0, nodes: 0 };
  const visit = (value, depth) => {
    state.nodes += 1;
    if (state.nodes > 50_000 || depth > maxDepth) throw new Error('invalid value');
    if (value === null || typeof value === 'boolean') {
      state.bytes += 5;
    } else if (typeof value === 'string') {
      state.bytes += Buffer.byteLength(value, 'utf8') + 2;
    } else if (typeof value === 'number') {
      if (!Number.isFinite(value) || !Number.isSafeInteger(value)) throw new Error('invalid number');
      state.bytes += 24;
    } else if (Array.isArray(value)) {
      if (active.has(value) || Object.getOwnPropertySymbols(value).length) {
        throw new Error('invalid array');
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
          throw new Error('invalid array');
        }
      }
      const extra = Object.keys(descriptors).filter((key) => key !== 'length'
        && !/^(0|[1-9]\d*)$/.test(key));
      if (extra.length) throw new Error('invalid array');
      active.add(value);
      for (const item of value) visit(item, depth + 1);
      active.delete(value);
      state.bytes += value.length + 2;
    } else if (isPlainObject(value)) {
      if (active.has(value) || Object.getOwnPropertySymbols(value).length) {
        throw new Error('invalid object');
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      active.add(value);
      for (const [key, descriptor] of Object.entries(descriptors)) {
        if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          throw new Error('invalid property');
        }
        state.bytes += Buffer.byteLength(key, 'utf8') + 3;
        visit(descriptor.value, depth + 1);
      }
      active.delete(value);
      state.bytes += Object.keys(descriptors).length + 2;
    } else {
      throw new Error('invalid value');
    }
    if (state.bytes > maxBytes) throw new Error('too large');
  };
  visit(root, 0);
}

function canonicalStringify(value) {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isPlainObject(value)) {
    const output = {};
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
    return output;
  }
  return value;
}

function clone(value) {
  if (value === undefined) return undefined;
  return JSON.parse(canonicalStringify(value));
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function canonicalEqual(left, right) {
  try { return canonicalStringify(left) === canonicalStringify(right); }
  catch { return false; }
}

function digest(value) {
  return crypto.createHash('sha256').update(canonicalStringify(value), 'utf8').digest('hex');
}

function digestBytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function omit(value, keys) {
  const omitted = new Set(keys);
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    if (!omitted.has(key)) output[key] = clone(item);
  }
  return output;
}

function assertObjectKeys(value, expectedKeys, code) {
  if (!isPlainObject(value)) throw lifecycleError(code);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) throw lifecycleError(code);
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function checkedIso(value, code) {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw lifecycleError(code);
  }
  const time = Date.parse(value);
  if (!Number.isFinite(time) || time < MIN_TIME_MS || time > MAX_TIME_MS
      || new Date(time).toISOString() !== value) throw lifecycleError(code);
  return time;
}

function checkedNow(value) {
  if (!Number.isSafeInteger(value) || value < MIN_TIME_MS || value > MAX_TIME_MS) {
    throw lifecycleError('clock_invalid');
  }
  return value;
}

function canonicalTime(value) {
  return new Date(checkedNow(value)).toISOString();
}

function checkedGeneratedUuid(value) {
  if (!UUID_RE.test(String(value || ''))) throw lifecycleError('uuid_generator_invalid');
  return value;
}

function safeHexEqual(left, right) {
  if (!SHA256_RE.test(String(left || '')) || !SHA256_RE.test(String(right || ''))) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function lifecycleError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

module.exports = {
  ACTIONS,
  AUTHORITY_MANIFEST_VERSION,
  AUTHORITY_PURPOSES,
  CREDENTIAL_PURPOSES,
  INTEGRITY_PURPOSE,
  MANUAL_ACTOR_ROLES,
  MANUAL_REASON_CODES,
  MAX_ACK_AGE_MS,
  MAX_AUTH_EVENT_AGE_MS,
  MAX_STEP_UP_AGE_MS,
  MAX_TARGET_CONFIRMATION_AGE_MS,
  OWNER_ATTESTATION_PURPOSE,
  OWNER_ATTESTATION_SIGNATURE_DOMAIN,
  SCHEMA_VERSION,
  STAGES,
  TARGET_CONFIRMATION_PURPOSE,
  WITNESS_PURPOSE,
  createVendorEntitlementLifecycle,
};
