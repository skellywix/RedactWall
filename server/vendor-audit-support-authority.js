'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const {
  KEY_PURPOSES,
  keyFingerprint,
  normalizePublicKeys,
} = require('./vendor-signed-artifact');
const {
  customerAuditResponseClaim,
  isCustomerAuditResponseKeyRegistry,
  verifyCustomerAuditResponse,
} = require('./customer-audit-response');
const {
  isReferenceVendorAuditSupportStore,
} = require('./vendor-audit-support-sqlite');
const {
  CANCELLATION_KIND,
  CANCELLATION_SIGNATURE_DOMAIN,
  payloadDigest: auditSupportPayloadDigest,
  signAuditSupportCancellation,
  signAuditSupportRequest,
} = require('./audit-support-control-artifacts');

const REQUEST_KIND = protocol.CHANNEL_KINDS.AUDIT_REQUEST;
const MAX_STEP_UP_AGE_MS = 5 * 60 * 1000;
const MAX_AUTH_EVENT_AGE_MS = 15 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 60 * 1000;
const MAX_REQUEST_WINDOW_MS = 24 * 60 * 60 * 1000;
const CUSTOMER_REGISTRY_BRAND = Symbol('authenticated-customer-registry-reference');
const OWNER_VERIFIER_BRAND = Symbol('owner-audit-step-up-verifier-reference');
const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const IDEMPOTENCY_RE = /^[A-Za-z0-9_-]{16,128}$/;
const OPAQUE_REF_RE = /^[a-z0-9][A-Za-z0-9_-]{19,127}$/;
const OWNER_ROLES = new Set(['vendor_owner', 'vendor_security_admin', 'vendor_support_analyst']);
const REQUEST_TYPE_FIELDS = Object.freeze({
  integrity_status: new Set(['integrity_status', 'coarse_timestamp']),
  bounded_event_summary: new Set([
    'event_type', 'outcome', 'component', 'policy_version', 'catalog_version',
    'entitlement_version', 'coarse_timestamp', 'count', 'integrity_status',
  ]),
  deployment_attestation: new Set([
    'policy_version', 'catalog_version', 'entitlement_version',
    'coarse_timestamp', 'integrity_status',
  ]),
});

function createReferenceVendorAuditSupportAuthority(options = {}) {
  assertReferenceRuntime();
  const authorityRegistry = checkedAuthorityRegistry(options.authorityRegistry);
  const signingSlot = checkedSigningSlot(options.signingSlot, authorityRegistry);
  const context = Object.freeze({
    authorityRegistry,
    signingSlot,
    customerRegistry: checkedCustomerRegistry(options.customerRegistry),
    ownerStepUpVerifier: checkedOwnerVerifier(options.ownerStepUpVerifier),
    responseKeyRegistry: checkedResponseRegistry(options.responseKeyRegistry),
    store: checkedStore(options.store),
    now: checkedFunction(options.now, Date.now, 'audit_support_clock_invalid'),
    messageId: checkedFunction(options.messageId, crypto.randomUUID,
      'audit_support_message_id_generator_invalid'),
  });
  return Object.freeze({
    issue: (command) => issue(context, command),
    markDelivered: (command) => transition(context, command, 'delivered'),
    expire: (command) => transition(context, command, 'expired'),
    revoke: (command) => revoke(context, command),
    markCancellationDelivered: (command) => markCancellationDelivered(context, command),
    acceptResponse: (envelope) => acceptResponse(context, envelope),
    get: (requestId, requestVersion) => context.store.get(requestId, requestVersion),
    claimDeliveries: (limit, now) => context.store.claimOutbox(limit, now),
    markDeliveryRetry: (...args) => context.store.markOutboxRetry(...args),
    auditEvents: (cursor) => context.store.auditEvents(cursor),
    readiness: (now) => context.store.readiness(now),
  });
}

function createProductionVendorAuditSupportAuthority() {
  throw authorityError('audit_support_owner_step_up_adapter_unavailable');
}

function createReferenceAuthenticatedCustomerRegistry(options = {}) {
  assertReferenceRuntime();
  const input = exactOptionalObject(options, ['records'], 'audit_support_customer_registry_invalid');
  if (!Array.isArray(input.records) || input.records.length < 1 || input.records.length > 100_000) {
    throw authorityError('audit_support_customer_registry_invalid');
  }
  const records = new Map();
  for (const raw of input.records) {
    const record = checkedCustomerRegistryRecord(raw);
    const key = scopeKey(record.customerId, record.deploymentId);
    if (records.has(key)) throw authorityError('audit_support_customer_scope_duplicate');
    records.set(key, record);
  }
  const registry = {
    resolve(customerId, deploymentId) {
      checkedScope(customerId, deploymentId);
      const record = records.get(scopeKey(customerId, deploymentId));
      if (!record) throw authorityError('audit_support_customer_scope_unknown');
      return record;
    },
  };
  Object.defineProperty(registry, CUSTOMER_REGISTRY_BRAND, { value: true });
  return Object.freeze(registry);
}

function createReferenceOwnerAuditStepUpVerifier(options = {}) {
  assertReferenceRuntime();
  const input = exactOptionalObject(options, ['events'], 'audit_support_owner_verifier_invalid');
  if (!Array.isArray(input.events) || input.events.length < 1 || input.events.length > 100_000) {
    throw authorityError('audit_support_owner_verifier_invalid');
  }
  const events = new Map();
  for (const raw of input.events) {
    const event = checkedOwnerAuthEvent(raw);
    if (events.has(event.authEventId)) throw authorityError('audit_support_owner_verifier_invalid');
    events.set(event.authEventId, event);
  }
  const verifier = { verify: (query) => verifyOwnerEvent(events, query) };
  Object.defineProperty(verifier, OWNER_VERIFIER_BRAND, { value: true });
  return Object.freeze(verifier);
}

function issue(context, rawCommand) {
  const command = checkedIssueCommand(rawCommand);
  const operationDigest = commandDigest('audit_support.issue', command);
  const replay = context.store.commandReplay({
    idempotencyKey: command.idempotencyKey, operationDigest,
  });
  if (replay) return replayWithArtifact(context.store, replay, 'signedArtifact');
  const nowMs = context.store.observeTrustedTime(checkedClock(context.now()));
  const scope = context.customerRegistry.resolve(command.customerId, command.deploymentId);
  if (scope.status !== 'active') throw authorityError('audit_support_customer_not_active');
  assertRequestWindow(command, nowMs);
  assertRequestFieldScope(command.requestType, command.fields);
  const proof = context.ownerStepUpVerifier.verify(ownerQuery(
    command, 'audit_support.issue', operationDigest, nowMs,
  ));
  const issuedAt = new Date(nowMs).toISOString();
  const payload = requestPayload(context, command, issuedAt);
  const signedArtifact = signAuditSupportRequest(payload, context.signingSlot);
  const requestDigest = auditSupportPayloadDigest(
    payload, 'redactwall.vendor-audit-request.v2',
  );
  const record = issuedRecord(
    command, signedArtifact, requestDigest, issuedAt, proof, scope.auditRef,
  );
  const artifactDigest = sha256(protocol.canonicalJson(signedArtifact));
  const result = context.store.issue({
    idempotencyKey: command.idempotencyKey,
    operationDigest,
    record,
    outbox: {
      messageId: payload.messageId,
      requestId: payload.requestId,
      requestVersion: payload.requestVersion,
      requestDigest,
      artifactDigest,
      document: signedArtifact,
      documentKind: REQUEST_KIND,
      createdAt: issuedAt,
    },
    auditEvent: vendorAuditEvent(
      'issued', 'issued', record, issuedAt, proof.auditRef, 0,
    ),
  });
  const stored = context.store.get(command.requestId, command.requestVersion);
  return deepFreeze({ ...result, signedArtifact: stored.signedArtifact });
}

function transition(context, rawCommand, targetStatus) {
  const command = checkedTransitionCommand(rawCommand, targetStatus);
  const operationDigest = commandDigest(`audit_support.${targetStatus}`, command);
  const replay = context.store.commandReplay({
    idempotencyKey: command.idempotencyKey, operationDigest,
  });
  if (replay) return replay;
  const nowMs = context.store.observeTrustedTime(checkedClock(context.now()));
  const occurredAt = new Date(nowMs).toISOString();
  const record = context.store.get(command.requestId, command.requestVersion);
  requireRecordBinding(record, command);
  if (targetStatus === 'delivered') {
    assertDeliveryReceipt(record, command, nowMs, false);
  }
  return context.store.transition({
    ...command,
    operationDigest,
    occurredAt,
    targetStatus,
    auditEvent: vendorAuditEvent(
      targetStatus, targetStatus, record, occurredAt, null, 0,
      targetStatus === 'delivered' ? acknowledgementEvidence(command.receipt) : null,
    ),
  });
}

function revoke(context, rawCommand) {
  const command = checkedRevokeCommand(rawCommand);
  const operationDigest = commandDigest('audit_support.revoke', command);
  const replay = context.store.commandReplay({
    idempotencyKey: command.idempotencyKey, operationDigest,
  });
  if (replay) return replayWithArtifact(context.store, replay, 'cancellationArtifact');
  const nowMs = context.store.observeTrustedTime(checkedClock(context.now()));
  const occurredAt = new Date(nowMs).toISOString();
  const record = context.store.get(command.requestId, command.requestVersion);
  requireRecordBinding(record, command);
  const proof = context.ownerStepUpVerifier.verify({
    action: 'audit_support.revoke',
    authEventId: command.authEventId,
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    nowMs,
    operationDigest,
    purposeCode: record.purposeCode,
  });
  const payload = cancellationPayload(record, occurredAt);
  const signedCancellation = signAuditSupportCancellation(payload, context.signingSlot);
  const cancellationDigest = auditSupportPayloadDigest(
    payload, CANCELLATION_SIGNATURE_DOMAIN,
  );
  const artifactDigest = sha256(protocol.canonicalJson(signedCancellation));
  const result = context.store.revoke({
    cancellation: {
      cancellationDigest,
      issuedAt: occurredAt,
      signedArtifact: signedCancellation,
    },
    cancellationOutbox: {
      artifactDigest,
      createdAt: occurredAt,
      document: signedCancellation,
      documentKind: CANCELLATION_KIND,
      messageId: payload.messageId,
      requestDigest: record.requestDigest,
      requestId: record.requestId,
      requestVersion: record.requestVersion,
    },
    idempotencyKey: command.idempotencyKey,
    operationDigest,
    requestDigest: command.requestDigest,
    requestId: command.requestId,
    requestVersion: command.requestVersion,
    occurredAt,
    targetStatus: 'revoked',
    auditEvent: vendorAuditEvent('revoked', 'revoked', record, occurredAt, proof.auditRef, 0),
  });
  const stored = context.store.get(command.requestId, command.requestVersion);
  return deepFreeze({ ...result, signedCancellation: stored.cancellationArtifact });
}

function markCancellationDelivered(context, rawCommand) {
  const command = checkedCancellationDeliveryCommand(rawCommand);
  const operationDigest = commandDigest('audit_support.cancellation_delivered', command);
  const replay = context.store.commandReplay({
    idempotencyKey: command.idempotencyKey, operationDigest,
  });
  if (replay) return replay;
  const nowMs = context.store.observeTrustedTime(checkedClock(context.now()));
  const occurredAt = new Date(nowMs).toISOString();
  const record = context.store.get(command.requestId, command.requestVersion);
  requireRecordBinding(record, command);
  assertDeliveryReceipt(record, command, nowMs, true);
  return context.store.markCancellationDelivered({
    ...command,
    auditEvent: vendorAuditEvent(
      'cancellation_delivered', 'delivered', record, occurredAt, null, 0,
      acknowledgementEvidence(command.receipt),
    ),
    occurredAt,
    operationDigest,
  });
}

function cancellationPayload(record, issuedAt) {
  return deepFreeze({
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: deterministicMessageId(
      `audit-cancellation\0${record.requestDigest}\0${record.requestVersion}\0${issuedAt}`,
    ),
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    kind: CANCELLATION_KIND,
    requestId: record.requestId,
    requestVersion: record.requestVersion,
    requestDigest: record.requestDigest,
    issuedAt,
    reasonCode: 'vendor_revoked',
  });
}

function acceptResponse(context, envelope) {
  const claim = customerAuditResponseClaim(envelope);
  const replay = context.store.responseReplay(claim);
  if (replay) return replay;
  const nowMs = checkedClock(context.now());
  const verified = verifyCustomerAuditResponse(envelope, context.responseKeyRegistry);
  const response = verified.payload;
  if (Date.parse(response.respondedAt) > nowMs + MAX_FUTURE_SKEW_MS) {
    throw authorityError('audit_support_response_time_invalid');
  }
  const record = context.store.get(response.requestId, response.requestVersion);
  if (!record || record.requestDigest !== response.requestDigest
      || record.customerId !== response.customerId
      || record.deploymentId !== response.deploymentId) {
    throw authorityError('audit_support_response_scope_mismatch');
  }
  const latest = context.store.getLatest(response.requestId);
  if (!latest || latest.requestVersion !== response.requestVersion
      || latest.requestDigest !== response.requestDigest) {
    throw authorityError('audit_support_response_not_current');
  }
  const respondedMs = Date.parse(response.respondedAt);
  const notBeforeMs = Date.parse(record.signedArtifact.payload.notBefore);
  const expiresMs = Date.parse(record.signedArtifact.payload.expiresAt);
  if (nowMs > expiresMs || respondedMs < notBeforeMs || respondedMs > expiresMs) {
    throw authorityError('audit_support_response_expired');
  }
  const events = [
    vendorAuditEvent(
      'customer_decision', response.decision, record, response.respondedAt,
      response.localApprovalRef, 0,
    ),
    vendorAuditEvent(
      'response_received', response.status, record, response.respondedAt,
      response.localApprovalRef, response.summaries.length,
    ),
  ];
  return context.store.acceptResponse({
    auditEvents: events,
    decision: response.decision,
    localApprovalRef: response.localApprovalRef,
    messageId: response.messageId,
    receivedTimeMs: nowMs,
    requestDigest: response.requestDigest,
    requestId: response.requestId,
    requestVersion: response.requestVersion,
    respondedAt: response.respondedAt,
    responseDigest: verified.responseDigest,
    responseKeyId: verified.keyId,
    responseSignatureDomain: verified.signatureDomain,
    responseStatus: response.status,
    summaryCount: response.summaries.length,
  });
}

function requestPayload(context, command, issuedAt) {
  const messageId = context.messageId();
  checkedUuid(messageId, 'audit_support_message_id_invalid');
  const candidate = {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId,
    customerId: command.customerId,
    deploymentId: command.deploymentId,
    kind: REQUEST_KIND,
    requestId: command.requestId,
    requestVersion: command.requestVersion,
    requestType: command.requestType,
    purposeCode: command.purposeCode,
    notBefore: command.notBefore,
    expiresAt: command.expiresAt,
    maxRecords: command.maxRecords,
    fields: command.fields,
    issuedAt,
  };
  try {
    const shared = { ...candidate };
    delete shared.issuedAt;
    protocol.assertChannel(shared, REQUEST_KIND);
    return deepFreeze(candidate);
  }
  catch { throw authorityError('audit_support_request_invalid'); }
}

function issuedRecord(command, signedArtifact, requestDigest, issuedAt, proof, scopeRef) {
  return deepFreeze({
    schemaVersion: 1,
    authorization: proof,
    cancellationAcknowledgementDigest: null,
    cancellationAcknowledgementKeyId: null,
    cancellationAppliedAt: null,
    cancellationArtifact: null,
    cancellationDeliveredAt: null,
    cancellationDigest: null,
    cancellationIssuedAt: null,
    customerDecision: null,
    customerId: command.customerId,
    deliveryAcknowledgementDigest: null,
    deliveryAcknowledgementKeyId: null,
    deliveryAppliedAt: null,
    deliveredAt: null,
    deploymentId: command.deploymentId,
    issuedAt,
    purposeCode: command.purposeCode,
    requestDigest,
    requestId: command.requestId,
    requestVersion: command.requestVersion,
    respondedAt: null,
    responseDigest: null,
    responseKeyId: null,
    responseMessageId: null,
    responseSignatureDomain: null,
    revision: 1,
    scopeRef,
    signedArtifact,
    status: 'issued',
    terminatedAt: null,
  });
}

function vendorAuditEvent(
  eventType, outcome, record, occurredAt, authorizationRef, count, evidence = null,
) {
  return Object.freeze({
    acknowledgementAppliedAt: evidence?.appliedAt || null,
    acknowledgementDigest: evidence?.digest || null,
    acknowledgementKeyId: evidence?.keyId || null,
    authorizationRef,
    count,
    eventType,
    occurredAt,
    outcome,
    requestDigest: record.requestDigest,
    requestVersion: record.requestVersion,
    scopeDigest: sha256(`${record.customerId}\0${record.deploymentId}`),
  });
}

function acknowledgementEvidence(receipt) {
  return Object.freeze({
    appliedAt: receipt.receivedAt,
    digest: sha256(protocol.canonicalJson(receipt)),
    keyId: receipt.acknowledgementKeyId,
  });
}

function createOwnerProof(event) {
  return Object.freeze({ authEventId: event.authEventId, auditRef: event.auditRef });
}

function verifyOwnerEvent(events, rawQuery) {
  const query = exactObject(rawQuery, [
    'action', 'authEventId', 'customerId', 'deploymentId', 'nowMs',
    'operationDigest', 'purposeCode',
  ], 'audit_support_authorization_denied');
  const event = events.get(query.authEventId);
  if (!event || !ownerEventMatches(event, query)) {
    throw authorityError('audit_support_authorization_denied');
  }
  const authenticatedMs = Date.parse(event.authenticatedAt);
  const stepUpMs = Date.parse(event.stepUpAt);
  if (!Number.isSafeInteger(query.nowMs) || query.nowMs < 0
      || authenticatedMs > query.nowMs + MAX_FUTURE_SKEW_MS
      || query.nowMs - authenticatedMs > MAX_AUTH_EVENT_AGE_MS
      || stepUpMs > authenticatedMs || query.nowMs - stepUpMs > MAX_STEP_UP_AGE_MS) {
    throw authorityError('audit_support_step_up_required');
  }
  return createOwnerProof(event);
}

function ownerEventMatches(event, query) {
  return event.action === query.action
    && event.authEventId === query.authEventId
    && event.customerId === query.customerId
    && event.deploymentId === query.deploymentId
    && event.operationDigest === query.operationDigest
    && event.purposeCode === query.purposeCode
    && event.credentialPurpose === 'vendor_audit_support'
    && OWNER_ROLES.has(event.role)
    && !(event.action === 'audit_support.revoke' && event.role === 'vendor_support_analyst');
}

function checkedOwnerAuthEvent(raw) {
  const value = exactObject(raw, [
    'action', 'auditRef', 'authEventId', 'authenticatedAt', 'credentialPurpose',
    'customerId', 'deploymentId', 'operationDigest', 'principalRef', 'purposeCode',
    'role', 'stepUpAt',
  ], 'audit_support_owner_verifier_invalid');
  if (!['audit_support.issue', 'audit_support.revoke'].includes(value.action)
      || value.credentialPurpose !== 'vendor_audit_support'
      || !OWNER_ROLES.has(value.role)
      || !UUID_RE.test(String(value.authEventId || ''))
      || !SHA256_RE.test(String(value.operationDigest || ''))
      || !SHA256_RE.test(String(value.principalRef || ''))
      || !OPAQUE_REF_RE.test(String(value.auditRef || ''))
      || !['customer_support', 'security_incident', 'compliance_assistance']
        .includes(value.purposeCode)) throw authorityError('audit_support_owner_verifier_invalid');
  checkedScope(value.customerId, value.deploymentId);
  canonicalIso(value.authenticatedAt, 'audit_support_owner_verifier_invalid');
  canonicalIso(value.stepUpAt, 'audit_support_owner_verifier_invalid');
  return deepFreeze(clone(value));
}

function checkedCustomerRegistryRecord(raw) {
  const value = exactObject(raw, [
    'auditRef', 'customerId', 'deploymentId', 'generation', 'status',
  ], 'audit_support_customer_registry_invalid');
  checkedScope(value.customerId, value.deploymentId);
  if (!Number.isSafeInteger(value.generation) || value.generation < 1
      || !['provisioning', 'verified', 'active', 'suspended', 'churned'].includes(value.status)
      || !OPAQUE_REF_RE.test(String(value.auditRef || ''))) {
    throw authorityError('audit_support_customer_registry_invalid');
  }
  return deepFreeze(clone(value));
}

function checkedIssueCommand(raw) {
  const value = exactObject(raw, [
    'authEventId', 'customerId', 'deploymentId', 'expiresAt', 'fields',
    'idempotencyKey', 'maxRecords', 'notBefore', 'purposeCode', 'requestId',
    'requestType', 'requestVersion',
  ], 'audit_support_issue_invalid');
  checkedUuid(value.authEventId, 'audit_support_issue_invalid');
  checkedScope(value.customerId, value.deploymentId);
  checkedUuid(value.requestId, 'audit_support_issue_invalid');
  checkedVersion(value.requestVersion, 'audit_support_issue_invalid');
  checkedIdempotency(value.idempotencyKey);
  canonicalIso(value.notBefore, 'audit_support_issue_invalid');
  canonicalIso(value.expiresAt, 'audit_support_issue_invalid');
  if (!['integrity_status', 'bounded_event_summary', 'deployment_attestation']
    .includes(value.requestType)
      || !['customer_support', 'security_incident', 'compliance_assistance']
        .includes(value.purposeCode)
      || !Number.isSafeInteger(value.maxRecords) || value.maxRecords < 1
      || value.maxRecords > 10_000 || !Array.isArray(value.fields)) {
    throw authorityError('audit_support_issue_invalid');
  }
  return deepFreeze(clone(value));
}

function checkedTransitionCommand(raw, targetStatus) {
  const keys = ['idempotencyKey', 'requestDigest', 'requestId', 'requestVersion'];
  if (targetStatus === 'delivered') {
    keys.push('artifactDigest', 'claimToken', 'messageId', 'receipt');
  }
  const value = exactObject(raw, keys, 'audit_support_transition_invalid');
  checkedIdempotency(value.idempotencyKey);
  checkedRequestBinding(value, 'audit_support_transition_invalid');
  if (targetStatus === 'delivered') {
    checkedUuid(value.messageId, 'audit_support_transition_invalid');
    checkedUuid(value.claimToken, 'audit_support_transition_invalid');
    if (!SHA256_RE.test(String(value.artifactDigest || ''))) {
      throw authorityError('audit_support_transition_invalid');
    }
    value.receipt = checkedDeliveryReceipt(value.receipt, false,
      'audit_support_transition_invalid');
  }
  return value;
}

function checkedRevokeCommand(raw) {
  const value = exactObject(raw, [
    'authEventId', 'idempotencyKey', 'requestDigest', 'requestId', 'requestVersion',
  ], 'audit_support_revoke_invalid');
  checkedUuid(value.authEventId, 'audit_support_revoke_invalid');
  checkedIdempotency(value.idempotencyKey);
  checkedRequestBinding(value, 'audit_support_revoke_invalid');
  return value;
}

function checkedCancellationDeliveryCommand(raw) {
  const value = exactObject(raw, [
    'artifactDigest', 'cancellationDigest', 'idempotencyKey', 'messageId',
    'claimToken', 'receipt', 'requestDigest', 'requestId', 'requestVersion',
  ], 'audit_support_cancellation_delivery_invalid');
  checkedIdempotency(value.idempotencyKey);
  checkedRequestBinding(value, 'audit_support_cancellation_delivery_invalid');
  checkedUuid(value.messageId, 'audit_support_cancellation_delivery_invalid');
  checkedUuid(value.claimToken, 'audit_support_cancellation_delivery_invalid');
  if (!SHA256_RE.test(String(value.artifactDigest || ''))
      || !SHA256_RE.test(String(value.cancellationDigest || ''))) {
    throw authorityError('audit_support_cancellation_delivery_invalid');
  }
  value.receipt = checkedDeliveryReceipt(
    value.receipt, true, 'audit_support_cancellation_delivery_invalid',
  );
  return value;
}

function checkedDeliveryReceipt(raw, cancellation, code) {
  const keys = [
    'accepted', 'acknowledgementKeyId', 'acknowledgementMac', 'artifactDigest',
    'customerId', 'deploymentId', 'messageId', 'receivedAt', 'requestDigest',
    'requestId', 'requestVersion',
  ];
  if (cancellation) keys.push('cancellationDigest');
  const value = exactObject(raw, keys, code);
  checkedScope(value.customerId, value.deploymentId);
  checkedUuid(value.messageId, code);
  checkedUuid(value.requestId, code);
  checkedVersion(value.requestVersion, code);
  canonicalIso(value.receivedAt, code);
  if (value.accepted !== true || !SHA256_RE.test(String(value.artifactDigest || ''))
      || !SHA256_RE.test(String(value.requestDigest || ''))
      || !/^rw-audit-ack-[a-z0-9][a-z0-9_.-]{0,70}$/.test(
        String(value.acknowledgementKeyId || ''),
      )
      || !/^[A-Za-z0-9_-]{43}$/.test(String(value.acknowledgementMac || ''))
      || (cancellation && !SHA256_RE.test(String(value.cancellationDigest || '')))) {
    throw authorityError(code);
  }
  return value;
}

function assertDeliveryReceipt(record, command, nowMs, cancellation) {
  const receipt = command.receipt;
  const earliest = cancellation ? record.cancellationIssuedAt : record.issuedAt;
  const latest = cancellation ? null : record.signedArtifact.payload.expiresAt;
  if (receipt.customerId !== record.customerId
      || receipt.deploymentId !== record.deploymentId
      || receipt.messageId !== command.messageId
      || receipt.artifactDigest !== command.artifactDigest
      || receipt.requestDigest !== record.requestDigest
      || receipt.requestId !== record.requestId
      || receipt.requestVersion !== record.requestVersion
      || Date.parse(receipt.receivedAt) < Date.parse(earliest)
      || (latest !== null && Date.parse(receipt.receivedAt) >= Date.parse(latest))
      || Date.parse(receipt.receivedAt) > nowMs + MAX_FUTURE_SKEW_MS
      || (cancellation && receipt.cancellationDigest !== record.cancellationDigest)) {
    throw authorityError(cancellation
      ? 'audit_support_cancellation_delivery_invalid' : 'audit_support_transition_invalid');
  }
}

function assertRequestWindow(command, nowMs) {
  const start = Date.parse(command.notBefore);
  const end = Date.parse(command.expiresAt);
  if (end <= start || end - start > MAX_REQUEST_WINDOW_MS
      || Math.abs(start - nowMs) > MAX_FUTURE_SKEW_MS) {
    throw authorityError('audit_support_request_window_invalid');
  }
}

function assertRequestFieldScope(requestType, fields) {
  const allowed = REQUEST_TYPE_FIELDS[requestType];
  if (!allowed || fields.length < 1 || fields.length > 16
      || new Set(fields).size !== fields.length
      || fields.some((field) => !allowed.has(field))) {
    throw authorityError('audit_support_scope_rejected');
  }
}

function ownerQuery(command, action, operationDigest, nowMs) {
  return {
    action,
    authEventId: command.authEventId,
    customerId: command.customerId,
    deploymentId: command.deploymentId,
    nowMs,
    operationDigest,
    purposeCode: command.purposeCode,
  };
}

function requireRecordBinding(record, command) {
  if (!record || record.requestDigest !== command.requestDigest) {
    throw authorityError('audit_support_request_not_current');
  }
}

function replayWithArtifact(store, replay, field) {
  const record = store.get(replay.requestId, replay.requestVersion);
  if (!record || !record[field]) throw authorityError('audit_support_command_replay_invalid');
  const outputField = field === 'signedArtifact' ? 'signedArtifact' : 'signedCancellation';
  return deepFreeze({ ...replay, [outputField]: record[field] });
}

function checkedAuthorityRegistry(value) {
  if (!value || typeof value.activePublicKeys !== 'function'
      || typeof value.assertPublicKey !== 'function') {
    throw authorityError('audit_support_authority_manifest_required');
  }
  const keys = value.activePublicKeys(KEY_PURPOSES.AUDIT_REQUEST);
  try {
    normalizePublicKeys(keys, {
      authorityRegistry: value,
      purpose: KEY_PURPOSES.AUDIT_REQUEST,
      strictPurpose: true,
    });
  } catch { throw authorityError('audit_support_authority_manifest_invalid'); }
  return value;
}

function checkedSigningSlot(raw, authorityRegistry) {
  const value = exactObject(raw, ['keyId', 'privateKey'], 'audit_support_signing_slot_invalid');
  let privateKey;
  try {
    privateKey = value.privateKey instanceof crypto.KeyObject
      ? value.privateKey : crypto.createPrivateKey(value.privateKey);
  }
  catch { throw authorityError('audit_support_signing_slot_invalid'); }
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw authorityError('audit_support_signing_slot_invalid');
  }
  const publicKey = crypto.createPublicKey(privateKey);
  try {
    authorityRegistry.assertPublicKey(
      KEY_PURPOSES.AUDIT_REQUEST, value.keyId, keyFingerprint(publicKey),
    );
  } catch { throw authorityError('audit_support_signing_slot_not_active'); }
  return Object.freeze({ keyId: value.keyId, privateKey });
}

function checkedCustomerRegistry(value) {
  if (!value || value[CUSTOMER_REGISTRY_BRAND] !== true || typeof value.resolve !== 'function') {
    throw authorityError('audit_support_customer_registry_invalid');
  }
  return value;
}
function checkedOwnerVerifier(value) {
  if (!value || value[OWNER_VERIFIER_BRAND] !== true || typeof value.verify !== 'function') {
    throw authorityError('audit_support_owner_verifier_invalid');
  }
  return value;
}
function checkedResponseRegistry(value) {
  if (!isCustomerAuditResponseKeyRegistry(value)) {
    throw authorityError('audit_support_response_registry_invalid');
  }
  return value;
}
function checkedStore(value) {
  if (!isReferenceVendorAuditSupportStore(value)) {
    throw authorityError('audit_support_store_invalid');
  }
  return value;
}

function commandDigest(action, command) {
  return sha256(protocol.canonicalJson({ action, command }));
}
function checkedRequestBinding(value, code) {
  checkedUuid(value.requestId, code);
  checkedVersion(value.requestVersion, code);
  if (!SHA256_RE.test(String(value.requestDigest || ''))) throw authorityError(code);
}
function checkedScope(customerId, deploymentId) {
  if (!CUSTOMER_ID_RE.test(String(customerId || ''))
      || !isDeploymentId(deploymentId)) {
    throw authorityError('audit_support_scope_invalid');
  }
}
function checkedUuid(value, code) {
  if (!UUID_RE.test(String(value || ''))) throw authorityError(code);
  return value;
}
function checkedVersion(value, code) {
  if (!Number.isSafeInteger(value) || value < 1) throw authorityError(code);
  return value;
}
function checkedIdempotency(value) {
  if (!IDEMPOTENCY_RE.test(String(value || ''))) {
    throw authorityError('audit_support_idempotency_invalid');
  }
}
function checkedClock(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw authorityError('audit_support_clock_invalid');
  return value;
}
function checkedFunction(value, fallback, code) {
  const output = value === undefined ? fallback : value;
  if (typeof output !== 'function') throw authorityError(code);
  return output;
}
function exactOptionalObject(value, allowed, code) {
  if (!plainObject(value) || Object.keys(value).some((key) => !allowed.includes(key))) {
    throw authorityError(code);
  }
  return descriptorValues(value, code);
}
function exactObject(value, keys, code) {
  if (!plainObject(value)
      || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) {
    throw authorityError(code);
  }
  return descriptorValues(value, code);
}
function descriptorValues(value, code) {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set
      || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true)) {
    throw authorityError(code);
  }
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
}
function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function canonicalIso(value, code) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw authorityError(code);
  return value;
}
function scopeKey(customerId, deploymentId) { return `${customerId}\0${deploymentId}`; }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function deterministicMessageId(value) {
  const bytes = crypto.createHash('sha256').update(value).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

function authorityError(code) {
  const error = new Error('vendor audit support authority rejected');
  error.code = code;
  return error;
}

function assertReferenceRuntime() {
  if (process.env.NODE_ENV === 'production') {
    throw authorityError('audit_support_reference_runtime_forbidden');
  }
}

module.exports = {
  createProductionVendorAuditSupportAuthority,
  createReferenceAuthenticatedCustomerRegistry,
  createReferenceOwnerAuditStepUpVerifier,
  createReferenceVendorAuditSupportAuthority,
};
