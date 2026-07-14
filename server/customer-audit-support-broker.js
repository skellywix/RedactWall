'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const {
  KEY_PURPOSES,
} = require('./vendor-signed-artifact');
const {
  verifyAuditSupportCancellation,
  verifyAuditSupportRequest,
} = require('./audit-support-control-verifier');
const {
  isAuditAcknowledgementSigner,
} = require('./customer-audit-support-acknowledgement');
const {
  isCustomerAuditResponseSigner,
} = require('./customer-audit-response-signer');
const {
  isCustomerAuditSupportStore,
} = require('./customer-audit-support-store');

const RESPONSE_KIND = protocol.CHANNEL_KINDS.AUDIT_RESPONSE;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_STEP_UP_AGE_MS = 5 * 60 * 1000;
const MAX_AUTH_EVENT_AGE_MS = 15 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 60 * 1000;
const SHA256_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const LOCAL_AUDIT_REF_RE = /^local_audit_[A-Za-z0-9_-]{20,86}$/;
const REQUEST_KEY_ID_RE = /^rw-audit-request-[a-z0-9][a-z0-9_.-]{0,77}$/;
const LOCAL_AUTH_BRAND = Symbol('customer-audit-local-admin-authorizer');
const SUMMARY_PROVIDER_BRAND = Symbol('customer-audit-summary-provider');
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
const DECISION_TRANSITIONS = Object.freeze({
  pending: new Set(['approved', 'denied']),
  approved: new Set(['revoked']),
  completed: new Set(),
  denied: new Set(),
  expired: new Set(),
  revoked: new Set(),
  superseded: new Set(),
});
const RESPONSE_BINDING = Object.freeze({
  approved: Object.freeze({ status: 'completed', reasonCode: 'completed' }),
  denied: Object.freeze({ status: 'denied', reasonCode: 'customer_denied' }),
  expired: Object.freeze({ status: 'expired', reasonCode: 'request_expired' }),
  revoked: Object.freeze({ status: 'revoked', reasonCode: 'customer_revoked' }),
});

class CustomerAuditSupportBroker {
  #customerId;
  #deploymentId;
  #authorityRegistry;
  #store;
  #localAdminAuthorizer;
  #summaryProvider;
  #responseSigner;
  #now;
  #messageId;
  #acknowledgementSigner;

  constructor(options = {}) {
    assertReferenceRuntime();
    this.#customerId = checkedCustomerId(options.customerId);
    this.#deploymentId = checkedDeploymentId(options.deploymentId);
    this.#authorityRegistry = checkedAuthorityRegistry(options.authorityRegistry);
    this.#store = checkedStore(options.store);
    this.#localAdminAuthorizer = checkedLocalAuthorizer(options.localAdminAuthorizer);
    this.#summaryProvider = checkedSummaryProvider(options.summaryProvider);
    this.#responseSigner = checkedResponseSigner(
      options.responseSigner, this.#customerId, this.#deploymentId,
    );
    this.#acknowledgementSigner = checkedAcknowledgementSigner(
      options.acknowledgementSigner, this.#customerId, this.#deploymentId,
    );
    this.#now = checkedFunction(options.now, Date.now, 'audit_clock_invalid');
    this.#messageId = checkedFunction(options.messageId, crypto.randomUUID,
      'audit_message_id_generator_invalid');
  }

  receive(signedArtifact) {
    const keyId = artifactKeyId(signedArtifact, 'audit_signature_rejected');
    let historicalKeys;
    try {
      historicalKeys = this.#authorityRegistry.verificationPublicKey(
        KEY_PURPOSES.AUDIT_REQUEST, keyId,
      );
    } catch { throw brokerError('unknown_signing_key'); }
    const verified = verifyRequest(
      signedArtifact, historicalKeys, historicalAuthorityRegistry(this.#authorityRegistry),
    );
    assertBinding(verified.payload, this.#customerId, this.#deploymentId);
    assertRequestFieldScope(verified.payload);
    let receipt;
    const result = this.#store.transaction((tx) => {
      const nowMs = this.#trustedNow(tx);
      const current = tx.readLatest(verified.payload.requestId);
      const replay = versionDisposition(current, verified);
      if (replay) {
        receipt = deliveryReceipt(
          signedArtifact, verified, Date.parse(current.appliedAt), false,
          this.#acknowledgementSigner,
        );
        return replay;
      }
      assertCurrent(verified.payload, nowMs);
      if (current) {
        tx.cancelResponses(current.requestId, current.requestVersion, current.requestDigest);
      }
      supersedeCurrent(tx, current, nowMs);
      const state = requestState(verified, current, nowMs);
      receipt = deliveryReceipt(
        signedArtifact, verified, nowMs, false, this.#acknowledgementSigner,
      );
      if (!tx.insert(state)) throw brokerError('audit_request_conflict');
      tx.appendAudit(auditDescriptor('request_received', 'accepted', state, 0, nowMs, null));
      return publicState(state, false);
    });
    return deepFreeze({ ...result, receipt });
  }

  receiveCancellation(signedArtifact) {
    const keyId = artifactKeyId(signedArtifact, 'audit_cancellation_rejected');
    let historicalKeys;
    try {
      historicalKeys = this.#authorityRegistry.verificationPublicKey(
        KEY_PURPOSES.AUDIT_REQUEST, keyId,
      );
    } catch { throw brokerError('unknown_signing_key'); }
    const verified = verifyCancellation(
      signedArtifact, historicalKeys,
      historicalAuthorityRegistry(this.#authorityRegistry),
    );
    assertBinding(verified.payload, this.#customerId, this.#deploymentId);
    let receipt;
    const result = this.#store.transaction((tx) => {
      const nowMs = this.#trustedNow(tx);
      if (Date.parse(verified.payload.issuedAt) > nowMs + MAX_FUTURE_SKEW_MS) {
        throw brokerError('audit_cancellation_time_invalid');
      }
      const state = requireCurrentState(
        tx, verified.payload.requestId, verified.payload.requestVersion,
      );
      assertCancellationBinding(state, verified.payload);
      if (state.cancellationDigest === verified.payloadDigest) {
        receipt = deliveryReceipt(
          signedArtifact, verified, Date.parse(state.cancellationAppliedAt), true,
          this.#acknowledgementSigner,
        );
        return publicState(state, true);
      }
      if (state.cancellationDigest !== null) {
        throw brokerError('audit_cancellation_conflict');
      }
      const cancellationAppliedAt = isoNow(Math.max(
        nowMs, Date.parse(verified.payload.issuedAt),
      ));
      receipt = deliveryReceipt(
        signedArtifact, verified, Date.parse(cancellationAppliedAt), true,
        this.#acknowledgementSigner,
      );
      const approvalRef = tx.reference('vendor-revocation', verified.payloadDigest);
      const updated = updateState(state, {
        approvalRef,
        cancellationAppliedAt,
        cancellationArtifact: clone(signedArtifact),
        cancellationDigest: verified.payloadDigest,
        cancellationIssuedAt: verified.payload.issuedAt,
        cancellationSignatureDomain: verified.signatureDomain,
        cancellationSigningKeyId: verified.keyId,
        decidedAt: verified.payload.issuedAt,
        status: 'revoked',
      });
      if (!tx.replace(updated, state.revision)) throw brokerError('audit_request_conflict');
      tx.cancelResponses(state.requestId, state.requestVersion, state.requestDigest);
      tx.appendAudit(auditDescriptor(
        'vendor_revocation_received', 'revoked', updated, 0, nowMs, approvalRef,
      ));
      return publicState(updated, false);
    });
    return deepFreeze({ ...result, receipt });
  }

  decide(rawCommand) {
    const command = checkedDecisionCommand(rawCommand);
    const result = this.#store.transaction((tx) => {
      const nowMs = this.#trustedNow(tx);
      let state = requireCurrentState(tx, command.requestId, command.requestVersion);
      if (state.cancellationDigest !== null) throw brokerError('audit_request_revoked');
      state = expireIfNeeded(tx, state, nowMs);
      if (nowMs >= Date.parse(state.request.expiresAt)) {
        return rejectedResult('audit_request_expired');
      }
      if (state.respondedAt) throw brokerError('audit_response_already_prepared');
      const next = decisionState(command.action);
      if (!DECISION_TRANSITIONS[state.status].has(next)) {
        throw brokerError('audit_decision_invalid');
      }
      const proof = this.#localAdminAuthorizer.authorize({
        action: command.action,
        authorizationId: command.authorizationId,
        customerId: this.#customerId,
        deploymentId: this.#deploymentId,
        nowMs,
        purposeCode: state.request.purposeCode,
        requestDigest: state.requestDigest,
        requestId: state.requestId,
        requestVersion: state.requestVersion,
      });
      const decidedAt = isoNow(nowMs);
      const updated = updateState(state, {
        approvalRef: proof.auditRef,
        decidedAt,
        status: next,
      });
      if (!tx.replace(updated, state.revision)) throw brokerError('audit_request_conflict');
      tx.appendAudit(auditDescriptor(
        'customer_decision', next, updated, 0, nowMs, proof.auditRef,
      ));
      return publicState(updated, false);
    });
    return unwrapResult(result);
  }

  respond(rawCommand) {
    const command = checkedResponseCommand(rawCommand);
    const result = this.#store.transaction((tx) => {
      const nowMs = this.#trustedNow(tx);
      let state = requireCurrentState(tx, command.requestId, command.requestVersion);
      if (state.cancellationDigest !== null) throw brokerError('audit_request_revoked');
      state = expireIfNeeded(tx, state, nowMs);
      if (nowMs >= Date.parse(state.request.expiresAt)) {
        return rejectedResult('audit_request_expired');
      }
      if (state.responseEnvelope) return state.responseEnvelope;
      const binding = RESPONSE_BINDING[state.status];
      if (!binding) throw brokerError('audit_customer_approval_required');
      const summaries = state.status === 'approved'
        ? this.#summaryProvider.collect(summaryScope(state)) : [];
      assertSummaryScope(state.request, summaries);
      const respondedAt = isoNow(nowMs);
      const envelope = this.#responseSigner.sign(responsePayload(
        this.#responseContext(respondedAt), state, binding, summaries,
      ));
      const responseDigest = sha256(protocol.canonicalJson(envelope));
      const updated = updateState(state, {
        respondedAt,
        responseDigest,
        responseEnvelope: envelope,
        status: state.status === 'approved' ? 'completed' : state.status,
      });
      if (!tx.replace(updated, state.revision)
          || !tx.enqueue(envelope, responseDigest, respondedAt)) {
        throw brokerError('audit_response_conflict');
      }
      tx.appendAudit(auditDescriptor(
        'response_prepared', updated.status, updated, summaries.length, nowMs,
        updated.approvalRef,
      ));
      return envelope;
    });
    return unwrapResult(result);
  }

  getState(requestId, requestVersion) {
    checkedUuid(requestId, 'audit_request_id_invalid');
    return this.#store.transaction((tx) => {
      const nowMs = this.#trustedNow(tx);
      let state = requestVersion === undefined
        ? tx.readLatest(requestId)
        : tx.read(requestId, checkedVersion(requestVersion));
      if (!state) return null;
      state = expireIfNeeded(tx, state, nowMs);
      return publicState(state, false);
    });
  }

  auditEvents(cursor = 0) { return this.#store.auditEvents(cursor); }
  claimResponses(limit, now) { return this.#store.claimOutbox(limit, now); }
  markResponseDelivered(messageId, responseDigest, deliveredAt, claimToken) {
    return this.#store.markOutboxDelivered(
      messageId, responseDigest, deliveredAt, claimToken,
    );
  }
  markResponseRetry(messageId, responseDigest, nextAt, errorCode, claimToken) {
    return this.#store.markOutboxRetry(
      messageId, responseDigest, nextAt, errorCode, claimToken,
    );
  }

  #trustedNow(tx) {
    const nowMs = this.#now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw brokerError('audit_clock_invalid');
    return tx.trustedTime(nowMs, MAX_CLOCK_SKEW_MS);
  }

  #responseContext(respondedAt) {
    const messageId = this.#messageId();
    checkedUuid(messageId, 'audit_message_id_invalid');
    return Object.freeze({
      customerId: this.#customerId,
      deploymentId: this.#deploymentId,
      messageId,
      respondedAt,
    });
  }
}

function createProductionCustomerAuditSupportBroker() {
  throw brokerError('customer_audit_root_db_adapter_required');
}

function createReferenceLocalAuditAdminAuthorizer(options = {}) {
  assertReferenceRuntime();
  const input = exactOptionalObject(options, ['events'], 'audit_local_authorizer_invalid');
  if (!Array.isArray(input.events) || input.events.length < 1 || input.events.length > 10_000) {
    throw brokerError('audit_local_authorizer_invalid');
  }
  const events = new Map();
  for (const raw of input.events) {
    const event = checkedLocalAuthEvent(raw);
    if (events.has(event.authorizationId)) throw brokerError('audit_local_authorizer_invalid');
    events.set(event.authorizationId, event);
  }
  const authorizer = {
    authorize: (query) => authorizeLocalEvent(events, query),
  };
  Object.defineProperty(authorizer, LOCAL_AUTH_BRAND, { value: true });
  return Object.freeze(authorizer);
}

function createReferenceAuditSummaryProvider(options = {}) {
  assertReferenceRuntime();
  const input = exactOptionalObject(options, ['summaries'], 'audit_summary_provider_invalid');
  if (!Array.isArray(input.summaries)) throw brokerError('audit_summary_provider_invalid');
  const configured = deepFreeze(clone(input.summaries));
  let calls = 0;
  const provider = {
    collect(scope) {
      checkedSummaryScope(scope);
      calls += 1;
      return clone(configured);
    },
    calls: () => calls,
  };
  Object.defineProperty(provider, SUMMARY_PROVIDER_BRAND, { value: true });
  return Object.freeze(provider);
}

function verifyRequest(artifact, publicKeys, authorityRegistry) {
  try {
    return verifyAuditSupportRequest(artifact, publicKeys, authorityRegistry);
  } catch (error) {
    throw brokerError(error && error.code ? error.code : 'audit_signature_rejected');
  }
}

function verifyCancellation(artifact, publicKeys, authorityRegistry) {
  try { return verifyAuditSupportCancellation(artifact, publicKeys, authorityRegistry); }
  catch (error) {
    throw brokerError(error && error.code ? error.code : 'audit_cancellation_rejected');
  }
}

function historicalAuthorityRegistry(registry) {
  return Object.freeze({
    assertPublicKey: (purpose, keyId, fingerprint) => registry.assertHistoricalPublicKey(
      purpose, keyId, fingerprint,
    ),
  });
}

function artifactKeyId(value, code) {
  if (!plainObject(value) || !exactKeys(value, ['keyId', 'payload', 'signature'])) {
    throw brokerError(code);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set
      || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true)
      || !REQUEST_KEY_ID_RE.test(String(descriptors.keyId.value || ''))) {
    throw brokerError(code);
  }
  return descriptors.keyId.value;
}

function deliveryReceipt(signedArtifact, verified, nowMs, cancellation, acknowledgementSigner) {
  const receipt = {
    accepted: true,
    artifactDigest: sha256(protocol.canonicalJson(signedArtifact)),
    customerId: verified.payload.customerId,
    deploymentId: verified.payload.deploymentId,
    messageId: verified.payload.messageId,
    receivedAt: isoNow(nowMs),
    requestDigest: cancellation ? verified.payload.requestDigest : verified.payloadDigest,
    requestId: verified.payload.requestId,
    requestVersion: verified.payload.requestVersion,
  };
  if (cancellation) receipt.cancellationDigest = verified.payloadDigest;
  return acknowledgementSigner.attest(receipt);
}

function assertCancellationBinding(state, payload) {
  if (payload.requestDigest !== state.requestDigest
      || payload.customerId !== state.request.customerId
      || payload.deploymentId !== state.request.deploymentId
      || Date.parse(payload.issuedAt) < Date.parse(state.request.issuedAt)) {
    throw brokerError('audit_cancellation_not_current');
  }
}

function assertBinding(request, customerId, deploymentId) {
  if (request.customerId !== customerId) throw brokerError('audit_customer_mismatch');
  if (request.deploymentId !== deploymentId) throw brokerError('audit_deployment_mismatch');
}

function assertCurrent(request, nowMs) {
  const issued = Date.parse(request.issuedAt);
  const start = Date.parse(request.notBefore);
  const end = Date.parse(request.expiresAt);
  if (issued > nowMs + MAX_FUTURE_SKEW_MS
      || Math.abs(start - issued) > MAX_FUTURE_SKEW_MS) {
    throw brokerError('audit_request_time_invalid');
  }
  if (nowMs < start) throw brokerError('audit_request_not_active');
  if (nowMs >= end) throw brokerError('audit_request_expired');
  if (end - start > 24 * 60 * 60 * 1000) throw brokerError('audit_request_too_long');
}

function assertRequestFieldScope(request) {
  const allowed = REQUEST_TYPE_FIELDS[request.requestType];
  if (!allowed || request.fields.some((field) => !allowed.has(field))) {
    throw brokerError('audit_scope_rejected');
  }
}

function versionDisposition(current, verified) {
  const version = verified.payload.requestVersion;
  if (!current) {
    if (version !== 1) throw brokerError('audit_version_genesis_required');
    return null;
  }
  if (version === current.requestVersion && verified.payloadDigest === current.requestDigest) {
    return publicState(current, true);
  }
  if (version === current.requestVersion) throw brokerError('audit_version_conflict');
  if (version < current.requestVersion) throw brokerError('audit_version_stale');
  if (version !== current.requestVersion + 1) throw brokerError('audit_version_gap');
  return null;
}

function requestState(verified, current, nowMs) {
  return deepFreeze({
    appliedAt: isoNow(nowMs),
    approvalRef: null,
    cancellationAppliedAt: null,
    cancellationArtifact: null,
    cancellationDigest: null,
    cancellationIssuedAt: null,
    cancellationSignatureDomain: null,
    cancellationSigningKeyId: null,
    decidedAt: null,
    digest: verified.payloadDigest,
    previousDigest: current ? current.requestDigest : null,
    request: clone(verified.payload),
    requestDigest: verified.payloadDigest,
    requestId: verified.payload.requestId,
    requestVersion: verified.payload.requestVersion,
    respondedAt: null,
    responseDigest: null,
    responseEnvelope: null,
    revision: 1,
    signatureDomain: verified.signatureDomain,
    signingKeyId: verified.keyId,
    status: 'pending',
  });
}

function supersedeCurrent(tx, current, nowMs) {
  if (!current || !['pending', 'approved'].includes(current.status)) return;
  const updated = updateState(current, { status: 'superseded' });
  if (!tx.replace(updated, current.revision)) throw brokerError('audit_request_conflict');
  tx.appendAudit(auditDescriptor(
    'request_superseded', 'superseded', updated, 0, nowMs, null,
  ));
}

function expireIfNeeded(tx, state, nowMs) {
  if (!['pending', 'approved'].includes(state.status)
      || nowMs < Date.parse(state.request.expiresAt)) return state;
  const occurredAt = isoNow(nowMs);
  const approvalRef = tx.reference(
    'expiry', `${state.requestDigest}:${state.requestVersion}:${occurredAt}`,
  );
  const updated = updateState(state, {
    approvalRef,
    decidedAt: occurredAt,
    status: 'expired',
  });
  if (!tx.replace(updated, state.revision)) throw brokerError('audit_request_conflict');
  tx.appendAudit(auditDescriptor(
    'request_expired', 'expired', updated, 0, nowMs, approvalRef,
  ));
  return updated;
}

function updateState(state, changes) {
  return deepFreeze({ ...clone(state), ...clone(changes), revision: state.revision + 1 });
}

function decisionState(action) {
  return { approve: 'approved', deny: 'denied', revoke: 'revoked' }[action];
}

function responsePayload(context, state, binding, summaries) {
  return {
    schemaVersion: protocol.PROTOCOL_VERSION,
    messageId: context.messageId,
    customerId: context.customerId,
    deploymentId: context.deploymentId,
    kind: RESPONSE_KIND,
    requestId: state.requestId,
    requestVersion: state.requestVersion,
    requestDigest: state.requestDigest,
    decision: state.status,
    status: binding.status,
    reasonCode: binding.reasonCode,
    respondedAt: context.respondedAt,
    summaries,
    localApprovalRef: state.approvalRef,
  };
}

function summaryScope(state) {
  return deepFreeze({
    customerId: state.request.customerId,
    deploymentId: state.request.deploymentId,
    fields: state.request.fields.slice(),
    maxRecords: state.request.maxRecords,
    purposeCode: state.request.purposeCode,
    requestDigest: state.requestDigest,
    requestType: state.request.requestType,
  });
}

function assertSummaryScope(request, summaries) {
  if (!Array.isArray(summaries)) throw brokerError('audit_summary_invalid');
  if (summaries.length > request.maxRecords) throw brokerError('audit_record_limit_exceeded');
  const requested = new Set(request.fields);
  const fields = new Set();
  let total = 0;
  for (const summary of summaries) {
    if (!plainObject(summary) || !requested.has(summary.field) || fields.has(summary.field)
        || !Number.isInteger(summary.count) || summary.count < 0
        || summary.count > request.maxRecords) throw brokerError('audit_summary_scope_exceeded');
    fields.add(summary.field);
    total += summary.count;
  }
  if (total > request.maxRecords) throw brokerError('audit_summary_scope_exceeded');
}

function auditDescriptor(eventType, outcome, state, count, nowMs, authorizationRef) {
  return Object.freeze({
    authorizationRef,
    count,
    eventType,
    occurredAt: isoNow(nowMs),
    outcome,
    requestDigest: state.requestDigest,
    requestVersion: state.requestVersion,
  });
}

function publicState(state, duplicate) {
  return Object.freeze({
    requestId: state.requestId,
    requestVersion: state.requestVersion,
    requestDigest: state.requestDigest,
    previousDigest: state.previousDigest,
    signingKeyId: state.signingKeyId,
    status: state.status,
    duplicate,
  });
}

function authorizeLocalEvent(events, rawQuery) {
  const query = exactObject(rawQuery, [
    'action', 'authorizationId', 'customerId', 'deploymentId', 'nowMs', 'purposeCode',
    'requestDigest', 'requestId', 'requestVersion',
  ], 'audit_authorization_denied');
  const event = events.get(query.authorizationId);
  if (!event || !authorizationMatches(event, query)) throw brokerError('audit_authorization_denied');
  const nowMs = query.nowMs;
  const authenticatedMs = Date.parse(event.authenticatedAt);
  const stepUpMs = Date.parse(event.stepUpAt);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0
      || authenticatedMs > nowMs + MAX_FUTURE_SKEW_MS
      || nowMs - authenticatedMs > MAX_AUTH_EVENT_AGE_MS
      || stepUpMs > authenticatedMs || nowMs - stepUpMs > MAX_STEP_UP_AGE_MS) {
    throw brokerError('audit_step_up_required');
  }
  return Object.freeze({ authEventId: event.authEventId, auditRef: event.auditRef });
}

function authorizationMatches(event, query) {
  return event.action === query.action
    && event.authorizationId === query.authorizationId
    && event.customerId === query.customerId
    && event.deploymentId === query.deploymentId
    && event.purposeCode === query.purposeCode
    && event.requestDigest === query.requestDigest
    && event.requestId === query.requestId
    && event.requestVersion === query.requestVersion;
}

function checkedLocalAuthEvent(raw) {
  const value = exactObject(raw, [
    'action', 'auditRef', 'authEventId', 'authenticatedAt', 'authorizationId',
    'customerId', 'deploymentId', 'purposeCode', 'requestDigest', 'requestId',
    'requestVersion', 'role', 'stepUpAt',
  ], 'audit_local_authorizer_invalid');
  if (!['approve', 'deny', 'revoke'].includes(value.action)
      || value.role !== 'security_admin'
      || !UUID_RE.test(String(value.authEventId || ''))
      || !UUID_RE.test(String(value.authorizationId || ''))
      || !UUID_RE.test(String(value.requestId || ''))
      || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !['customer_support', 'security_incident', 'compliance_assistance']
        .includes(value.purposeCode)
      || !SHA256_RE.test(String(value.requestDigest || ''))
      || !Number.isSafeInteger(value.requestVersion) || value.requestVersion < 1
      || !LOCAL_AUDIT_REF_RE.test(String(value.auditRef || ''))) {
    throw brokerError('audit_local_authorizer_invalid');
  }
  canonicalIso(value.authenticatedAt, 'audit_local_authorizer_invalid');
  canonicalIso(value.stepUpAt, 'audit_local_authorizer_invalid');
  return deepFreeze(clone(value));
}

function checkedDecisionCommand(raw) {
  const value = exactObject(raw, [
    'action', 'authorizationId', 'requestId', 'requestVersion',
  ], 'audit_decision_invalid');
  if (!['approve', 'deny', 'revoke'].includes(value.action)
      || !UUID_RE.test(String(value.authorizationId || ''))
      || !UUID_RE.test(String(value.requestId || ''))
      || !Number.isSafeInteger(value.requestVersion) || value.requestVersion < 1) {
    throw brokerError('audit_decision_invalid');
  }
  return value;
}

function checkedResponseCommand(raw) {
  const value = exactObject(raw, ['requestId', 'requestVersion'], 'audit_response_command_invalid');
  checkedUuid(value.requestId, 'audit_response_command_invalid');
  checkedVersion(value.requestVersion);
  return value;
}

function checkedSummaryScope(value) {
  if (!plainObject(value) || !exactKeys(value, [
    'customerId', 'deploymentId', 'fields', 'maxRecords', 'purposeCode',
    'requestDigest', 'requestType',
  ]) || !CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)
      || !SHA256_RE.test(String(value.requestDigest || ''))
      || !Array.isArray(value.fields)) throw brokerError('audit_summary_provider_invalid');
  return value;
}

function requireCurrentState(tx, requestId, requestVersion) {
  const latest = tx.readLatest(requestId);
  if (!latest || latest.requestVersion !== requestVersion) {
    throw brokerError('audit_request_not_current');
  }
  return latest;
}

function checkedAuthorityRegistry(value) {
  if (!value || typeof value.activePublicKeys !== 'function'
      || typeof value.assertPublicKey !== 'function'
      || typeof value.assertHistoricalPublicKey !== 'function'
      || typeof value.verificationPublicKey !== 'function') {
    throw brokerError('audit_authority_manifest_required');
  }
  const keys = value.activePublicKeys(KEY_PURPOSES.AUDIT_REQUEST);
  if (!(keys instanceof Map) || keys.size < 1 || keys.size > 2) {
    throw brokerError('audit_authority_manifest_invalid');
  }
  return value;
}

function checkedStore(value) {
  if (!isCustomerAuditSupportStore(value)) throw brokerError('audit_store_invalid');
  return value;
}

function checkedLocalAuthorizer(value) {
  if (!value || value[LOCAL_AUTH_BRAND] !== true || typeof value.authorize !== 'function') {
    throw brokerError('audit_local_authorizer_invalid');
  }
  return value;
}

function checkedSummaryProvider(value) {
  if (!value || value[SUMMARY_PROVIDER_BRAND] !== true || typeof value.collect !== 'function') {
    throw brokerError('audit_summary_provider_invalid');
  }
  return value;
}

function checkedResponseSigner(value, customerId, deploymentId) {
  if (!isCustomerAuditResponseSigner(value)
      || value.customerId !== customerId || value.deploymentId !== deploymentId) {
    throw brokerError('audit_response_signer_invalid');
  }
  return value;
}

function checkedAcknowledgementSigner(value, customerId, deploymentId) {
  if (!isAuditAcknowledgementSigner(value)
      || value.customerId !== customerId || value.deploymentId !== deploymentId) {
    throw brokerError('audit_acknowledgement_signer_invalid');
  }
  return value;
}

function checkedCustomerId(value) {
  if (!CUSTOMER_ID_RE.test(String(value || ''))) throw brokerError('audit_configuration_invalid');
  return value;
}
function checkedDeploymentId(value) {
  if (!isDeploymentId(value)) throw brokerError('audit_configuration_invalid');
  return value;
}
function checkedUuid(value, code) {
  if (!UUID_RE.test(String(value || ''))) throw brokerError(code);
  return value;
}
function checkedVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw brokerError('audit_version_invalid');
  return value;
}
function checkedFunction(value, fallback, code) {
  const output = value === undefined ? fallback : value;
  if (typeof output !== 'function') throw brokerError(code);
  return output;
}

function exactOptionalObject(value, allowed, code) {
  if (!plainObject(value) || Object.keys(value).some((key) => !allowed.includes(key))) {
    throw brokerError(code);
  }
  return descriptorValues(value, code);
}
function exactObject(value, keys, code) {
  if (!plainObject(value) || !exactKeys(value, keys)) throw brokerError(code);
  return descriptorValues(value, code);
}
function descriptorValues(value, code) {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set
      || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true)) {
    throw brokerError(code);
  }
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
}
function exactKeys(value, keys) {
  return Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function canonicalIso(value, code) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw brokerError(code);
  return value;
}
function isoNow(value) { return new Date(value).toISOString(); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

function brokerError(code) {
  const error = new Error('customer audit support operation rejected');
  error.code = code;
  return error;
}

function rejectedResult(code) { return Object.freeze({ auditSupportFailureCode: code }); }
function unwrapResult(value) {
  if (value && value.auditSupportFailureCode) throw brokerError(value.auditSupportFailureCode);
  return value;
}

function assertReferenceRuntime() {
  if (process.env.NODE_ENV === 'production') {
    throw brokerError('customer_audit_reference_runtime_forbidden');
  }
}

module.exports = {
  CustomerAuditSupportBroker,
  createProductionCustomerAuditSupportBroker,
  createReferenceAuditSummaryProvider,
  createReferenceLocalAuditAdminAuthorizer,
};
