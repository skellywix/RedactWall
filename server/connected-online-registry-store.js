'use strict';

const crypto = require('node:crypto');
const registryState = require('./connected-online-registry-state');
const {
  isConnectedHeartbeatTransactionCoordinator,
} = require('./connected-heartbeat-apply-store');
const protocol = require('./vendor-control-protocol');

const STATE_ACTIONS = Object.freeze([
  'CONNECTED_REGISTRY_VERDICT_APPLIED',
  'CONNECTED_REGISTRY_VERDICT_REFRESHED',
  'CONNECTED_REGISTRY_VERDICT_REVOKED',
  'CONNECTED_REGISTRY_VERDICT_RESTORED',
]);
const APPLY_KEYS = Object.freeze([
  'customerId', 'deploymentId', 'nowMs', 'signedVerdict',
]);
const AUDIT_DETAIL_KEYS = Object.freeze([
  'authorityRef', 'registryGeneration', 'registryStateDigest',
  'signatureDomain', 'signingKeyFingerprint', 'signingKeyId',
  'stateDigest', 'status',
]);
const SQLITE_RESERVED_AUTHORITY_RELATIONS = Object.freeze([
  'audit',
  'connected_online_registry_state',
]);
const SQLITE_RESERVED_AUTHORITY_OBJECTS = Object.freeze([
  ...SQLITE_RESERVED_AUTHORITY_RELATIONS,
  'idx_connected_registry_generation',
  'idx_audit_connected_authority',
  'idx_audit_connected_authority_action',
]);

function createConnectedOnlineRegistryStore(options = {}) {
  const ctx = context(options);
  const apply = ctx.driver.transaction((input) => applyInTransaction(ctx, input));
  const read = registryReadTransaction(ctx);
  const getState = (customerId, deploymentId) => read(
    () => readState(ctx, customerId, deploymentId),
  );
  return Object.freeze({
    applyVerdict: apply,
    getState,
    registryGeneration: (customerId, deploymentId) => {
      const state = getState(customerId, deploymentId);
      return registryState.registryGenerationForHeartbeat(state);
    },
    disposition: (customerId, deploymentId, entitlementDisposition) => {
      const state = getState(customerId, deploymentId)
        || registryState.initialState(customerId, deploymentId);
      return registryState.combineConnectedDisposition(state, entitlementDisposition);
    },
  });
}

function registryReadTransaction(ctx) {
  const transaction = ctx.driver.transaction((callback) => {
    lockAuthority(ctx);
    return callback();
  });
  if (typeof transaction !== 'function') {
    throw new TypeError('connected registry read transaction is required');
  }
  return receiverless(transaction);
}

function context(options) {
  requireFunction(options.appendAudit, 'appendAudit');
  requireFunction(options.registryReference, 'registryReference');
  requireFunction(options.verifyAuditState, 'verifyAuditState');
  requireFunction(options.verifyAuditEntry, 'verifyAuditEntry');
  requireFunction(options.verifyVerdict, 'verifyVerdict');
  const driver = options.driver;
  if (!driver || typeof driver.prepare !== 'function'
      || typeof driver.transaction !== 'function') throw new TypeError('driver is required');
  registryState.initialState(options.customerId, options.deploymentId);
  const relation = trustedAuthorityRelations(driver);
  return {
    customerId: options.customerId,
    deploymentId: options.deploymentId,
    driver,
    appendAudit: receiverless(options.appendAudit),
    registryReference: receiverless(options.registryReference),
    verifyAuditState: receiverless(options.verifyAuditState),
    verifyAuditEntry: receiverless(options.verifyAuditEntry),
    verifyVerdict: receiverless(options.verifyVerdict),
    compositeCoordinator: checkedCoordinator(options.compositeCoordinator),
    relation,
    stateRead: driver.prepare(`SELECT authority_ref, registry_generation,
      registry_state_digest, status, state_json
      FROM ${relation.state}
      WHERE customer_id = ? AND deployment_id = ?`),
    stateWrite: driver.prepare(`INSERT INTO ${relation.state} AS registry_state
      (customer_id, deployment_id, authority_ref, registry_generation,
       registry_state_digest, status, state_json, updated_at)
      VALUES (@customerId, @deploymentId, @authorityRef, @registryGeneration,
       @registryStateDigest, @status, @stateJson, @updatedAt)
      ON CONFLICT(customer_id, deployment_id) DO UPDATE SET
        registry_generation = excluded.registry_generation,
        registry_state_digest = excluded.registry_state_digest,
        status = excluded.status,
        state_json = excluded.state_json,
        updated_at = excluded.updated_at
      WHERE registry_state.authority_ref = excluded.authority_ref`),
    stateAudit: driver.prepare(`SELECT seq, action, connected_entry_action, entry FROM ${relation.audit}
      WHERE connected_authority_ref = ? AND connected_entry_action IN
        ('CONNECTED_REGISTRY_VERDICT_APPLIED', 'CONNECTED_REGISTRY_VERDICT_REFRESHED',
         'CONNECTED_REGISTRY_VERDICT_REVOKED', 'CONNECTED_REGISTRY_VERDICT_RESTORED')
      ORDER BY seq DESC LIMIT 1`),
    tempAuthorityObjects: driver.kind === 'postgres' ? null : driver.prepare(`
      SELECT type, name, tbl_name FROM temp.sqlite_schema
      WHERE name IN (${SQLITE_RESERVED_AUTHORITY_OBJECTS.map((name) => `'${name}'`).join(', ')})
        OR ((type = 'trigger' OR type = 'index')
          AND tbl_name IN (${SQLITE_RESERVED_AUTHORITY_RELATIONS
    .map((name) => `'${name}'`).join(', ')}))
      ORDER BY type, name`),
  };
}

function trustedAuthorityRelations(driver) {
  const schema = driver.kind === 'postgres' ? 'public' : 'main';
  return Object.freeze({
    state: `${schema}.connected_online_registry_state`,
    audit: `${schema}.audit`,
  });
}

function applyInTransaction(ctx, input) {
  const parsed = checkedApplyInput(input);
  assertScope(ctx, parsed.customerId, parsed.deploymentId);
  lockAuthority(ctx);
  const verified = verifyVerdict(ctx, parsed.signedVerdict);
  const current = readState(ctx, ctx.customerId, ctx.deploymentId)
    || registryState.initialState(ctx.customerId, ctx.deploymentId);
  const result = registryState.applyVerifiedRegistryVerdict(current, verified, {
    nowMs: parsed.nowMs,
  });
  if (!result.contactAdvanced) return result;
  const authorityRef = referenceFor(ctx);
  writeState(ctx, result.state, authorityRef);
  appendStateAudit(ctx, result, authorityRef);
  return result;
}

function readState(ctx, customerId, deploymentId) {
  assertScope(ctx, customerId, deploymentId);
  requireAuditHealthy(ctx);
  const authorityRef = referenceFor(ctx);
  const row = ctx.stateRead.get(customerId, deploymentId);
  const anchor = verifiedAuditDetail(ctx, ctx.stateAudit.get(authorityRef));
  if (!row) {
    if (anchor) throw integrityError();
    return null;
  }
  const state = parsedState(row, customerId, deploymentId);
  if (row.authority_ref !== authorityRef || !anchor
      || anchor.authorityRef !== authorityRef
      || anchor.registryGeneration !== state.registryGeneration
      || anchor.registryStateDigest !== state.registryStateDigest
      || anchor.status !== state.status
      || anchor.stateDigest !== stateDigest(state)
      || anchor.signingKeyId !== state.signingKeyId
      || anchor.signingKeyFingerprint !== state.signingKeyFingerprint
      || anchor.signatureDomain !== state.signatureDomain) throw integrityError();
  return state;
}

function parsedState(row, customerId, deploymentId) {
  let state;
  try {
    state = registryState.restoreState(JSON.parse(row.state_json), { customerId, deploymentId });
  } catch { throw integrityError(); }
  if (Number(row.registry_generation) !== state.registryGeneration
      || row.registry_state_digest !== state.registryStateDigest
      || row.status !== state.status) throw integrityError();
  return state;
}

function writeState(ctx, state, authorityRef) {
  const result = ctx.stateWrite.run({
    customerId: state.customerId,
    deploymentId: state.deploymentId,
    authorityRef,
    registryGeneration: state.registryGeneration,
    registryStateDigest: state.registryStateDigest,
    status: state.status,
    stateJson: protocol.canonicalJson(state),
    updatedAt: state.acceptedAt,
  });
  if (Number(result.changes) !== 1) throw integrityError();
}

function appendStateAudit(ctx, result, authorityRef) {
  const state = result.state;
  ctx.appendAudit({
    action: result.auditAction,
    actor: 'vendor_connector',
    connectedAuthorityRef: authorityRef,
    detail: JSON.stringify({
      authorityRef,
      registryGeneration: state.registryGeneration,
      registryStateDigest: state.registryStateDigest,
      signatureDomain: state.signatureDomain,
      signingKeyFingerprint: state.signingKeyFingerprint,
      signingKeyId: state.signingKeyId,
      stateDigest: stateDigest(state),
      status: state.status,
    }),
  });
}

function verifiedAuditDetail(ctx, row) {
  if (!row) return null;
  let entry;
  let detail;
  try {
    entry = JSON.parse(row.entry);
    if (!ctx.verifyAuditEntry(entry) || !STATE_ACTIONS.includes(entry.action)
        || entry.action !== row.connected_entry_action
        || entry.action !== row.action) throw new Error();
    detail = JSON.parse(entry.detail);
  } catch { throw integrityError(); }
  if (!plainRecord(detail) || !exactKeys(detail, AUDIT_DETAIL_KEYS)
      || typeof detail.authorityRef !== 'string'
      || !Number.isSafeInteger(detail.registryGeneration) || detail.registryGeneration < 1
      || !/^[a-f0-9]{64}$/.test(String(detail.registryStateDigest || ''))
      || !/^[a-f0-9]{64}$/.test(String(detail.stateDigest || ''))
      || !/^[a-f0-9]{64}$/.test(String(detail.signingKeyFingerprint || ''))
      || !/^rw-online-verdict-[a-f0-9]{64}$/.test(String(detail.signingKeyId || ''))
      || detail.signatureDomain !== registryState.VERDICT_DOMAIN
      || !['active', 'revoked'].includes(detail.status)) throw integrityError();
  return detail;
}

function verifyVerdict(ctx, value) {
  let verified;
  try { verified = ctx.verifyVerdict(value); }
  catch (error) { throw error; }
  if (verified && typeof verified.then === 'function') {
    throw storeError('registry_verifier_must_be_synchronous');
  }
  return verified;
}

function checkedApplyInput(value) {
  if (!plainRecord(value) || !exactKeys(value, APPLY_KEYS)
      || !Object.hasOwn(value, 'signedVerdict')) throw storeError('registry_apply_invalid');
  const nowMs = Number(value.nowMs);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw storeError('registry_apply_invalid');
  return { ...value, nowMs };
}

function requireAuditHealthy(ctx) {
  if (ctx.compositeCoordinator && ctx.compositeCoordinator.isAuditVerified()) return;
  let result;
  try { result = ctx.verifyAuditState(); }
  catch { throw integrityError(); }
  if (!result || result.ok !== true) throw integrityError();
}

function checkedCoordinator(value) {
  if (value === undefined || value === null) return null;
  if (!isConnectedHeartbeatTransactionCoordinator(value)) {
    throw new TypeError('connected heartbeat transaction coordinator is invalid');
  }
  return value;
}

function assertScope(ctx, customerId, deploymentId) {
  registryState.initialState(customerId, deploymentId);
  if (customerId !== ctx.customerId) throw storeError('registry_customer_mismatch');
  if (deploymentId !== ctx.deploymentId) throw storeError('registry_deployment_mismatch');
}

function referenceFor(ctx) {
  const value = ctx.registryReference(ctx.customerId, ctx.deploymentId);
  if (!/^connected_registry_[A-Za-z0-9_-]{24,96}$/.test(String(value || ''))) {
    throw integrityError();
  }
  return value;
}

function stateDigest(state) {
  return crypto.createHash('sha256').update(protocol.canonicalJson(state), 'utf8').digest('hex');
}

function lockAuthority(ctx) {
  if (typeof ctx.driver.lockAuditAppend === 'function') ctx.driver.lockAuditAppend();
  assertNoTemporaryAuthorityCollision(ctx);
}

function assertNoTemporaryAuthorityCollision(ctx) {
  if (ctx.tempAuthorityObjects && ctx.tempAuthorityObjects.all().length !== 0) {
    throw integrityError();
  }
}

function requireFunction(value, name) {
  if (typeof value !== 'function') throw new TypeError(`${name} is required`);
}

function receiverless(callback) {
  return (...args) => Reflect.apply(callback, undefined, args);
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function storeError(code) {
  const error = new Error('connected online registry store rejected input');
  error.code = code;
  return error;
}

function integrityError() {
  const error = new Error('connected online registry state is not anchored by audit evidence');
  error.code = 'CONNECTED_REGISTRY_INTEGRITY';
  return error;
}

module.exports = Object.freeze({
  createConnectedOnlineRegistryStore,
  STATE_ACTIONS,
});
