'use strict';

const crypto = require('node:crypto');
const Database = require('better-sqlite3');
const protocol = require('./vendor-control-protocol');
const { isDeploymentId } = require('./deployment-identity');
const {
  INDEPENDENT_WITNESS_ASSURANCE,
  TEST_WITNESS_ASSURANCE,
} = require('./monotonic-anchor-authority');
const customerSigner = require('./customer-audit-response-signer');

const CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN = 'redactwall.customer-audit-response.v1';
const RESPONSE_KIND = protocol.CHANNEL_KINDS.AUDIT_RESPONSE;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_VERIFY_ONLY_KEYS = 4;
const REGISTRY_SCHEMA_VERSION = 1;
const ZERO_DIGEST = '0'.repeat(64);
const KEY_ID_RE = /^rw-customer-audit-response-[a-z0-9][a-z0-9_.-]{0,55}$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const ANCHOR_NAMESPACE_RE = /^[a-z0-9][a-z0-9_.:-]{0,159}$/;
const RESPONSE_REGISTRY_ANCHOR_PURPOSE = 'customer_audit_response_registry';
const LOCAL_AUDIT_REF_RE = /^local_audit_[A-Za-z0-9_-]{20,86}$/;
const RESPONSE_KEYS = Object.freeze([
  'customerId', 'decision', 'deploymentId', 'kind', 'localApprovalRef', 'messageId',
  'reasonCode', 'requestDigest', 'requestId', 'requestVersion', 'respondedAt',
  'schemaVersion', 'status', 'summaries',
]);
const REGISTRY_BRAND = Symbol('customer-audit-response-key-registry');
const REGISTRY_MIGRATION = `
CREATE TABLE IF NOT EXISTS customer_audit_response_registry (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL,
  state_json TEXT NOT NULL,
  state_mac TEXT NOT NULL
);
`;
const REGISTRY_WITNESS_MIGRATION = `
CREATE TABLE IF NOT EXISTS registry_witness.customer_audit_response_registry_anchor (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL,
  anchor_revision INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  registry_digest TEXT NOT NULL,
  trusted_time_ms INTEGER NOT NULL,
  anchor_mac TEXT NOT NULL
);
`;

function createCustomerAuditResponseSigner(options = {}) {
  return customerSigner.createCustomerAuditResponseSigner(options);
}

function isCustomerAuditResponseSigner(value) {
  return customerSigner.isCustomerAuditResponseSigner(value);
}

function createCustomerAuditResponseKeyRegistry(options = {}) {
  assertReferenceRuntime();
  const input = exactOptionalObject(options, [
    'anchorAuthority', 'anchorNamespace', 'database', 'entries', 'generation', 'integrityKey', 'now', 'path',
    'previousRegistryDigest', 'witnessPath',
  ], 'customer_response_registry_invalid');
  const now = checkedNow(input.now);
  const integrityKey = checkedRegistrySecret(input.integrityKey);
  const anchorNamespace = checkedAnchorNamespace(input.anchorNamespace);
  const anchorAuthority = checkedAnchorAuthority(input.anchorAuthority, integrityKey);
  const databasePath = input.path || ':memory:';
  const witnessPath = input.witnessPath
    || (databasePath === ':memory:' ? ':memory:' : `${databasePath}.witness`);
  if (databasePath !== ':memory:' && witnessPath === databasePath) {
    throw responseError('customer_response_registry_invalid');
  }
  const database = input.database || new Database(databasePath);
  try {
    setupRegistryDatabase(database, witnessPath);
    initializeRegistry(database, integrityKey, input, now, anchorAuthority, anchorNamespace);
  } catch (error) {
    if (!input.database) try { database.close(); } catch {}
    throw error;
  }
  let closed = false;
  const registry = {
    verify(query) {
      assertRegistryOpen(closed);
      return verifyRegistryQuery(
        database, integrityKey, now, query, anchorAuthority, anchorNamespace,
      );
    },
    manifest() {
      assertRegistryOpen(closed);
      return readAnchoredRegistryManifest(
        database, integrityKey, anchorAuthority, anchorNamespace,
      );
    },
    install(candidate) {
      assertRegistryOpen(closed);
      return installRegistryGeneration(
        database, integrityKey, now, candidate, anchorAuthority, anchorNamespace,
      );
    },
    close() {
      if (!closed) database.close();
      closed = true;
    },
  };
  Object.defineProperty(registry, REGISTRY_BRAND, { value: true });
  return Object.freeze(registry);
}

function isCustomerAuditResponseKeyRegistry(value) {
  return Boolean(value && value[REGISTRY_BRAND] === true);
}

function verifyCustomerAuditResponse(rawEnvelope, registry) {
  const { keyId, payload, signature } = checkedCustomerAuditResponseEnvelope(rawEnvelope);
  if (!registry || typeof registry.verify !== 'function') {
    throw responseError('customer_response_registry_required');
  }
  const message = protocol.canonicalJson(payload);
  if (registry.verify({
    customerId: payload.customerId,
    deploymentId: payload.deploymentId,
    domain: CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN,
    issuedAt: payload.respondedAt,
    keyId,
    message,
    signature: signature.toString('base64'),
  }) !== true) throw responseError('customer_response_signature_invalid');
  return deepFreeze({
    keyId,
    payload,
    responseDigest: responseDigest(keyId, payload, signature),
    signatureDomain: CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN,
  });
}

function customerAuditResponseClaim(rawEnvelope) {
  const { keyId, payload, signature } = checkedCustomerAuditResponseEnvelope(rawEnvelope);
  return deepFreeze({
    messageId: payload.messageId,
    responseDigest: responseDigest(keyId, payload, signature),
  });
}

function checkedCustomerAuditResponseEnvelope(rawEnvelope) {
  const envelope = boundedSnapshot(rawEnvelope, 'customer_response_envelope_invalid');
  if (!exactKeys(envelope, ['keyId', 'payload', 'signature'])) {
    throw responseError('customer_response_envelope_invalid');
  }
  return Object.freeze({
    keyId: checkedKeyId(envelope.keyId),
    payload: assertCustomerAuditResponsePayload(envelope.payload),
    signature: canonicalSignature(envelope.signature),
  });
}

function responseDigest(keyId, payload, signature) {
  return sha256(protocol.canonicalJson({
    keyId, payload, signature: signature.toString('base64'),
  }));
}

function assertCustomerAuditResponsePayload(raw) {
  const value = boundedSnapshot(raw, 'customer_response_payload_invalid');
  if (!exactKeys(value, RESPONSE_KEYS)
      || !SHA256_RE.test(String(value.requestDigest || ''))
      || !LOCAL_AUDIT_REF_RE.test(String(value.localApprovalRef || ''))
      || !['approved', 'denied', 'expired', 'revoked'].includes(value.decision)) {
    throw responseError('customer_response_payload_invalid');
  }
  const shared = { ...value };
  delete shared.decision;
  delete shared.localApprovalRef;
  delete shared.requestDigest;
  let checked;
  try { checked = protocol.assertChannel(shared, RESPONSE_KIND); }
  catch { throw responseError('customer_response_payload_invalid'); }
  assertDecisionBinding(value);
  return deepFreeze({ ...checked,
    requestDigest: value.requestDigest,
    decision: value.decision,
    localApprovalRef: value.localApprovalRef,
  });
}

function customerAuditResponseSigningInput(payload, keyId) {
  const checked = assertCustomerAuditResponsePayload(payload);
  const normalized = checkedKeyId(keyId);
  return Buffer.from(
    `${CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN}\0${normalized}\0${protocol.canonicalJson(checked)}`,
    'utf8',
  );
}

function setupRegistryDatabase(database, witnessPath) {
  database.pragma('journal_mode = DELETE');
  database.pragma('synchronous = FULL');
  database.pragma('busy_timeout = 30000');
  database.prepare('ATTACH DATABASE ? AS registry_witness').run(witnessPath);
  database.exec('PRAGMA registry_witness.journal_mode = DELETE');
  database.exec('PRAGMA registry_witness.synchronous = FULL');
  database.exec(REGISTRY_MIGRATION);
  database.exec(REGISTRY_WITNESS_MIGRATION);
}

function initializeRegistry(database, integrityKey, input, now, anchorAuthority, anchorNamespace) {
  let transition = null;
  let committed = false;
  database.exec('BEGIN IMMEDIATE');
  try {
    reconcileRegistryAnchor(database, integrityKey, anchorAuthority, anchorNamespace);
    const row = database.prepare(`
      SELECT state_json, state_mac FROM customer_audit_response_registry WHERE singleton = 1
    `).get();
    const anchor = readRegistryAnchor(database);
    if (!row && !anchor) {
      const state = insertInitialRegistry(database, integrityKey, input, now);
      transition = registryAnchorTransition(anchorNamespace, null, state, integrityKey);
      assertRegistryAnchorPrepared(anchorAuthority.prepare(transition), transition);
    }
    else {
      if (!row || !anchor) throw responseError('customer_response_registry_rewind');
      const state = readRegistryState(database, integrityKey, true);
      assertConfiguredRegistryMatches(state, input);
    }
    database.exec('COMMIT');
    committed = true;
  } catch (error) {
    if (!committed) try { database.exec('ROLLBACK'); } catch {}
    throw error;
  }
  if (transition) {
    try { assertRegistryAnchorFinalized(anchorAuthority.finalize(transition), transition); }
    catch {}
  }
}

function insertInitialRegistry(database, integrityKey, input, now) {
  if (!Array.isArray(input.entries) || input.entries.length < 1
      || input.entries.length > 10_000) {
    throw responseError('customer_response_registry_invalid');
  }
  const generation = input.generation === undefined ? 1 : input.generation;
  const previous = input.previousRegistryDigest || ZERO_DIGEST;
  if (generation !== 1 || previous !== ZERO_DIGEST) {
    throw responseError('customer_response_registry_generation_invalid');
  }
  const normalized = normalizeRegistryEntries(input.entries);
  const bindings = initialBindings(normalized.scopes, generation);
  const state = createRegistryState(
    normalized, generation, previous, checkedClock(now()), bindings, [], 1,
  );
  insertRegistryState(database, integrityKey, state);
  insertRegistryAnchor(database, integrityKey, state);
  return state;
}

function assertConfiguredRegistryMatches(state, input) {
  if (input.generation !== undefined && input.generation !== state.generation) {
    throw responseError('customer_response_registry_generation_invalid');
  }
  if (input.previousRegistryDigest !== undefined
      && input.previousRegistryDigest !== state.previousRegistryDigest) {
    throw responseError('customer_response_registry_generation_invalid');
  }
  if (input.entries !== undefined) {
    const normalized = normalizeRegistryEntries(input.entries);
    if (canonical(normalized.entries) !== canonical(state.entries)) {
      throw responseError('customer_response_registry_configuration_mismatch');
    }
  }
}

function verifyRegistryQuery(database, integrityKey, now, rawQuery,
  anchorAuthority, anchorNamespace) {
  let transition = null;
  let verified = false;
  database.exec('BEGIN IMMEDIATE');
  try {
    reconcileRegistryAnchor(database, integrityKey, anchorAuthority, anchorNamespace);
    const state = readRegistryState(database, integrityKey, true);
    assertRegistryExternalCurrent(anchorAuthority.read(anchorNamespace), state);
    const currentMs = checkedClock(now());
    const trustedTimeMs = Math.max(currentMs, state.trustedTimeMs);
    const scopes = normalizeRegistryEntries(state.entries).scopes;
    verified = verifyWithRegistry(scopes, trustedTimeMs, rawQuery);
    if (trustedTimeMs !== state.trustedTimeMs) {
      const advanced = { ...state, anchorRevision: state.anchorRevision + 1, trustedTimeMs };
      replaceRegistryState(database, integrityKey, advanced);
      replaceRegistryAnchor(database, integrityKey, advanced);
      transition = registryAnchorTransition(
        anchorNamespace, state, advanced, integrityKey,
      );
      assertRegistryAnchorPrepared(anchorAuthority.prepare(transition), transition);
    }
    database.exec('COMMIT');
  } catch {
    try { database.exec('ROLLBACK'); } catch {}
    return false;
  }
  if (transition) {
    try { assertRegistryAnchorFinalized(anchorAuthority.finalize(transition), transition); }
    catch {}
  }
  return verified;
}

function installRegistryGeneration(database, integrityKey, now, rawCandidate,
  anchorAuthority, anchorNamespace) {
  const candidate = exactObject(rawCandidate, [
    'entries', 'generation', 'previousRegistryDigest',
  ], 'customer_response_registry_generation_invalid');
  if (!Array.isArray(candidate.entries) || candidate.entries.length < 1
      || candidate.entries.length > 10_000
      || !Number.isSafeInteger(candidate.generation) || candidate.generation < 2
      || !SHA256_RE.test(String(candidate.previousRegistryDigest || ''))) {
    throw responseError('customer_response_registry_generation_invalid');
  }
  let transition = null;
  let next;
  database.exec('BEGIN IMMEDIATE');
  try {
    reconcileRegistryAnchor(database, integrityKey, anchorAuthority, anchorNamespace);
    const current = readRegistryState(database, integrityKey, true);
    assertRegistryExternalCurrent(anchorAuthority.read(anchorNamespace), current);
    if (candidate.generation !== current.generation + 1
        || candidate.previousRegistryDigest !== current.registryDigest) {
      throw responseError('customer_response_registry_generation_invalid');
    }
    const normalized = normalizeRegistryEntries(candidate.entries);
    const history = evolveRegistryHistory(current, normalized.scopes, candidate.generation);
    const trustedTimeMs = Math.max(current.trustedTimeMs, checkedClock(now()));
    next = createRegistryState(
      normalized, candidate.generation, current.registryDigest, trustedTimeMs,
      history.bindings, history.tombstones, current.anchorRevision + 1,
    );
    replaceRegistryState(database, integrityKey, next);
    replaceRegistryAnchor(database, integrityKey, next);
    transition = registryAnchorTransition(anchorNamespace, current, next, integrityKey);
    assertRegistryAnchorPrepared(anchorAuthority.prepare(transition), transition);
    database.exec('COMMIT');
  } catch (error) {
    try { database.exec('ROLLBACK'); } catch {}
    throw error;
  }
  try { assertRegistryAnchorFinalized(anchorAuthority.finalize(transition), transition); }
  catch {}
  return publicRegistryManifest(next);
}

function createRegistryState(normalized, generation, previous, trustedTimeMs,
  bindings, tombstones, anchorRevision) {
  const document = registryDocument(
    normalized.scopes, generation, previous, bindings, tombstones,
  );
  return deepFreeze({
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    recordType: 'customer_audit_response_key_registry_state',
    anchorRevision,
    generation,
    previousRegistryDigest: previous,
    registryDigest: sha256(canonical(document)),
    trustedTimeMs,
    entries: normalized.entries,
    bindings,
    tombstones,
  });
}

function normalizeRegistryEntries(rawEntries) {
  if (!Array.isArray(rawEntries) || rawEntries.length < 1 || rawEntries.length > 10_000) {
    throw responseError('customer_response_registry_invalid');
  }
  const scopes = new Map();
  const identities = new Set();
  const keyIds = new Set();
  for (const raw of rawEntries) {
    const entry = checkedRegistryEntry(raw, identities, keyIds);
    const scope = scopeKey(entry.customerId, entry.deploymentId);
    if (scopes.has(scope)) throw responseError('customer_response_scope_duplicate');
    scopes.set(scope, entry);
  }
  return { scopes, entries: serializeRegistryEntries(scopes) };
}

function serializeRegistryEntries(scopes) {
  return [...scopes.values()].map((entry) => ({
    customerId: entry.customerId,
    deploymentId: entry.deploymentId,
    current: serializePublicKey(entry.current),
    next: entry.next ? serializePublicKey(entry.next) : null,
    verifyOnly: entry.verifyOnly.map(serializePublicKey),
  })).sort((left, right) => scopeKey(left.customerId, left.deploymentId)
    .localeCompare(scopeKey(right.customerId, right.deploymentId)));
}

function serializePublicKey(record) {
  const output = {
    keyId: record.keyId,
    publicKey: record.publicKey.export({ format: 'pem', type: 'spki' }),
    validFrom: record.validFrom,
  };
  if (record.verifyUntil !== null) output.verifyUntil = record.verifyUntil;
  return output;
}

function initialBindings(scopes, generation) {
  return flattenRegistryRecords(scopes).map((record) => ({
    customerId: record.customerId,
    deploymentId: record.deploymentId,
    fingerprint: record.fingerprint,
    firstSeenGeneration: generation,
    keyId: record.keyId,
    validFrom: record.validFrom,
    verifyUntilCeiling: record.verifyUntil,
  })).sort(compareBinding);
}

function evolveRegistryHistory(current, candidateScopes, generation) {
  const currentScopes = normalizeRegistryEntries(current.entries).scopes;
  const oldRecords = flattenRegistryRecords(currentScopes);
  const nextRecords = flattenRegistryRecords(candidateScopes);
  const bindings = current.bindings.map((binding) => ({ ...binding }));
  const tombstones = current.tombstones.map((tombstone) => ({ ...tombstone }));
  for (const record of nextRecords) {
    assertRecordHistory(record, oldRecords, bindings, tombstones);
    updateRecordBinding(record, bindings, generation);
  }
  const nextIds = new Set(nextRecords.map((record) => record.keyId));
  for (const record of oldRecords) {
    if (!nextIds.has(record.keyId) && !tombstones.some((item) => item.keyId === record.keyId)) {
      const binding = bindings.find((item) => item.keyId === record.keyId);
      tombstones.push({ ...binding, retiredAtGeneration: generation });
    }
  }
  return {
    bindings: bindings.sort(compareBinding),
    tombstones: tombstones.sort(compareBinding),
  };
}

function assertRecordHistory(record, oldRecords, bindings, tombstones) {
  const byId = bindings.find((item) => item.keyId === record.keyId);
  const byIdentity = bindings.find((item) => item.fingerprint === record.fingerprint);
  if ((byId && byIdentity && byId !== byIdentity)
      || tombstones.some((item) => item.keyId === record.keyId
        || item.fingerprint === record.fingerprint)) {
    throw responseError('customer_response_key_retired');
  }
  const binding = byId || byIdentity;
  if (binding && (binding.keyId !== record.keyId
      || binding.fingerprint !== record.fingerprint
      || binding.customerId !== record.customerId
      || binding.deploymentId !== record.deploymentId
      || binding.validFrom !== record.validFrom)) {
    throw responseError('customer_response_key_identity_reused');
  }
  const previous = oldRecords.find((item) => item.keyId === record.keyId);
  if (previous) assertSlotProgression(previous, record, binding);
  else if (binding) throw responseError('customer_response_key_retired');
}

function assertSlotProgression(previous, record, binding) {
  const rank = { next: 0, current: 1, verifyOnly: 2 };
  if (rank[record.slot] < rank[previous.slot]) {
    throw responseError('customer_response_key_slot_rollback');
  }
  if (previous.slot === 'verifyOnly' && record.slot !== 'verifyOnly') {
    throw responseError('customer_response_key_retired');
  }
  if (record.slot === 'verifyOnly' && binding.verifyUntilCeiling !== null
      && Date.parse(record.verifyUntil) > Date.parse(binding.verifyUntilCeiling)) {
    throw responseError('customer_response_verify_window_extended');
  }
}

function updateRecordBinding(record, bindings, generation) {
  let binding = bindings.find((item) => item.keyId === record.keyId);
  if (!binding) {
    bindings.push({
      customerId: record.customerId,
      deploymentId: record.deploymentId,
      fingerprint: record.fingerprint,
      firstSeenGeneration: generation,
      keyId: record.keyId,
      validFrom: record.validFrom,
      verifyUntilCeiling: record.verifyUntil,
    });
    return;
  }
  if (record.slot === 'verifyOnly') binding.verifyUntilCeiling = record.verifyUntil;
}

function flattenRegistryRecords(scopes) {
  const output = [];
  for (const entry of scopes.values()) {
    for (const record of [entry.current, ...(entry.next ? [entry.next] : []),
      ...entry.verifyOnly]) {
      output.push({
        ...record,
        customerId: entry.customerId,
        deploymentId: entry.deploymentId,
      });
    }
  }
  return output;
}

function registryDocument(scopes, generation, previous, bindings, tombstones) {
  return {
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    recordType: 'customer_audit_response_key_registry',
    generation,
    previousRegistryDigest: previous,
    entries: registryManifest(scopes).entries,
    bindings,
    tombstones,
  };
}

function publicRegistryManifest(state) {
  const scopes = normalizeRegistryEntries(state.entries).scopes;
  return deepFreeze({
    ...registryDocument(
      scopes, state.generation, state.previousRegistryDigest,
      state.bindings, state.tombstones,
    ),
    registryDigest: state.registryDigest,
  });
}

function readRegistryState(database, integrityKey, verifyWitness) {
  const row = database.prepare(`
    SELECT schema_version, state_json, state_mac
    FROM customer_audit_response_registry WHERE singleton = 1
  `).get();
  if (!row || row.schema_version !== REGISTRY_SCHEMA_VERSION) {
    throw responseError('customer_response_registry_rewind');
  }
  verifyRegistryMac(integrityKey, 'state', row.state_json, row.state_mac);
  const state = parseCanonical(row.state_json, 'customer_response_registry_invalid');
  validateRegistryState(state);
  if (verifyWitness) verifyRegistryAnchor(integrityKey, state, readRegistryAnchor(database));
  return state;
}

function validateRegistryState(state) {
  if (!exactKeys(state, [
    'anchorRevision', 'bindings', 'entries', 'generation', 'previousRegistryDigest', 'recordType',
    'registryDigest', 'schemaVersion', 'tombstones', 'trustedTimeMs',
  ]) || state.schemaVersion !== REGISTRY_SCHEMA_VERSION
      || state.recordType !== 'customer_audit_response_key_registry_state'
      || !Number.isSafeInteger(state.anchorRevision) || state.anchorRevision < 1
      || !Number.isSafeInteger(state.generation) || state.generation < 1
      || !Number.isSafeInteger(state.trustedTimeMs) || state.trustedTimeMs < 0
      || !SHA256_RE.test(String(state.previousRegistryDigest || ''))
      || !SHA256_RE.test(String(state.registryDigest || ''))
      || !Array.isArray(state.bindings) || !Array.isArray(state.tombstones)) {
    throw responseError('customer_response_registry_invalid');
  }
  const normalized = normalizeRegistryEntries(state.entries);
  validateRegistryHistory(state, normalized.scopes);
  const document = registryDocument(
    normalized.scopes, state.generation, state.previousRegistryDigest,
    state.bindings, state.tombstones,
  );
  if (sha256(canonical(document)) !== state.registryDigest) {
    throw responseError('customer_response_registry_invalid');
  }
}

function validateRegistryHistory(state, scopes) {
  const bindings = state.bindings.map((item) => checkedBinding(item, false));
  const tombstones = state.tombstones.map((item) => checkedBinding(item, true));
  if (canonical(bindings.slice().sort(compareBinding)) !== canonical(state.bindings)
      || canonical(tombstones.slice().sort(compareBinding)) !== canonical(state.tombstones)) {
    throw responseError('customer_response_registry_invalid');
  }
  const records = flattenRegistryRecords(scopes);
  for (const record of records) {
    const binding = bindings.find((item) => item.keyId === record.keyId);
    if (!binding || binding.fingerprint !== record.fingerprint
        || binding.customerId !== record.customerId
        || binding.deploymentId !== record.deploymentId
        || tombstones.some((item) => item.keyId === record.keyId)) {
      throw responseError('customer_response_registry_invalid');
    }
  }
}

function checkedBinding(raw, tombstone) {
  const keys = [
    'customerId', 'deploymentId', 'fingerprint', 'firstSeenGeneration', 'keyId',
    'validFrom', 'verifyUntilCeiling',
  ];
  if (tombstone) keys.push('retiredAtGeneration');
  const value = exactObject(raw, keys, 'customer_response_registry_invalid');
  checkedScope(value);
  checkedKeyId(value.keyId);
  canonicalIso(value.validFrom, 'customer_response_registry_invalid');
  if (!SHA256_RE.test(String(value.fingerprint || ''))
      || !Number.isSafeInteger(value.firstSeenGeneration) || value.firstSeenGeneration < 1
      || (value.verifyUntilCeiling !== null
        && !canonicalIso(value.verifyUntilCeiling, 'customer_response_registry_invalid'))
      || (tombstone && (!Number.isSafeInteger(value.retiredAtGeneration)
        || value.retiredAtGeneration <= value.firstSeenGeneration))) {
    throw responseError('customer_response_registry_invalid');
  }
  return value;
}

function insertRegistryState(database, integrityKey, state) {
  const document = canonical(state);
  database.prepare(`
    INSERT INTO customer_audit_response_registry
      (singleton, schema_version, state_json, state_mac) VALUES (1, ?, ?, ?)
  `).run(REGISTRY_SCHEMA_VERSION, document, registryMac(integrityKey, 'state', document));
}

function replaceRegistryState(database, integrityKey, state) {
  const document = canonical(state);
  const changed = database.prepare(`
    UPDATE customer_audit_response_registry SET state_json = ?, state_mac = ?
    WHERE singleton = 1 AND schema_version = ?
  `).run(document, registryMac(integrityKey, 'state', document),
    REGISTRY_SCHEMA_VERSION).changes;
  if (changed !== 1) throw responseError('customer_response_registry_conflict');
}

function readRegistryAnchor(database) {
  return database.prepare(`
    SELECT schema_version, anchor_revision, generation, registry_digest, trusted_time_ms, anchor_mac
    FROM registry_witness.customer_audit_response_registry_anchor WHERE singleton = 1
  `).get() || null;
}

function insertRegistryAnchor(database, integrityKey, state) {
  const anchor = registryAnchorDocument(state);
  database.prepare(`
    INSERT INTO registry_witness.customer_audit_response_registry_anchor
      (singleton, schema_version, anchor_revision, generation, registry_digest,
       trusted_time_ms, anchor_mac)
    VALUES (1, ?, ?, ?, ?, ?, ?)
  `).run(REGISTRY_SCHEMA_VERSION, state.anchorRevision, state.generation, state.registryDigest,
    state.trustedTimeMs, registryMac(integrityKey, 'anchor', canonical(anchor)));
}

function replaceRegistryAnchor(database, integrityKey, state) {
  const anchor = registryAnchorDocument(state);
  const changed = database.prepare(`
    UPDATE registry_witness.customer_audit_response_registry_anchor
    SET anchor_revision = ?, generation = ?, registry_digest = ?, trusted_time_ms = ?, anchor_mac = ?
    WHERE singleton = 1 AND schema_version = ?
  `).run(state.anchorRevision, state.generation, state.registryDigest, state.trustedTimeMs,
    registryMac(integrityKey, 'anchor', canonical(anchor)),
    REGISTRY_SCHEMA_VERSION).changes;
  if (changed !== 1) throw responseError('customer_response_registry_rewind');
}

function verifyRegistryAnchor(integrityKey, state, row) {
  if (!row || row.schema_version !== REGISTRY_SCHEMA_VERSION
      || row.anchor_revision !== state.anchorRevision
      || row.generation !== state.generation
      || row.registry_digest !== state.registryDigest
      || row.trusted_time_ms !== state.trustedTimeMs) {
    throw responseError('customer_response_registry_rewind');
  }
  const anchor = registryAnchorDocument(state);
  verifyRegistryMac(integrityKey, 'anchor', canonical(anchor), row.anchor_mac);
}

function registryAnchorDocument(state) {
  return {
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    anchorRevision: state.anchorRevision,
    generation: state.generation,
    registryDigest: state.registryDigest,
    trustedTimeMs: state.trustedTimeMs,
  };
}

function readAnchoredRegistryManifest(database, integrityKey, anchorAuthority, anchorNamespace) {
  database.exec('BEGIN IMMEDIATE');
  try {
    reconcileRegistryAnchor(database, integrityKey, anchorAuthority, anchorNamespace);
    const state = readRegistryState(database, integrityKey, true);
    assertRegistryExternalCurrent(anchorAuthority.read(anchorNamespace), state);
    database.exec('COMMIT');
    return publicRegistryManifest(state);
  } catch (error) {
    try { database.exec('ROLLBACK'); } catch {}
    throw error;
  }
}

function reconcileRegistryAnchor(database, integrityKey, anchorAuthority, anchorNamespace) {
  const row = database.prepare(`
    SELECT state_json FROM customer_audit_response_registry WHERE singleton = 1
  `).get();
  const localAnchor = readRegistryAnchor(database);
  let external = checkedExternalAnchorState(anchorAuthority.read(anchorNamespace), anchorNamespace);
  if (!row && !localAnchor) {
    if (external.pending || external.revision !== 0 || external.headDigest !== ZERO_DIGEST) {
      throw responseError('customer_response_registry_anchor_mismatch');
    }
    return;
  }
  if (!row || !localAnchor) throw responseError('customer_response_registry_rewind');
  const state = readRegistryState(database, integrityKey, true);
  if (external.pending) {
    const transition = registryTransitionFromExternal(anchorNamespace, external);
    const localDigest = registryExternalHead(state);
    if (state.anchorRevision === transition.targetRevision
        && localDigest === transition.targetDigest) {
      assertRegistryAnchorFinalized(anchorAuthority.finalize(transition), transition);
    } else if (state.anchorRevision === transition.expectedRevision
        && localDigest === transition.expectedDigest) {
      anchorAuthority.abort(transition);
    } else throw responseError('customer_response_registry_anchor_mismatch');
    external = checkedExternalAnchorState(anchorAuthority.read(anchorNamespace), anchorNamespace);
  }
  assertRegistryExternalCurrent(external, state);
}

function registryAnchorTransition(namespace, previous, next, integrityKey) {
  const document = registryAnchorDocument(next);
  return {
    namespace,
    expectedRevision: previous ? previous.anchorRevision : 0,
    expectedDigest: previous ? registryExternalHead(previous) : ZERO_DIGEST,
    targetRevision: next.anchorRevision,
    targetDigest: registryExternalHead(next),
    witnessDigest: sha256(canonical({
      document,
      mac: registryMac(integrityKey, 'anchor', canonical(document)),
    })),
  };
}

function registryExternalHead(state) {
  return sha256(canonical(registryAnchorDocument(state)));
}

function registryTransitionFromExternal(namespace, state) {
  return {
    namespace,
    expectedRevision: state.pending.expectedRevision,
    expectedDigest: state.pending.expectedDigest,
    targetRevision: state.pending.targetRevision,
    targetDigest: state.pending.targetDigest,
    witnessDigest: state.pending.witnessDigest,
  };
}

function assertRegistryExternalCurrent(rawState, state) {
  const external = checkedExternalAnchorState(rawState);
  if (external.pending || external.revision !== state.anchorRevision
      || external.headDigest !== registryExternalHead(state)) {
    throw responseError('customer_response_registry_anchor_mismatch');
  }
}

function assertRegistryAnchorPrepared(rawState, transition) {
  const state = checkedExternalAnchorState(rawState, transition.namespace);
  if (!state.pending || state.revision !== transition.expectedRevision
      || state.headDigest !== transition.expectedDigest
      || canonical(registryTransitionFromExternal(transition.namespace, state))
        !== canonical(transition)) {
    throw responseError('customer_response_registry_anchor_prepare_failed');
  }
}

function assertRegistryAnchorFinalized(rawState, transition) {
  const state = checkedExternalAnchorState(rawState, transition.namespace);
  if (state.pending || state.revision !== transition.targetRevision
      || state.headDigest !== transition.targetDigest) {
    throw responseError('customer_response_registry_anchor_finalize_failed');
  }
}

function checkedExternalAnchorState(value, namespace) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !Number.isSafeInteger(value.revision) || value.revision < 0
      || !SHA256_RE.test(String(value.headDigest || ''))
      || (namespace !== undefined && value.namespace !== namespace)
      || (value.pending !== null && (!value.pending || typeof value.pending !== 'object'))) {
    throw responseError('customer_response_registry_anchor_invalid');
  }
  return value;
}

function registryMac(key, domain, message) {
  return crypto.createHmac('sha256', key)
    .update(`customer-audit-response-registry:${domain}\0${message}`, 'utf8')
    .digest('base64url');
}

function verifyRegistryMac(key, domain, message, actual) {
  const expected = registryMac(key, domain, message);
  const left = Buffer.from(String(actual || ''), 'utf8');
  const right = Buffer.from(expected, 'utf8');
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) {
    throw responseError('customer_response_registry_integrity_failed');
  }
}

function checkedRegistrySecret(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) {
    throw responseError('customer_response_registry_integrity_required');
  }
  return Buffer.from(value);
}

function checkedAnchorNamespace(value) {
  if (!ANCHOR_NAMESPACE_RE.test(String(value || ''))) {
    throw responseError('customer_response_registry_anchor_namespace_required');
  }
  return value;
}

function checkedAnchorAuthority(value, integrityKey) {
  const methods = ['abort', 'describe', 'finalize', 'prepare', 'read'];
  if (!value || typeof value !== 'object'
      || methods.some((method) => typeof value[method] !== 'function')) {
    throw responseError('customer_response_registry_anchor_required');
  }
  const descriptor = value.describe();
  const integrityIdentity = sha256(integrityKey);
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)
      || descriptor.purpose !== RESPONSE_REGISTRY_ANCHOR_PURPOSE
      || ![INDEPENDENT_WITNESS_ASSURANCE, TEST_WITNESS_ASSURANCE]
        .includes(descriptor.assurance)
      || !SHA256_RE.test(String(descriptor.identity || ''))
      || descriptor.identity === integrityIdentity) {
    throw responseError('customer_response_registry_anchor_required');
  }
  return value;
}

function parseCanonical(value, code) {
  let parsed;
  try { parsed = JSON.parse(value); } catch { throw responseError(code); }
  if (canonical(parsed) !== value) throw responseError(code);
  return parsed;
}

function compareBinding(left, right) {
  return left.keyId.localeCompare(right.keyId);
}

function checkedClock(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw responseError('customer_response_registry_clock_invalid');
  }
  return value;
}

function assertRegistryOpen(closed) {
  if (closed) throw responseError('customer_response_registry_closed');
}

function checkedRegistryEntry(raw, identities, keyIds) {
  const value = exactObject(raw, [
    'current', 'customerId', 'deploymentId', 'next', 'verifyOnly',
  ], 'customer_response_registry_invalid');
  checkedScope(value);
  if (!Array.isArray(value.verifyOnly) || value.verifyOnly.length > MAX_VERIFY_ONLY_KEYS) {
    throw responseError('customer_response_registry_invalid');
  }
  const current = checkedPublicKey(value.current, 'current');
  const next = value.next === null ? null : checkedPublicKey(value.next, 'next');
  const verifyOnly = value.verifyOnly.map((item) => checkedPublicKey(item, 'verifyOnly'));
  for (const record of [current, ...(next ? [next] : []), ...verifyOnly]) {
    if (identities.has(record.fingerprint) || keyIds.has(record.keyId)) {
      throw responseError('customer_response_key_identity_reused');
    }
    identities.add(record.fingerprint);
    keyIds.add(record.keyId);
  }
  return Object.freeze({ ...checkedScope(value), current, next, verifyOnly: Object.freeze(verifyOnly) });
}

function checkedPublicKey(raw, slot) {
  const keys = slot === 'verifyOnly'
    ? ['keyId', 'publicKey', 'validFrom', 'verifyUntil']
    : ['keyId', 'publicKey', 'validFrom'];
  const value = exactObject(raw, keys, 'customer_response_registry_invalid');
  const keyId = checkedKeyId(value.keyId);
  const publicKey = publicEd25519(value.publicKey);
  const validFrom = canonicalIso(value.validFrom, 'customer_response_registry_invalid');
  const verifyUntil = slot === 'verifyOnly'
    ? canonicalIso(value.verifyUntil, 'customer_response_registry_invalid') : null;
  if (verifyUntil !== null && Date.parse(verifyUntil) <= Date.parse(validFrom)) {
    throw responseError('customer_response_registry_invalid');
  }
  return Object.freeze({
    keyId, publicKey, fingerprint: keyFingerprint(publicKey), slot, validFrom, verifyUntil,
  });
}

function verifyWithRegistry(scopes, currentMs, rawQuery) {
  try {
    const query = exactObject(rawQuery, [
      'customerId', 'deploymentId', 'domain', 'issuedAt', 'keyId', 'message', 'signature',
    ], 'customer_response_verification_invalid');
    checkedScope(query);
    if (query.domain !== CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN
        || !KEY_ID_RE.test(String(query.keyId || ''))
        || typeof query.message !== 'string'
        || Buffer.byteLength(query.message, 'utf8') > MAX_RESPONSE_BYTES) return false;
    const issuedMs = Date.parse(canonicalIso(query.issuedAt, 'customer_response_verification_invalid'));
    const entry = scopes.get(scopeKey(query.customerId, query.deploymentId));
    if (!entry) return false;
    const record = [entry.current, ...(entry.next ? [entry.next] : []), ...entry.verifyOnly]
      .find((candidate) => candidate.keyId === query.keyId);
    if (!record || issuedMs < Date.parse(record.validFrom)) return false;
    if (!Number.isSafeInteger(currentMs) || currentMs < 0) return false;
    if (record.verifyUntil !== null
        && (issuedMs > Date.parse(record.verifyUntil)
          || currentMs > Date.parse(record.verifyUntil))) {
      return false;
    }
    return crypto.verify(
      null,
      Buffer.from(`${query.domain}\0${query.keyId}\0${query.message}`, 'utf8'),
      record.publicKey,
      canonicalSignature(query.signature),
    );
  } catch { return false; }
}

function registryManifest(scopes) {
  const summarize = (record) => record && Object.freeze({
    keyId: record.keyId,
    fingerprint: record.fingerprint,
    slot: record.slot,
    validFrom: record.validFrom,
    verifyUntil: record.verifyUntil,
  });
  const entries = [...scopes.values()].map((entry) => Object.freeze({
    customerId: entry.customerId,
    deploymentId: entry.deploymentId,
    current: summarize(entry.current),
    next: summarize(entry.next),
    verifyOnly: Object.freeze(entry.verifyOnly.map(summarize)),
  })).sort((left, right) => scopeKey(left.customerId, left.deploymentId)
    .localeCompare(scopeKey(right.customerId, right.deploymentId)));
  return deepFreeze({ schemaVersion: 1, recordType: 'customer_audit_response_key_registry', entries });
}

function assertDecisionBinding(value) {
  const bindings = {
    approved: ['completed', 'completed'],
    denied: ['denied', 'customer_denied'],
    expired: ['expired', 'request_expired'],
    revoked: ['revoked', 'customer_revoked'],
  };
  const [status, reason] = bindings[value.decision];
  if (value.status !== status || value.reasonCode !== reason) {
    throw responseError('customer_response_decision_mismatch');
  }
}

function checkedScope(value) {
  if (!CUSTOMER_ID_RE.test(String(value.customerId || ''))
      || !isDeploymentId(value.deploymentId)) {
    throw responseError('customer_response_scope_invalid');
  }
  return { customerId: value.customerId, deploymentId: value.deploymentId };
}

function checkedNow(value) {
  const now = value === undefined ? Date.now : value;
  if (typeof now !== 'function') throw responseError('customer_response_registry_invalid');
  const probe = now();
  if (!Number.isSafeInteger(probe) || probe < 0) {
    throw responseError('customer_response_registry_invalid');
  }
  return now;
}

function checkedKeyId(value) {
  if (!KEY_ID_RE.test(String(value || ''))) throw responseError('customer_response_key_id_invalid');
  return value;
}

function publicEd25519(value) {
  let key;
  try { key = value instanceof crypto.KeyObject ? value : crypto.createPublicKey(value); }
  catch { throw responseError('customer_response_public_key_invalid'); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw responseError('customer_response_public_key_invalid');
  }
  return key;
}

function keyFingerprint(key) {
  return sha256(key.export({ format: 'der', type: 'spki' }));
}

function canonicalSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw responseError('customer_response_signature_invalid');
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== value) {
    throw responseError('customer_response_signature_invalid');
  }
  return decoded;
}

function boundedSnapshot(value, code) {
  let serialized;
  try { serialized = JSON.stringify(value); }
  catch { throw responseError(code); }
  if (typeof serialized !== 'string' || Buffer.byteLength(serialized, 'utf8') > MAX_RESPONSE_BYTES) {
    throw responseError(code);
  }
  return JSON.parse(serialized);
}

function exactOptionalObject(value, allowed, code) {
  if (!plainObject(value) || Object.keys(value).some((key) => !allowed.includes(key))) {
    throw responseError(code);
  }
  return descriptorValues(value, code);
}

function exactObject(value, keys, code) {
  if (!plainObject(value) || !exactKeys(value, keys)) throw responseError(code);
  return descriptorValues(value, code);
}

function descriptorValues(value, code) {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set
      || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true)) {
    throw responseError(code);
  }
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
}

function exactKeys(value, keys) {
  return plainObject(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function canonicalIso(value, code) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw responseError(code);
  }
  return value;
}

function scopeKey(customerId, deploymentId) { return `${customerId}\0${deploymentId}`; }
function canonical(value) { return protocol.canonicalJson(value); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

function responseError(code) {
  const error = new Error('customer audit response rejected');
  error.code = code;
  return error;
}

function assertReferenceRuntime() {
  if (process.env.NODE_ENV === 'production') {
    throw responseError('customer_response_reference_runtime_forbidden');
  }
}

module.exports = {
  CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN,
  assertCustomerAuditResponsePayload,
  createCustomerAuditResponseKeyRegistry,
  createCustomerAuditResponseSigner,
  customerAuditResponseClaim,
  customerAuditResponseSigningInput,
  isCustomerAuditResponseKeyRegistry,
  isCustomerAuditResponseSigner,
  verifyCustomerAuditResponse,
};
