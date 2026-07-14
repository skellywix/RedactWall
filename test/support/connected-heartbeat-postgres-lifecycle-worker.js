'use strict';

const crypto = require('node:crypto');
const protocol = require('../../server/vendor-control-protocol');
const onlineVerdict = require('../../server/connected-online-verdict');
const storage = require('../../server/storage');

const CUSTOMER_ID = process.env.REDACTWALL_TENANT_ID;
const DEPLOYMENT_ID = process.env.REDACTWALL_CONNECTED_DEPLOYMENT_ID;
const OTHER_CUSTOMER_ID = 'customer_pg_connected_other';
const NOW = Date.parse('2026-07-13T15:00:00.000Z');
const REGISTRY_GENERATION = 41;
const LAST_ACTIVE_VERSION = 34;
const PAUSED_VERSION = LAST_ACTIVE_VERSION + 1;
const REVOKED_VERSION = PAUSED_VERSION + 1;
const CONNECTED_TABLES = Object.freeze([
  'connected_entitlement_state',
  'connected_ack_outbox',
  'connected_online_registry_state',
  'connected_ack_health',
  'connected_ack_archive',
  'connected_ack_archive_mutations',
]);
const PUBLIC_AUTHORITY_RELATIONS = Object.freeze([
  'schema_migrations', 'redactwall_audit_scope', ...CONNECTED_TABLES,
]);

let db;

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function privateKey(name) {
  const encoded = String(process.env[name] || '');
  if (!encoded) throw new Error(`${name} is required`);
  return crypto.createPrivateKey(Buffer.from(encoded, 'base64').toString('utf8'));
}

function messageId(version) {
  return `00000000-0000-4000-8000-${version.toString(16).padStart(12, '0')}`;
}

function entitlement(version, status = 'active') {
  const issuedAt = NOW + (version * 1000);
  return {
    schemaVersion: 1,
    messageId: messageId(version),
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status,
    plan: 'enterprise',
    seats: 40,
    features: ['policy'],
    entitlementVersion: version,
    previousVersion: version - 1,
    issuedAt: new Date(issuedAt).toISOString(),
    expiresAt: new Date(issuedAt + (5 * 60 * 1000)).toISOString(),
    fallbackUntil: status === 'active'
      ? new Date(issuedAt + (3 * 24 * 60 * 60 * 1000)).toISOString() : null,
    reasonCode: status === 'active' ? 'billing_active'
      : status === 'paused' ? 'manual_pause' : 'manual_revoke',
  };
}

function signedEntitlement(version, status = 'active') {
  const payload = entitlement(version, status);
  const keyId = process.env.REDACTWALL_ENTITLEMENT_KEY_ID;
  const signature = crypto.sign(
    null, protocol.signingInput(payload, keyId), privateKey('RW_TEST_ENTITLEMENT_PRIVATE_KEY_B64'),
  ).toString('base64');
  return { keyId, payload, signature };
}

function verdictPayload(generation) {
  const publicKey = process.env.REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY;
  return {
    kind: onlineVerdict.VERDICT_DOMAIN,
    keyId: onlineVerdict.keyIdForPublicKey(publicKey),
    status: 'active',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    issuedAt: new Date(NOW).toISOString(),
    registryGeneration: generation,
    registryStateDigest: sha256(`registry\0${generation}\0active`),
  };
}

function signedVerdict(generation = REGISTRY_GENERATION) {
  const value = verdictPayload(generation);
  const payload = Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
  const input = Buffer.from(`${onlineVerdict.VERDICT_DOMAIN}\0${payload}`, 'utf8');
  const signature = crypto.sign(
    null, input, privateKey('RW_TEST_VERDICT_PRIVATE_KEY_B64'),
  ).toString('base64');
  return `${payload}.${signature}`;
}

function applyResponse(version, status = 'active', generation = REGISTRY_GENERATION, artifact = null) {
  return db.applyConnectedHeartbeatResponse({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedOnlineRegistryVerdict: signedVerdict(generation),
    signedEntitlementArtifact: artifact || signedEntitlement(version, status),
    nowMs: NOW + (version * 1000),
    randomUUID: () => messageId(version),
    clock: { bootId: '4'.repeat(32), nowMs: 10_000 + (version * 1000) },
  });
}

function ackInput(row, nowMs) {
  return {
    id: row.id,
    customerId: row.customerId,
    deploymentId: row.deploymentId,
    payloadDigest: row.payloadDigest,
    accepted: true,
    nowMs,
  };
}

function acknowledgePair(result, nowMs) {
  const delivered = db.recordConnectedAcknowledgementResult(
    ackInput(result.outboxes.delivered, nowMs),
  );
  const applied = db.recordConnectedAcknowledgementResult(
    ackInput(result.outboxes.applied, nowMs + 1),
  );
  return { delivered, applied };
}

function tableCount(table) {
  return db._db.prepare(`SELECT COUNT(*) AS n FROM public.${table}`).get().n;
}

function connectedCounts() {
  return Object.fromEntries(CONNECTED_TABLES.map((table) => [table, tableCount(table)]));
}

function acknowledgementRows(version) {
  return db._db.prepare(`SELECT id, target_version, lifecycle_stage, status,
      attempts, failure_class, payload_digest, created_at, updated_at
    FROM public.connected_ack_outbox
    WHERE customer_id = ? AND deployment_id = ? AND target_version = ?
    ORDER BY CASE lifecycle_stage WHEN 'delivered' THEN 0 ELSE 1 END`)
    .all(CUSTOMER_ID, DEPLOYMENT_ID, version);
}

function mutationSnapshot() {
  const statements = [
    `SELECT customer_id, deployment_id, authority_ref, entitlement_version,
       entitlement_digest, state_json, updated_at
     FROM public.connected_entitlement_state ORDER BY customer_id, deployment_id`,
    `SELECT customer_id, deployment_id, authority_ref, registry_generation,
       registry_state_digest, status, state_json, updated_at
     FROM public.connected_online_registry_state ORDER BY customer_id, deployment_id`,
    `SELECT id, customer_id, deployment_id, target_kind, target_version, target_digest,
       lifecycle_stage, payload_json, payload_digest, status, failure_class, attempts,
       next_attempt_at, created_at, updated_at
     FROM public.connected_ack_outbox ORDER BY id`,
    `SELECT customer_id, deployment_id, authority_ref, state_json, updated_at
     FROM public.connected_ack_health ORDER BY customer_id, deployment_id`,
    `SELECT archive_seq, id, customer_id, deployment_id, target_kind, target_version,
       target_digest, lifecycle_stage, payload_json, payload_digest, status, failure_class,
       attempts, next_attempt_at, created_at, updated_at, archived_at
     FROM public.connected_ack_archive ORDER BY archive_seq`,
    `SELECT event_seq, customer_id, deployment_id, scope_seq, mutation_kind,
       archive_seq, archive_id
     FROM public.connected_ack_archive_mutations ORDER BY event_seq`,
    `SELECT seq, id, ts, action, "queryId", actor, "prevHash", hash, entry
     FROM public.audit ORDER BY seq`,
  ];
  return sha256(JSON.stringify(statements.map((sql) => db._db.prepare(sql).all())));
}

function invalidCompositeRollback() {
  const artifact = signedEntitlement(1);
  artifact.signature = Buffer.alloc(64, 0x5a).toString('base64');
  let code = null;
  try { applyResponse(1, 'active', REGISTRY_GENERATION - 1, artifact); }
  catch (error) { code = error.code || error.message; }
  return { code, counts: connectedCounts(), audit: tableCount('audit') };
}

function firstApplyAndReplay() {
  const first = applyResponse(1);
  const firstRows = acknowledgementRows(1);
  const before = mutationSnapshot();
  const replay = applyResponse(1);
  const after = mutationSnapshot();
  return { first, replay, firstRows, mutationFree: before === after };
}

function markFirstPair(first) {
  const prematureDigest = mutationSnapshot();
  const premature = db.recordConnectedAcknowledgementResult(
    ackInput(first.entitlement.outboxes.applied, NOW + 2100),
  );
  const prematureMutationFree = prematureDigest === mutationSnapshot();
  const delivered = db.recordConnectedAcknowledgementResult(
    ackInput(first.entitlement.outboxes.delivered, NOW + 2200),
  );
  const exposed = db.pendingConnectedAcknowledgements({
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID, nowMs: NOW + 2300, limit: 10,
  }).filter((row) => row.acknowledgement.targetVersion === 1);
  const applied = db.recordConnectedAcknowledgementResult(
    ackInput(first.entitlement.outboxes.applied, NOW + 2400),
  );
  return { premature, prematureMutationFree, delivered, applied, exposed };
}

function advanceAndCompact(second) {
  let previous = second.entitlement;
  for (let version = 3; version <= LAST_ACTIVE_VERSION; version += 1) {
    const current = applyResponse(version);
    acknowledgePair(previous, NOW + (version * 1000) + 100);
    previous = current.entitlement;
  }
  return previous;
}

function ledgerState() {
  const row = db._db.prepare(`SELECT state_json FROM public.connected_ack_health
    WHERE customer_id = ? AND deployment_id = ?`).get(CUSTOMER_ID, DEPLOYMENT_ID);
  return JSON.parse(row.state_json);
}

function pendingVersions() {
  return db._db.prepare(`SELECT target_version, COUNT(*) AS count
    FROM public.connected_ack_outbox WHERE status = 'pending'
    GROUP BY target_version ORDER BY target_version`).all();
}

function exerciseLifecycle() {
  const rollback = invalidCompositeRollback();
  const initial = firstApplyAndReplay();
  const second = applyResponse(2);
  const secondAckRows = acknowledgementRows(2);
  const marking = markFirstPair(initial.first);
  advanceAndCompact(second);
  const paused = applyResponse(PAUSED_VERSION, 'paused');
  const pausedDisposition = db.connectedLicensingDisposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + (PAUSED_VERSION * 1000) + 1,
  });
  const revoked = applyResponse(REVOKED_VERSION, 'revoked');
  const revokedDisposition = db.connectedLicensingDisposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + (REVOKED_VERSION * 1000) + 1,
  });
  const chain = db.verifyAuditChain();
  return lifecycleEvidence({ rollback, initial, second, secondAckRows, marking, paused, revoked,
    pausedDisposition, revokedDisposition, chain });
}

function lifecycleEvidence(values) {
  const { rollback, initial, second, marking, paused, revoked } = values;
  return {
    driverKind: db._driverKind,
    rollback,
    first: summarizeApply(initial.first),
    replay: summarizeApply(initial.replay),
    replayMutationFree: initial.mutationFree,
    firstAckRows: initial.firstRows,
    second: summarizeApply(second),
    secondAckRows: values.secondAckRows,
    marking: summarizeMarking(marking),
    paused: summarizeApply(paused),
    revoked: summarizeApply(revoked),
    pausedDisposition: values.pausedDisposition,
    revokedDisposition: values.revokedDisposition,
    pendingVersions: pendingVersions(),
    counts: connectedCounts(),
    ledger: ledgerState(),
    chain: values.chain,
  };
}

function summarizeApply(result) {
  return {
    contactAdvanced: result.contactAdvanced,
    registryContactAdvanced: result.registry.contactAdvanced,
    registryGeneration: result.registry.state.registryGeneration,
    entitlementVersion: result.entitlement.state.entitlementVersion,
    entitlementStatus: result.entitlement.state.entitlement.status,
    entitlementIdempotent: result.entitlement.idempotent,
    registryLastContactAt: result.registry.state.lastContactAt,
    entitlementLastContactAt: result.entitlement.state.lastContactAt,
  };
}

function summarizeMarking(value) {
  return {
    premature: value.premature,
    prematureMutationFree: value.prematureMutationFree,
    deliveredStatus: value.delivered && value.delivered.status,
    appliedStatus: value.applied && value.applied.status,
    exposedStages: value.exposed.map((row) => row.acknowledgement.lifecycleStage),
  };
}

function attempt(callback) {
  try { return { ok: true, value: callback() }; }
  catch (error) { return { ok: false, code: error.code || null, message: error.message }; }
}

function directOwnerIdentity() {
  return db._db.prepare(`SELECT current_user AS current_role,
      session_user AS session_role,
      pg_get_userbyid(d.datdba) AS database_owner,
      r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole,
      current_setting('search_path') AS search_path
    FROM pg_catalog.pg_database d
    JOIN pg_catalog.pg_roles r ON r.rolname = current_user
    WHERE d.datname = current_database()`).get();
}

function searchPathEvidence() {
  const placeholders = PUBLIC_AUTHORITY_RELATIONS.map(() => '?').join(', ');
  const relations = db._db.prepare(`SELECT n.nspname AS schema_name, c.relname
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
      AND c.relname IN (${placeholders})
    ORDER BY c.relname, n.nspname`).all(...PUBLIC_AUTHORITY_RELATIONS);
  const attackerRelations = db._db.prepare(`SELECT c.relname, c.relkind
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'attacker' ORDER BY c.relname`).all();
  const attackerRoutines = db._db.prepare(`SELECT p.proname
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'attacker' ORDER BY p.proname`).all();
  return { relations, attackerRelations, attackerRoutines };
}

function migrationRows(schema) {
  if (!['public', 'attacker', 'pg_temp'].includes(schema)) throw new Error('invalid ledger schema');
  return db._db.prepare(`SELECT version, name FROM ${schema}.schema_migrations
    ORDER BY version`).all();
}

function migrationAppliedEvidence() {
  return {
    publicVersion8: storage.migrationApplied(db._db, 'postgres', 8),
    tempOnlyVersion999: storage.migrationApplied(db._db, 'postgres', 999),
  };
}

function migrationAuthorityEvidence() {
  const publicBefore = migrationRows('public');
  const attackerBefore = migrationRows('attacker');
  db._db.exec(`CREATE TEMP TABLE schema_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, appliedAt TEXT NOT NULL
  )`);
  db._db.prepare(`INSERT INTO pg_temp.schema_migrations
    (version, name, appliedAt) VALUES (?, ?, ?)`).run(
    999, 'temp-shadow', new Date(NOW).toISOString(),
  );
  const appliedBefore = migrationAppliedEvidence();
  const runResult = storage.runMigrations(db._db, 'postgres');
  return {
    publicBefore,
    publicAfter: migrationRows('public'),
    attackerBefore,
    attackerAfter: migrationRows('attacker'),
    tempAfter: migrationRows('pg_temp'),
    appliedBefore,
    appliedAfter: migrationAppliedEvidence(),
    runResult,
  };
}

function rlsEvidence() {
  const ownCounts = connectedCounts();
  const crossInsert = attempt(() => db._db.prepare(`INSERT INTO public.connected_online_registry_state
    (customer_id, deployment_id, authority_ref, registry_generation,
     registry_state_digest, status, state_json, updated_at)
    VALUES (?, ?, ?, 1, ?, 'active', '{}', ?)`).run(
    OTHER_CUSTOMER_ID, DEPLOYMENT_ID, 'connected_registry_cross_tenant',
    'e'.repeat(64), new Date(NOW).toISOString(),
  ));
  db.setTenantContext(OTHER_CUSTOMER_ID);
  let hiddenCounts;
  let hiddenUpdate;
  try {
    hiddenCounts = connectedCounts();
    hiddenUpdate = db._db.prepare(`UPDATE public.connected_entitlement_state
      SET updated_at = updated_at WHERE customer_id = ?`).run(CUSTOMER_ID).changes;
  } finally {
    db.setTenantContext(CUSTOMER_ID);
  }
  return { ownCounts, crossInsert, hiddenCounts, hiddenUpdate };
}

function restartEvidence() {
  const state = db.connectedHeartbeatState(CUSTOMER_ID, DEPLOYMENT_ID);
  const disposition = db.connectedLicensingDisposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    nowMs: NOW + (REVOKED_VERSION * 1000) + 2000,
  });
  const migrations = migrationAuthorityEvidence();
  const postShadow = db.connectedHeartbeatState(CUSTOMER_ID, DEPLOYMENT_ID);
  return {
    identity: directOwnerIdentity(),
    entitlementVersion: state.entitlement.entitlementVersion,
    entitlementStatus: state.entitlement.entitlement.status,
    registryGeneration: state.registry.registryGeneration,
    disposition,
    health: db.connectedAcknowledgementHealth(CUSTOMER_ID, DEPLOYMENT_ID),
    pendingVersions: pendingVersions(),
    counts: connectedCounts(),
    ledger: ledgerState(),
    migrations,
    postShadowEntitlementVersion: postShadow.entitlement.entitlementVersion,
    searchPath: searchPathEvidence(),
    rls: rlsEvidence(),
    chain: db.verifyAuditChain(),
  };
}

function integrityProbe() {
  return {
    chain: attempt(() => db.verifyAuditChain()),
    state: attempt(() => db.connectedHeartbeatState(CUSTOMER_ID, DEPLOYMENT_ID)),
    disposition: attempt(() => db.connectedLicensingDisposition(CUSTOMER_ID, DEPLOYMENT_ID, {
      nowMs: NOW + (REVOKED_VERSION * 1000) + 3000,
    })),
  };
}

async function closeDatabase() {
  await new Promise((resolve) => setImmediate(resolve));
  if (db && db._db && typeof db._db.close === 'function') db._db.close();
}

function send(payload) {
  if (typeof process.send === 'function') {
    process.send(payload, () => process.exit(0));
    return;
  }
  process.stdout.write(JSON.stringify(payload));
}

async function main() {
  const mode = process.argv[2];
  try {
    db = require('../../server/db');
  } catch (error) {
    send({ ok: false, stage: 'startup', code: error.code || null, message: error.message });
    return;
  }
  try {
    const value = mode === 'exercise' ? exerciseLifecycle()
      : mode === 'restart' ? restartEvidence()
        : mode === 'probe-integrity' ? integrityProbe() : null;
    if (!value) throw new Error(`unsupported worker mode: ${mode}`);
    await closeDatabase();
    send({ ok: true, value });
  } catch (error) {
    await closeDatabase().catch(() => {});
    send({ ok: false, stage: 'operation', code: error.code || null, message: error.message });
  }
}

main();
