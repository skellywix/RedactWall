'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const registryState = require('./connected-online-registry-state');
const { isDeploymentId } = require('./deployment-identity');
const {
  isConnectedHeartbeatTransactionCoordinator,
} = require('./connected-heartbeat-apply-store');

const STATE_VERSION = 3;
const MAX_LIVE_PAIR_LINEAGES = 1024;
// Deletions are intentionally read as one authenticated per-scope chain. Do not
// raise this release gate without adding a separately authenticated prefix
// checkpoint plus a bounded suffix; summary-only compaction is not authority.
const MAX_DELETION_HISTORY_ROWS = 4096;
const MAX_DELETION_ROW_BYTES = 2048;
const MAX_AUTHORITY_CATALOG_ROWS = 256;
const MAX_AUTHORITY_CATALOG_SQL_BYTES = 65536;
const MAX_STATE_JSON_BYTES = 4096;
const MAX_AUDIT_ENTRY_BYTES = 32768;
const MAX_AUTHORITY_JSON_BYTES = 16384;
const INVALID_TEXT_PROJECTION = '';
const INVALID_NUMERIC_PROJECTION = -9007199254740991;
const TRANSITION_KINDS = Object.freeze({
  ENTITLEMENT_RELEASE: 'entitlement_release',
  REGISTRY_ONLY: 'registry_only',
});
const EMPTY_HISTORY_DIGEST = sha256('redactwall.connected-authority-pair-history.empty.v1');
const EMPTY_DELETION_DIGEST = sha256(
  'redactwall.connected-authority-pair-deletions.empty.v1',
);
const STATE_ACTIONS = Object.freeze([
  'CONNECTED_ACKNOWLEDGED_AUTHORITY_STAGED',
  'CONNECTED_ACKNOWLEDGED_AUTHORITY_ADVANCED',
  'CONNECTED_ACKNOWLEDGED_AUTHORITY_COMPACTED',
]);
const AUTHORITY_TABLES = Object.freeze([
  'connected_acknowledged_authority_state',
  'connected_authority_pair_lineage',
  'connected_authority_pair_deletions',
]);
const SQLITE_RESERVED_OBJECTS = Object.freeze([
  ...AUTHORITY_TABLES,
  'connected_authority_pair_no_update',
  'connected_authority_pair_record_delete',
  'connected_authority_pair_deletions_no_update',
  'connected_authority_pair_deletions_no_delete',
  'idx_connected_authority_pair_ack',
  'idx_connected_authority_pair_high_water',
  'idx_connected_authority_pair_deletion_scope',
  'idx_connected_acknowledged_authority_high_water',
]);
const SQLITE_AUTHORITY_CATALOG_IDENTITY =
  'f43aa6d59a5a88a277d14be8ffde25d0f21c9d7e341f506aedcd95d92f1f7c63';
const STATE_COLUMNS = Object.freeze([
  'customer_id',
  'deployment_id',
  'authority_ref',
  'current_pair_digest',
  'current_registry_generation',
  'current_registry_state_digest',
  'current_entitlement_version',
  'current_entitlement_digest',
  'acknowledged_registry_generation',
  'acknowledged_registry_state_digest',
  'acknowledged_entitlement_version',
  'acknowledged_entitlement_digest',
  'acknowledged_pair_digest',
  'history_count',
  'history_digest',
  'deletion_count',
  'deletion_high_water',
  'deletion_digest',
  'state_json',
  'updated_at',
]);
const STATE_TEXT_LIMITS = Object.freeze({
  customer_id: 63,
  deployment_id: 36,
  authority_ref: 106,
  current_pair_digest: 64,
  current_registry_state_digest: 64,
  current_entitlement_digest: 64,
  acknowledged_registry_state_digest: 64,
  acknowledged_entitlement_digest: 64,
  acknowledged_pair_digest: 64,
  history_digest: 64,
  deletion_digest: 64,
  state_json: MAX_STATE_JSON_BYTES,
  updated_at: 24,
});
const STATE_NUMERIC_COLUMNS = new Set([
  'current_registry_generation', 'current_entitlement_version',
  'acknowledged_registry_generation', 'acknowledged_entitlement_version',
  'history_count', 'deletion_count', 'deletion_high_water',
]);
const PAIR_COLUMNS = Object.freeze([
  'pair_digest',
  'customer_id',
  'deployment_id',
  'transition_kind',
  'registry_generation',
  'registry_state_digest',
  'registry_status',
  'entitlement_version',
  'entitlement_digest',
  'artifact_digest',
  'entitlement_status',
  'authority_json',
  'entitlement_issued_at',
  'entitlement_expires_at',
  'entitlement_fallback_until',
  'entitlement_reason_code',
  'entitlement_signing_key_id',
  'delivered_ack_id',
  'delivered_ack_payload_digest',
  'applied_ack_id',
  'applied_ack_payload_digest',
  'created_at',
]);
const PAIR_TEXT_LIMITS = Object.freeze({
  pair_digest: 64,
  customer_id: 63,
  deployment_id: 36,
  transition_kind: 32,
  registry_state_digest: 64,
  registry_status: 7,
  entitlement_digest: 64,
  artifact_digest: 64,
  entitlement_status: 7,
  authority_json: MAX_AUTHORITY_JSON_BYTES,
  entitlement_issued_at: 24,
  entitlement_expires_at: 24,
  entitlement_fallback_until: 24,
  entitlement_reason_code: 48,
  entitlement_signing_key_id: 79,
  delivered_ack_id: 256,
  delivered_ack_payload_digest: 64,
  applied_ack_id: 256,
  applied_ack_payload_digest: 64,
  created_at: 24,
});
const PAIR_NUMERIC_COLUMNS = new Set(['registry_generation', 'entitlement_version']);
function createConnectedAcknowledgedAuthorityStore(options = {}) {
  const ctx = context(options);
  return Object.freeze({
    stagePair: (input) => stagePair(ctx, input),
    recordAcknowledgementResult: (input, result) => recordAcknowledgementResult(
      ctx, input, result,
    ),
    getState: (customerId, deploymentId) => projectionSnapshot(readState(
      ctx, customerId, deploymentId,
    )),
    constrainDisposition: (input) => constrainDisposition(ctx, input),
  });
}

function context(options) {
  const driver = options.driver;
  if (!driver || typeof driver.prepare !== 'function') throw new TypeError('driver is required');
  for (const name of [
    'appendAudit', 'authorityReference', 'ackReference', 'verifyAuditState', 'verifyAuditEntry',
  ]) requireFunction(options[name], name);
  if (!options.entitlementStore
      || typeof options.entitlementStore.assertAcknowledgementLineages !== 'function') {
    throw new TypeError('connected entitlement lineage store is required');
  }
  if (!isConnectedHeartbeatTransactionCoordinator(options.compositeCoordinator)) {
    throw new TypeError('connected heartbeat transaction coordinator is required');
  }
  assertScopeValue(options.customerId, options.deploymentId);
  const schema = driver.kind === 'postgres' ? 'public' : 'main';
  const relation = Object.freeze({
    audit: `${schema}.audit`,
    state: `${schema}.connected_acknowledged_authority_state`,
    lineage: `${schema}.connected_authority_pair_lineage`,
    deletions: `${schema}.connected_authority_pair_deletions`,
  });
  const deletionColumns = boundedDeletionColumns(driver);
  const stateColumns = boundedColumns(
    driver, STATE_COLUMNS, STATE_TEXT_LIMITS, STATE_NUMERIC_COLUMNS,
  );
  const pairColumns = boundedColumns(
    driver, PAIR_COLUMNS, PAIR_TEXT_LIMITS, PAIR_NUMERIC_COLUMNS,
  );
  const ctx = {
    customerId: options.customerId,
    deploymentId: options.deploymentId,
    driver,
    relation,
    appendAudit: receiverless(options.appendAudit),
    authorityReference: receiverless(options.authorityReference),
    ackReference: receiverless(options.ackReference),
    verifyAuditState: receiverless(options.verifyAuditState),
    verifyAuditEntry: receiverless(options.verifyAuditEntry),
    assertAcknowledgementLineages: receiverless(
      options.entitlementStore.assertAcknowledgementLineages,
    ),
    coordinator: options.compositeCoordinator,
    stateRead: driver.prepare(`SELECT ${stateColumns.join(', ')} FROM ${relation.state}
      WHERE customer_id = ? AND deployment_id = ?`),
    stateWrite: driver.prepare(`INSERT INTO ${relation.state} AS authority_state
      (customer_id, deployment_id, authority_ref, current_pair_digest,
       current_registry_generation, current_registry_state_digest,
       current_entitlement_version, current_entitlement_digest,
       acknowledged_registry_generation, acknowledged_registry_state_digest,
       acknowledged_entitlement_version, acknowledged_entitlement_digest,
       acknowledged_pair_digest, history_count, history_digest,
       deletion_count, deletion_high_water, deletion_digest, state_json, updated_at)
      VALUES (@customerId, @deploymentId, @authorityRef, @currentPairDigest,
       @currentRegistryGeneration, @currentRegistryStateDigest,
       @currentEntitlementVersion, @currentEntitlementDigest,
       @acknowledgedRegistryGeneration, @acknowledgedRegistryStateDigest,
       @acknowledgedEntitlementVersion, @acknowledgedEntitlementDigest,
       @acknowledgedPairDigest, @historyCount, @historyDigest,
       @deletionCount, @deletionHighWater, @deletionDigest, @stateJson, @updatedAt)
      ON CONFLICT(customer_id, deployment_id) DO UPDATE SET
       current_pair_digest = excluded.current_pair_digest,
       current_registry_generation = excluded.current_registry_generation,
       current_registry_state_digest = excluded.current_registry_state_digest,
       current_entitlement_version = excluded.current_entitlement_version,
       current_entitlement_digest = excluded.current_entitlement_digest,
       acknowledged_registry_generation = excluded.acknowledged_registry_generation,
       acknowledged_registry_state_digest = excluded.acknowledged_registry_state_digest,
       acknowledged_entitlement_version = excluded.acknowledged_entitlement_version,
       acknowledged_entitlement_digest = excluded.acknowledged_entitlement_digest,
       acknowledged_pair_digest = excluded.acknowledged_pair_digest,
       history_count = excluded.history_count,
       history_digest = excluded.history_digest,
       deletion_count = excluded.deletion_count,
       deletion_high_water = excluded.deletion_high_water,
       deletion_digest = excluded.deletion_digest,
       state_json = excluded.state_json,
       updated_at = excluded.updated_at
      WHERE authority_state.authority_ref = excluded.authority_ref`),
    stateAudit: driver.prepare(`SELECT ${boundedNumericColumn(driver, 'seq')},
      ${boundedTextColumn(driver, 'action', 64)},
      ${boundedTextColumn(driver, 'connected_entry_action', 64)},
      ${boundedTextColumn(driver, 'entry', MAX_AUDIT_ENTRY_BYTES)}
      FROM ${relation.audit} WHERE connected_authority_ref = ?
        AND connected_entry_action IN
          ('CONNECTED_ACKNOWLEDGED_AUTHORITY_STAGED',
           'CONNECTED_ACKNOWLEDGED_AUTHORITY_ADVANCED',
           'CONNECTED_ACKNOWLEDGED_AUTHORITY_COMPACTED')
      ORDER BY seq DESC LIMIT 1`),
    pairRead: driver.prepare(`SELECT ${pairColumns.join(', ')} FROM ${relation.lineage}
      WHERE pair_digest = ?
      AND customer_id = ? AND deployment_id = ?`),
    pairsByAppliedAck: driver.prepare(`SELECT ${pairColumns.join(', ')} FROM ${relation.lineage}
      WHERE customer_id = @customerId AND deployment_id = @deploymentId
        AND applied_ack_id = @id AND applied_ack_payload_digest = @payloadDigest
      ORDER BY registry_generation DESC, entitlement_version DESC, pair_digest DESC
      LIMIT ${MAX_LIVE_PAIR_LINEAGES + 1}`),
    pairInsert: driver.prepare(`INSERT INTO ${relation.lineage}
      (pair_digest, customer_id, deployment_id, transition_kind, registry_generation,
       registry_state_digest, registry_status, entitlement_version,
       entitlement_digest, artifact_digest, entitlement_status, authority_json,
       entitlement_issued_at, entitlement_expires_at, entitlement_fallback_until,
       entitlement_reason_code, entitlement_signing_key_id,
       delivered_ack_id, delivered_ack_payload_digest,
       applied_ack_id, applied_ack_payload_digest, created_at)
      VALUES (@pairDigest, @customerId, @deploymentId, @transitionKind, @registryGeneration,
       @registryStateDigest, @registryStatus, @entitlementVersion,
       @entitlementDigest, @artifactDigest, @entitlementStatus, @authorityJson,
       @entitlementIssuedAt, @entitlementExpiresAt, @entitlementFallbackUntil,
       @entitlementReasonCode, @entitlementSigningKeyId,
       @deliveredAckId, @deliveredAckPayloadDigest,
       @appliedAckId, @appliedAckPayloadDigest, @createdAt)
      ON CONFLICT(pair_digest) DO NOTHING RETURNING pair_digest`),
    pairCount: driver.prepare(`SELECT COUNT(*) AS count FROM (
      SELECT 1 FROM ${relation.lineage}
      WHERE customer_id = ? AND deployment_id = ?
      LIMIT ${MAX_LIVE_PAIR_LINEAGES + 1}
    ) AS bounded_pair_count`),
    compactablePairs: driver.prepare(`SELECT ${pairColumns.join(', ')} FROM ${relation.lineage}
      WHERE customer_id = @customerId AND deployment_id = @deploymentId
        AND registry_generation <= @registryGeneration
        AND entitlement_version <= @entitlementVersion
        AND pair_digest <> @acknowledgedPairDigest
        AND pair_digest <> @currentPairDigest
      ORDER BY registry_generation, entitlement_version, pair_digest
      LIMIT ${MAX_LIVE_PAIR_LINEAGES + 1}`),
    pairDelete: driver.prepare(`DELETE FROM ${relation.lineage}
      WHERE pair_digest = @pairDigest AND customer_id = @customerId
        AND deployment_id = @deploymentId RETURNING pair_digest`),
    deletionRows: driver.prepare(`SELECT ${deletionColumns.join(', ')}
      FROM ${relation.deletions} WHERE customer_id = ? AND deployment_id = ?
      ORDER BY scope_seq, event_seq LIMIT ${MAX_DELETION_HISTORY_ROWS + 1}`),
    tempObjects: driver.kind === 'postgres' ? null : driver.prepare(`SELECT type, name, tbl_name
      FROM temp.sqlite_schema WHERE name IN
        (${SQLITE_RESERVED_OBJECTS.map((name) => `'${name}'`).join(', ')})
        OR ((type = 'trigger' OR type = 'index') AND tbl_name IN
          (${AUTHORITY_TABLES.map((name) => `'${name}'`).join(', ')}))
      ORDER BY type, name LIMIT ${MAX_AUTHORITY_CATALOG_ROWS + 1}`),
  };
  Object.assign(ctx, authorityCatalogStatements(driver));
  if (driver.kind !== 'postgres') {
    ctx.sqliteSchemaVersionRead = driver.prepare('PRAGMA main.schema_version');
    ctx.sqliteSchemaVersion = readSqliteSchemaVersion(ctx);
  }
  return ctx;
}

function boundedDeletionColumns(driver) {
  const textColumns = Object.freeze({
    customer_id: 63,
    deployment_id: 36,
    transition_kind: 32,
    pair_digest: 64,
    applied_ack_id: 256,
    applied_ack_payload_digest: 64,
    deleted_at: 24,
  });
  return Object.freeze([
    boundedNumericColumn(driver, 'event_seq'), boundedNumericColumn(driver, 'event_version'),
    boundedTextColumn(driver, 'customer_id', textColumns.customer_id),
    boundedTextColumn(driver, 'deployment_id', textColumns.deployment_id),
    boundedNumericColumn(driver, 'scope_seq'),
    boundedTextColumn(driver, 'transition_kind', textColumns.transition_kind),
    boundedTextColumn(driver, 'pair_digest', textColumns.pair_digest),
    boundedNumericColumn(driver, 'registry_generation'),
    boundedNumericColumn(driver, 'entitlement_version'),
    boundedTextColumn(driver, 'applied_ack_id', textColumns.applied_ack_id),
    boundedTextColumn(driver, 'applied_ack_payload_digest',
      textColumns.applied_ack_payload_digest),
    boundedTextColumn(driver, 'deleted_at', textColumns.deleted_at),
  ]);
}

function boundedColumns(driver, columns, limits, numericColumns) {
  return Object.freeze(columns.map((name) => (
    limits[name] ? boundedTextColumn(driver, name, limits[name])
      : numericColumns.has(name) ? boundedNumericColumn(driver, name) : name
  )));
}

function boundedTextColumn(driver, name, bytes) {
  return driver.kind === 'postgres'
    ? `CASE WHEN ${name} IS NULL THEN NULL
      WHEN pg_catalog.octet_length(${name}) <= ${bytes} THEN ${name}
      ELSE '${INVALID_TEXT_PROJECTION}' END AS ${name}`
    : `CASE WHEN ${name} IS NULL THEN NULL
      WHEN typeof(${name}) = 'text' AND length(CAST(${name} AS BLOB)) <= ${bytes} THEN ${name}
      ELSE '${INVALID_TEXT_PROJECTION}' END AS ${name}`;
}

function boundedNumericColumn(driver, name) {
  if (driver.kind === 'postgres') return name;
  return `CASE WHEN ${name} IS NULL THEN NULL
    WHEN typeof(${name}) = 'integer'
      AND ${name} BETWEEN -9007199254740991 AND 9007199254740991 THEN ${name}
    ELSE ${INVALID_NUMERIC_PROJECTION} END AS ${name}`;
}

function authorityCatalogStatements(driver) {
  if (driver.kind !== 'postgres') {
    return {
      authorityCatalogKind: 'sqlite',
      authorityCatalogRead: driver.prepare(`SELECT type AS object_type,
        name AS object_name, tbl_name AS table_name,
        substr(sql, 1, ${MAX_AUTHORITY_CATALOG_SQL_BYTES + 1}) AS object_sql,
        length(CAST(sql AS BLOB)) AS object_sql_bytes
        FROM main.sqlite_schema
        WHERE type IN ('table', 'index', 'trigger')
          AND (name IN (${AUTHORITY_TABLES.map((name) => `'${name}'`).join(', ')})
            OR tbl_name IN (${AUTHORITY_TABLES.map((name) => `'${name}'`).join(', ')}))
        ORDER BY type, name LIMIT ${MAX_AUTHORITY_CATALOG_ROWS + 1}`),
    };
  }
  const tableNames = AUTHORITY_TABLES.map((name) => `'${name}'`).join(', ');
  return {
    authorityCatalogKind: 'postgres',
    authorityCatalogReadLock: driver.prepare(`LOCK TABLE
      public.connected_acknowledged_authority_state,
      public.connected_authority_pair_lineage,
      public.connected_authority_pair_deletions IN SHARE MODE`),
    authorityCatalogMutationLock: driver.prepare(`LOCK TABLE
      public.connected_acknowledged_authority_state,
      public.connected_authority_pair_lineage,
      public.connected_authority_pair_deletions IN SHARE ROW EXCLUSIVE MODE`),
    authorityCatalogRead: driver.prepare(`
      WITH authority_catalog AS (
      SELECT 'runtime' AS object_type, current_user::pg_catalog.text AS object_name,
        ''::pg_catalog.text AS table_name, '0'::pg_catalog.text AS object_oid,
        '0'::pg_catalog.text AS object_xmin, current_user::pg_catalog.text AS object_owner,
        pg_catalog.jsonb_build_object('currentUser', current_user)::pg_catalog.text AS object_detail
      UNION ALL
      SELECT 'relation', c.relname, c.relname, c.oid::pg_catalog.text,
        c.xmin::pg_catalog.text, pg_catalog.pg_get_userbyid(c.relowner),
        pg_catalog.jsonb_build_object('relkind', c.relkind,
          'rowSecurity', c.relrowsecurity, 'forceRowSecurity', c.relforcerowsecurity,
          'persistence', c.relpersistence, 'hasRules', c.relhasrules,
          'hasTriggers', c.relhastriggers, 'hasIndex', c.relhasindex)::pg_catalog.text
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname IN (${tableNames})
      UNION ALL
      SELECT 'column', c.relname || ':' || a.attname, c.relname,
        c.oid::pg_catalog.text, c.xmin::pg_catalog.text,
        pg_catalog.pg_get_userbyid(c.relowner),
        pg_catalog.jsonb_build_object('position', a.attnum,
          'type', pg_catalog.format_type(a.atttypid, a.atttypmod),
          'notNull', a.attnotnull, 'identity', a.attidentity,
          'generated', a.attgenerated,
          'defaultCollation', CASE WHEN a.attcollation = 0 THEN true
            ELSE a.attcollation = pg_catalog.to_regcollation('pg_catalog.default') END,
          'default', pg_catalog.pg_get_expr(ad.adbin, ad.adrelid))::pg_catalog.text
      FROM pg_catalog.pg_attribute a
      JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      LEFT JOIN pg_catalog.pg_attrdef ad
        ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
      WHERE n.nspname = 'public' AND c.relname IN (${tableNames})
        AND a.attnum > 0 AND NOT a.attisdropped
      UNION ALL
      SELECT 'constraint', c.relname || ':' || con.conname, c.relname,
        con.oid::pg_catalog.text, con.xmin::pg_catalog.text,
        pg_catalog.pg_get_userbyid(c.relowner),
        pg_catalog.jsonb_build_object('type', con.contype,
          'validated', con.convalidated, 'deferrable', con.condeferrable,
          'deferred', con.condeferred,
          'columns', (SELECT pg_catalog.jsonb_agg(att.attname ORDER BY key_col.ordinality)
            FROM pg_catalog.unnest(con.conkey) WITH ORDINALITY AS key_col(attnum, ordinality)
            JOIN pg_catalog.pg_attribute att
              ON att.attrelid = con.conrelid AND att.attnum = key_col.attnum),
          'referencedTable', CASE WHEN con.confrelid = 0 THEN NULL
            ELSE con.confrelid::pg_catalog.regclass::pg_catalog.text END,
          'referencedColumns', (SELECT pg_catalog.jsonb_agg(att.attname ORDER BY ref_col.ordinality)
            FROM pg_catalog.unnest(con.confkey) WITH ORDINALITY AS ref_col(attnum, ordinality)
            JOIN pg_catalog.pg_attribute att
              ON att.attrelid = con.confrelid AND att.attnum = ref_col.attnum),
          'definition', pg_catalog.pg_get_constraintdef(con.oid, true))::pg_catalog.text
      FROM pg_catalog.pg_constraint con
      JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname IN (${tableNames})
      UNION ALL
      SELECT 'function', p.proname, ''::pg_catalog.text,
        p.oid::pg_catalog.text, p.xmin::pg_catalog.text,
        pg_catalog.pg_get_userbyid(p.proowner),
        pg_catalog.jsonb_build_object('kind', p.prokind,
          'securityDefiner', p.prosecdef, 'volatility', p.provolatile,
          'language', language.lanname, 'strict', p.proisstrict,
          'leakproof', p.proleakproof, 'parallel', p.proparallel,
          'arguments', pg_catalog.pg_get_function_identity_arguments(p.oid),
          'returnType', pg_catalog.pg_get_function_result(p.oid),
          'config', COALESCE(p.proconfig, ARRAY[]::pg_catalog.text[]),
          'source', p.prosrc)::pg_catalog.text
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_catalog.pg_language language ON language.oid = p.prolang
      WHERE n.nspname = 'public' AND p.pronargs = 0 AND p.proname IN
        ('record_connected_authority_pair_delete',
         'reject_connected_authority_pair_update',
         'reject_connected_authority_pair_deletion_mutation')
      UNION ALL
      SELECT 'trigger', t.tgname, c.relname, t.oid::pg_catalog.text,
        t.xmin::pg_catalog.text, pg_catalog.pg_get_userbyid(c.relowner),
        pg_catalog.jsonb_build_object('enabled', t.tgenabled, 'type', t.tgtype,
          'functionOid', t.tgfoid::pg_catalog.text,
          'definition', pg_catalog.pg_get_triggerdef(t.oid, true))::pg_catalog.text
      FROM pg_catalog.pg_trigger t
      JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND NOT t.tgisinternal AND c.relname IN (${tableNames})
      UNION ALL
      SELECT 'policy', p.polname, c.relname, p.oid::pg_catalog.text,
        p.xmin::pg_catalog.text, pg_catalog.pg_get_userbyid(c.relowner),
        pg_catalog.jsonb_build_object('permissive', p.polpermissive,
          'command', p.polcmd, 'roles', p.polroles::pg_catalog.text,
          'using', pg_catalog.pg_get_expr(p.polqual, p.polrelid),
          'check', pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))::pg_catalog.text
      FROM pg_catalog.pg_policy p
      JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname IN (${tableNames})
      UNION ALL
      SELECT 'index', ci.relname, ct.relname, ci.oid::pg_catalog.text,
        ci.xmin::pg_catalog.text, pg_catalog.pg_get_userbyid(ci.relowner),
        pg_catalog.jsonb_build_object('valid', i.indisvalid, 'ready', i.indisready,
          'live', i.indislive, 'definition', pg_catalog.pg_get_indexdef(i.indexrelid))::pg_catalog.text
      FROM pg_catalog.pg_index i
      JOIN pg_catalog.pg_class ci ON ci.oid = i.indexrelid
      JOIN pg_catalog.pg_class ct ON ct.oid = i.indrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = ct.relnamespace
      WHERE n.nspname = 'public' AND ct.relname IN (${tableNames})
      )
      SELECT object_type, object_name, table_name, object_oid, object_xmin, object_owner,
        pg_catalog.left(object_detail, ${MAX_AUTHORITY_CATALOG_SQL_BYTES + 1}) AS object_detail,
        pg_catalog.octet_length(object_detail) AS object_detail_bytes
      FROM authority_catalog
      ORDER BY object_type, table_name, object_name
      LIMIT ${MAX_AUTHORITY_CATALOG_ROWS + 1}`),
  };
}

function stagePair(ctx, input = {}) {
  requireCoordinated(ctx);
  const parsed = checkedStageInput(ctx, input);
  lockAuthority(ctx, true);
  const prior = readState(ctx, parsed.customerId, parsed.deploymentId);
  const pair = pairFromStage(parsed, prior?.current || null);
  insertOrVerifyPair(ctx, pair, parsed.nowMs);
  const current = prior?.state || initialState(ctx);
  assertPairProgression(current, prior, pair);
  const lineages = verifyPairAcknowledgements(ctx, pair);
  const acknowledgedNow = lineages.every(({ status }) => status === 'acknowledged');
  if (prior && prior.current.pairDigest === pair.pairDigest
      && (!acknowledgedNow || prior.state.acknowledgedPairDigest === pair.pairDigest)) {
    return Object.freeze({
      state: prior.state,
      pair: prior.current,
      acknowledged: prior.state.acknowledgedPairDigest === pair.pairDigest,
    });
  }
  let next = { ...current, currentPairDigest: pair.pairDigest };
  let action = STATE_ACTIONS[0];
  let advancedBy = null;
  if (acknowledgedNow) {
    next = promotePair(ctx, next, pair, parsed.nowMs);
    action = STATE_ACTIONS[1];
    advancedBy = pair.transitionKind === TRANSITION_KINDS.ENTITLEMENT_RELEASE
      ? pair.appliedAck : null;
  } else {
    next = checkedState(next, ctx);
  }
  persistState(ctx, next, pair, action, parsed.nowMs, advancedBy);
  assertLivePairBound(ctx);
  return Object.freeze({ state: next, pair, acknowledged: action === STATE_ACTIONS[1] });
}

function recordAcknowledgementResult(ctx, input = {}, result = null) {
  requireCoordinated(ctx);
  assertScope(ctx, input.customerId, input.deploymentId);
  if (!result || result.id !== input.id || result.payloadDigest !== input.payloadDigest
      || result.customerId !== input.customerId || result.deploymentId !== input.deploymentId) {
    throw integrityError();
  }
  lockAuthority(ctx, true);
  const prior = readState(ctx, input.customerId, input.deploymentId);
  if (!prior) throw integrityError();
  if (input.accepted !== true || result.status !== 'acknowledged') return prior.state;
  const pairRows = ctx.pairsByAppliedAck.all({
    customerId: input.customerId,
    deploymentId: input.deploymentId,
    id: input.id,
    payloadDigest: input.payloadDigest,
  });
  if (pairRows.length > MAX_LIVE_PAIR_LINEAGES) throw integrityError();
  const pairs = pairRows.map((row) => checkedPairRow(row, ctx));
  if (pairs.length === 0) {
    return compactAfterSupersededAcknowledgement(ctx, prior, input.nowMs);
  }
  const pair = pairs[0];
  assertSharedAcknowledgementLineage(pairs, prior);
  const lineages = verifyPairAcknowledgements(ctx, pair);
  if (!lineages.every(({ status }) => status === 'acknowledged')) throw integrityError();
  if (prior.state.acknowledgedPairDigest === pair.pairDigest) return prior.state;
  const acknowledged = prior.acknowledged;
  if (acknowledged && pairBehind(pair, acknowledged)) {
    const compacted = compactSupersededPairs(ctx, prior.state, acknowledged);
    if (compacted.historyCount !== prior.state.historyCount) {
      persistState(
        ctx, compacted, prior.current, STATE_ACTIONS[2], input.nowMs, pair.appliedAck,
      );
    }
    return compacted;
  }
  const next = promotePair(ctx, prior.state, pair, input.nowMs);
  persistState(ctx, next, prior.current, STATE_ACTIONS[1], input.nowMs, pair.appliedAck);
  assertLivePairBound(ctx);
  return next;
}

function compactAfterSupersededAcknowledgement(ctx, prior, nowMs) {
  if (!prior.acknowledged) return prior.state;
  const compacted = compactSupersededPairs(ctx, prior.state, prior.acknowledged);
  if (compacted.historyCount !== prior.state.historyCount) {
    persistState(ctx, compacted, prior.current, STATE_ACTIONS[2], nowMs, null);
  }
  return compacted;
}

function constrainDisposition(ctx, input = {}) {
  requireCoordinated(ctx);
  assertScope(ctx, input.customerId, input.deploymentId);
  const currentDisposition = checkedDisposition(input.currentDisposition);
  const source = sourcePair(input.registryState, input.entitlementState);
  lockAuthority(ctx, false);
  let projection;
  try { projection = readState(ctx, input.customerId, input.deploymentId); }
  catch (error) {
    if (error?.code === 'CONNECTED_AUTHORITY_DELETION_HISTORY_CAPACITY') {
      return blocked('connected_authority_history_capacity');
    }
    throw error;
  }
  if (!projection) return source
    ? initialAcknowledgementRestriction(currentDisposition) : currentDisposition;
  if (currentDisposition.protectedEgress !== 'allow') {
    if (!projection.acknowledged) return initialAcknowledgementRestriction(currentDisposition);
    return Object.freeze({
      ...currentDisposition,
      authority: currentDisposition.authority === null
        ? null
        : intersectAuthority(currentDisposition.authority, projection.acknowledged.authority),
    });
  }
  if (!source || !sameSourcePair(source, projection.current)) {
    return blocked(
      'connected_authority_pair_unacknowledged',
      'blocked',
      null,
      !projection.acknowledged,
    );
  }
  if (!projection.acknowledged) return initialAcknowledgementRestriction(currentDisposition);
  const acknowledged = projection.acknowledged;
  if (acknowledged.registryStatus === 'revoked') return blocked(
    'vendor_registry_revoked', 'revoked', acknowledged.authority,
  );
  if (acknowledged.entitlementStatus === 'paused') {
    return blocked('vendor_paused', 'paused', acknowledged.authority);
  }
  if (acknowledged.entitlementStatus === 'revoked') {
    return blocked('vendor_revoked', 'revoked', acknowledged.authority);
  }
  const nowMs = checkedTime(input.nowMs);
  if (nowMs > Date.parse(acknowledged.entitlementExpiresAt)
      && (currentDisposition.mode !== 'degraded_fallback'
        || acknowledged.entitlementFallbackUntil === null
        || nowMs > Date.parse(acknowledged.entitlementFallbackUntil))) {
    return blocked('connected_acknowledgement_expired');
  }
  return Object.freeze({
    ...currentDisposition,
    authority: intersectAuthority(currentDisposition.authority, acknowledged.authority),
  });
}

function readState(ctx, customerId, deploymentId) {
  assertScope(ctx, customerId, deploymentId);
  requireAuditHealthy(ctx);
  assertNoTemporaryCollision(ctx);
  assertAuthorityCatalog(ctx);
  const authorityRef = referenceFor(ctx);
  const row = ctx.stateRead.get(customerId, deploymentId);
  const anchor = verifiedAuditDetail(ctx, ctx.stateAudit.get(authorityRef));
  const deletion = deletionHistory(ctx);
  const pairCount = livePairCount(ctx);
  if (!row) {
    if (anchor || pairCount !== 0 || deletion.count !== 0) throw integrityError();
    return null;
  }
  if (pairCount < 1) throw integrityError();
  const state = parsedStateRow(row, ctx);
  if (!anchor || anchor.authorityRef !== authorityRef
      || anchor.stateDigest !== stateDigest(state)
      || anchor.currentPairDigest !== state.currentPairDigest
      || anchor.acknowledgedPairDigest !== state.acknowledgedPairDigest
      || anchor.historyCount !== state.historyCount
      || anchor.historyDigest !== state.historyDigest
      || anchor.deletionCount !== state.deletionCount
      || anchor.deletionHighWater !== state.deletionHighWater
      || anchor.deletionDigest !== state.deletionDigest
      || state.deletionCount !== deletion.count
      || state.deletionHighWater !== deletion.highWater
      || state.deletionDigest !== deletion.digest) throw integrityError();
  const current = readPair(ctx, state.currentPairDigest);
  const acknowledged = state.acknowledgedPairDigest
    ? readPair(ctx, state.acknowledgedPairDigest) : null;
  if (anchor.transitionKind !== current.transitionKind) throw integrityError();
  assertStatePairColumns(row, current, acknowledged);
  const pairs = acknowledged && acknowledged.pairDigest !== current.pairDigest
    ? [current, acknowledged] : [current];
  for (const pair of pairs) verifyPairAcknowledgements(ctx, pair);
  return { state, current, acknowledged };
}

function projectionSnapshot(value) {
  if (!value) return null;
  return Object.freeze({
    ...value.state,
    current: publicPair(value.current),
    acknowledged: value.acknowledged ? publicPair(value.acknowledged) : null,
  });
}

function publicPair(pair) {
  return Object.freeze({
    pairDigest: pair.pairDigest,
    transitionKind: pair.transitionKind,
    registryGeneration: pair.registryGeneration,
    registryStateDigest: pair.registryStateDigest,
    registryStatus: pair.registryStatus,
    entitlementVersion: pair.entitlementVersion,
    entitlementDigest: pair.entitlementDigest,
    artifactDigest: pair.artifactDigest,
    entitlementStatus: pair.entitlementStatus,
    authority: pair.authority,
  });
}

function promotePair(ctx, stateValue, pair, nowMs) {
  const prior = checkedState(stateValue, ctx);
  if (prior.acknowledgedPairDigest) {
    const acknowledged = readPair(ctx, prior.acknowledgedPairDigest);
    if (pairBehind(pair, acknowledged)) return prior;
  }
  const promoted = checkedState({ ...prior, acknowledgedPairDigest: pair.pairDigest }, ctx);
  writeStateRow(ctx, promoted, readPair(ctx, promoted.currentPairDigest), pair, nowMs);
  return compactSupersededPairs(ctx, promoted, pair);
}

function compactSupersededPairs(ctx, state, acknowledged) {
  const current = readPair(ctx, state.currentPairDigest);
  const candidateRows = ctx.compactablePairs.all({
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    registryGeneration: acknowledged.registryGeneration,
    entitlementVersion: acknowledged.entitlementVersion,
    acknowledgedPairDigest: acknowledged.pairDigest,
    currentPairDigest: current.pairDigest,
  });
  if (candidateRows.length > MAX_LIVE_PAIR_LINEAGES) throw integrityError();
  const candidates = candidateRows.map((row) => checkedPairRow(row, ctx)).filter((pair) => (
    verifyPairAcknowledgements(ctx, pair).every(({ status }) => status === 'acknowledged')
  ));
  const catalogIdentity = assertAuthorityCatalog(ctx);
  const priorDeletion = deletionHistory(ctx);
  assertDeletionAnchor(state, priorDeletion);
  let historyCount = state.historyCount;
  let historyDigest = state.historyDigest;
  for (const pair of candidates) {
    historyDigest = nextHistoryDigest(historyDigest, pair);
    historyCount += 1;
    const removed = ctx.pairDelete.get({
      pairDigest: pair.pairDigest,
      customerId: ctx.customerId,
      deploymentId: ctx.deploymentId,
    });
    if (!removed || removed.pair_digest !== pair.pairDigest) throw integrityError();
  }
  const deletion = deletionHistory(ctx);
  assertDeletionAppend(priorDeletion, deletion, candidates);
  assertAuthorityCatalog(ctx, catalogIdentity);
  return checkedState({
    ...state,
    historyCount,
    historyDigest,
    deletionCount: deletion.count,
    deletionHighWater: deletion.highWater,
    deletionDigest: deletion.digest,
  }, ctx);
}

function persistState(ctx, state, current, action, nowMs, advancedBy) {
  const currentPair = current.pairDigest ? current : readPair(ctx, state.currentPairDigest);
  const acknowledged = state.acknowledgedPairDigest
    ? readPair(ctx, state.acknowledgedPairDigest) : null;
  writeStateRow(ctx, state, currentPair, acknowledged, nowMs);
  const authorityRef = referenceFor(ctx);
  ctx.appendAudit({
    action,
    actor: 'vendor_connector',
    connectedAuthorityRef: authorityRef,
    ...(advancedBy ? { connectedAckRef: ctx.ackReference(advancedBy.id) } : {}),
    detail: JSON.stringify({
      authorityRef,
      stateDigest: stateDigest(state),
      currentPairDigest: state.currentPairDigest,
      transitionKind: currentPair.transitionKind,
      acknowledgedPairDigest: state.acknowledgedPairDigest,
      historyCount: state.historyCount,
      historyDigest: state.historyDigest,
      deletionCount: state.deletionCount,
      deletionHighWater: state.deletionHighWater,
      deletionDigest: state.deletionDigest,
    }),
  });
}

function writeStateRow(ctx, state, current, acknowledged, nowMs) {
  const result = ctx.stateWrite.run({
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    authorityRef: referenceFor(ctx),
    currentPairDigest: current.pairDigest,
    currentRegistryGeneration: current.registryGeneration,
    currentRegistryStateDigest: current.registryStateDigest,
    currentEntitlementVersion: current.entitlementVersion,
    currentEntitlementDigest: current.entitlementDigest,
    acknowledgedRegistryGeneration: acknowledged?.registryGeneration ?? null,
    acknowledgedRegistryStateDigest: acknowledged?.registryStateDigest ?? null,
    acknowledgedEntitlementVersion: acknowledged?.entitlementVersion ?? null,
    acknowledgedEntitlementDigest: acknowledged?.entitlementDigest ?? null,
    acknowledgedPairDigest: acknowledged?.pairDigest ?? null,
    historyCount: state.historyCount,
    historyDigest: state.historyDigest,
    deletionCount: state.deletionCount,
    deletionHighWater: state.deletionHighWater,
    deletionDigest: state.deletionDigest,
    stateJson: protocol.canonicalJson(state),
    updatedAt: new Date(checkedTime(nowMs)).toISOString(),
  });
  if (Number(result.changes) !== 1) throw integrityError();
}

function pairFromStage(input, prior) {
  const registry = registryState.restoreState(input.registryState, {
    customerId: input.customerId,
    deploymentId: input.deploymentId,
  });
  const entitlement = protocol.assertChannel(
    input.entitlementState.entitlement, protocol.CHANNEL_KINDS.ENTITLEMENT,
  );
  const entitlementMaterial = {
    customerId: input.customerId,
    deploymentId: input.deploymentId,
    registryGeneration: registry.registryGeneration,
    registryStateDigest: registry.registryStateDigest,
    registryStatus: registry.status,
    entitlementVersion: input.entitlementState.entitlementVersion,
    entitlementDigest: input.entitlementState.entitlementDigest,
    artifactDigest: input.artifactDigest,
    entitlementStatus: entitlement.status,
    authority: { plan: entitlement.plan, seats: entitlement.seats, features: [...entitlement.features] },
    entitlementIssuedAt: entitlement.issuedAt,
    entitlementExpiresAt: entitlement.expiresAt,
    entitlementFallbackUntil: entitlement.fallbackUntil,
    entitlementReasonCode: entitlement.reasonCode,
    entitlementSigningKeyId: input.entitlementState.signingKeyId,
    deliveredAck: checkedAck(input.outboxes.delivered, 'delivered', input.entitlementState),
    appliedAck: checkedAck(input.outboxes.applied, 'applied', input.entitlementState),
  };
  const material = {
    ...entitlementMaterial,
    transitionKind: transitionKind(prior, entitlementMaterial),
  };
  return checkedPair({ ...material, pairDigest: sha256(protocol.canonicalJson(material)) }, input);
}

function sourcePair(registryValue, entitlementValue) {
  try {
    if (!registryValue || !entitlementValue?.entitlement) return null;
    const registry = registryState.restoreState(registryValue);
    const entitlement = protocol.assertChannel(
      entitlementValue.entitlement, protocol.CHANNEL_KINDS.ENTITLEMENT,
    );
    return {
      customerId: registry.customerId,
      deploymentId: registry.deploymentId,
      registryGeneration: registry.registryGeneration,
      registryStateDigest: registry.registryStateDigest,
      registryStatus: registry.status,
      entitlementVersion: entitlementValue.entitlementVersion,
      entitlementDigest: entitlementValue.entitlementDigest,
      entitlementStatus: entitlement.status,
      authority: { plan: entitlement.plan, seats: entitlement.seats, features: [...entitlement.features] },
      entitlementIssuedAt: entitlement.issuedAt,
      entitlementExpiresAt: entitlement.expiresAt,
      entitlementFallbackUntil: entitlement.fallbackUntil,
      entitlementReasonCode: entitlement.reasonCode,
      entitlementSigningKeyId: entitlementValue.signingKeyId,
    };
  } catch { return null; }
}

function insertOrVerifyPair(ctx, pair, nowMs) {
  ctx.pairInsert.get(pairRowParameters(pair, nowMs));
  const stored = readPair(ctx, pair.pairDigest);
  if (protocol.canonicalJson(stored) !== protocol.canonicalJson(pair)) throw integrityError();
}

function readPair(ctx, digest) {
  const row = ctx.pairRead.get(digest, ctx.customerId, ctx.deploymentId);
  if (!row) throw integrityError();
  return checkedPairRow(row, ctx);
}

function checkedPairRow(row, ctx) {
  let authority;
  try { authority = checkedAuthority(JSON.parse(row.authority_json)); }
  catch { throw integrityError(); }
  const material = {
    customerId: row.customer_id,
    deploymentId: row.deployment_id,
    transitionKind: row.transition_kind,
    registryGeneration: Number(row.registry_generation),
    registryStateDigest: row.registry_state_digest,
    registryStatus: row.registry_status,
    entitlementVersion: Number(row.entitlement_version),
    entitlementDigest: row.entitlement_digest,
    artifactDigest: row.artifact_digest,
    entitlementStatus: row.entitlement_status,
    authority,
    entitlementIssuedAt: row.entitlement_issued_at,
    entitlementExpiresAt: row.entitlement_expires_at,
    entitlementFallbackUntil: row.entitlement_fallback_until,
    entitlementReasonCode: row.entitlement_reason_code,
    entitlementSigningKeyId: row.entitlement_signing_key_id,
    deliveredAck: ackFromRow(row, 'delivered'),
    appliedAck: ackFromRow(row, 'applied'),
  };
  return checkedPair({ ...material, pairDigest: row.pair_digest }, ctx);
}

function checkedPair(value, expected) {
  const source = { ...value };
  delete source.pairDigest;
  if (!plainRecord(value) || !isDeploymentId(value.deploymentId)
      || value.customerId !== expected.customerId || value.deploymentId !== expected.deploymentId
      || !Object.values(TRANSITION_KINDS).includes(value.transitionKind)
      || !Number.isSafeInteger(value.registryGeneration) || value.registryGeneration < 1
      || !hexDigest(value.registryStateDigest) || !['active', 'revoked'].includes(value.registryStatus)
      || !Number.isSafeInteger(value.entitlementVersion) || value.entitlementVersion < 1
      || !hexDigest(value.entitlementDigest) || !hexDigest(value.artifactDigest)
      || !['active', 'paused', 'revoked'].includes(value.entitlementStatus)
      || !validIso(value.entitlementIssuedAt) || !validIso(value.entitlementExpiresAt)
      || (value.entitlementFallbackUntil !== null && !validIso(value.entitlementFallbackUntil))
      || !/^[a-z][a-z0-9_]{1,47}$/.test(String(value.entitlementReasonCode || ''))
      || !/^rw-entitlement-[a-f0-9]{64}$/.test(String(value.entitlementSigningKeyId || ''))
      || !checkedAuthority(value.authority)
      || !checkedAck(value.deliveredAck, 'delivered', value)
      || !checkedAck(value.appliedAck, 'applied', value)
      || !hexDigest(value.pairDigest)
      || sha256(protocol.canonicalJson(source)) !== value.pairDigest) throw integrityError();
  return deepFreeze({ ...value, authority: checkedAuthority(value.authority) });
}

function checkedAck(value, stage, target) {
  if (!plainRecord(value) || !/^[\x21-\x7e]{1,256}$/.test(String(value.id || ''))
      || value.lifecycleStage !== stage || value.targetKind !== protocol.CHANNEL_KINDS.ENTITLEMENT
      || value.targetVersion !== target.entitlementVersion
      || value.targetDigest !== target.entitlementDigest || !hexDigest(value.payloadDigest)) {
    throw integrityError();
  }
  return Object.freeze({
    id: value.id,
    targetKind: value.targetKind,
    targetVersion: value.targetVersion,
    targetDigest: value.targetDigest,
    lifecycleStage: value.lifecycleStage,
    payloadDigest: value.payloadDigest,
  });
}

function verifyPairAcknowledgements(ctx, pair) {
  return ctx.assertAcknowledgementLineages({
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    acknowledgements: [pair.deliveredAck, pair.appliedAck],
  });
}

function parsedStateRow(row, ctx) {
  let state;
  try { state = checkedState(JSON.parse(row.state_json), ctx); }
  catch { throw integrityError(); }
  if (row.authority_ref !== referenceFor(ctx)
      || row.current_pair_digest !== state.currentPairDigest
      || (row.acknowledged_pair_digest ?? null) !== state.acknowledgedPairDigest
      || Number(row.history_count) !== state.historyCount
      || row.history_digest !== state.historyDigest
      || Number(row.deletion_count) !== state.deletionCount
      || Number(row.deletion_high_water) !== state.deletionHighWater
      || row.deletion_digest !== state.deletionDigest) throw integrityError();
  return state;
}

function checkedState(value, ctx) {
  if (!plainRecord(value)
      || Object.keys(value).sort().join(',') !== [
        'acknowledgedPairDigest', 'currentPairDigest', 'customerId', 'deletionCount',
        'deletionDigest', 'deletionHighWater', 'deploymentId', 'historyCount',
        'historyDigest', 'sqliteSchemaVersion', 'stateVersion',
      ].sort().join(',')
      || value.stateVersion !== STATE_VERSION || value.customerId !== ctx.customerId
      || value.deploymentId !== ctx.deploymentId || !hexDigest(value.currentPairDigest)
      || value.sqliteSchemaVersion !== (ctx.sqliteSchemaVersion ?? null)
      || (value.acknowledgedPairDigest !== null && !hexDigest(value.acknowledgedPairDigest))
      || !Number.isSafeInteger(value.historyCount) || value.historyCount < 0
      || !hexDigest(value.historyDigest)
      || !Number.isSafeInteger(value.deletionCount) || value.deletionCount < 0
      || value.deletionCount > MAX_DELETION_HISTORY_ROWS
      || !Number.isSafeInteger(value.deletionHighWater) || value.deletionHighWater < 0
      || !hexDigest(value.deletionDigest)
      || value.deletionCount !== value.historyCount
      || (value.deletionCount === 0) !== (value.deletionDigest === EMPTY_DELETION_DIGEST)
      || (value.deletionCount === 0) !== (value.deletionHighWater === 0)) throw integrityError();
  return Object.freeze({ ...value });
}

function initialState(ctx) {
  return Object.freeze({
    stateVersion: STATE_VERSION,
    customerId: ctx.customerId,
    deploymentId: ctx.deploymentId,
    currentPairDigest: null,
    acknowledgedPairDigest: null,
    historyCount: 0,
    historyDigest: EMPTY_HISTORY_DIGEST,
    sqliteSchemaVersion: ctx.sqliteSchemaVersion ?? null,
    deletionCount: 0,
    deletionHighWater: 0,
    deletionDigest: EMPTY_DELETION_DIGEST,
  });
}

function assertPairProgression(state, prior, pair) {
  if (!prior) return;
  const current = prior.current;
  if (pair.registryGeneration < current.registryGeneration
      || pair.entitlementVersion < current.entitlementVersion) throw integrityError();
  if (pair.registryGeneration === current.registryGeneration
      && pair.registryStateDigest !== current.registryStateDigest) throw pairConflict();
  if (pair.entitlementVersion === current.entitlementVersion
      && (pair.entitlementDigest !== current.entitlementDigest
        || pair.artifactDigest !== current.artifactDigest)) throw pairConflict();
  if (state.currentPairDigest === pair.pairDigest
      && protocol.canonicalJson(current) !== protocol.canonicalJson(pair)) throw pairConflict();
}

function assertStatePairColumns(row, current, acknowledged) {
  if (Number(row.current_registry_generation) !== current.registryGeneration
      || row.current_registry_state_digest !== current.registryStateDigest
      || Number(row.current_entitlement_version) !== current.entitlementVersion
      || row.current_entitlement_digest !== current.entitlementDigest) throw integrityError();
  const expected = acknowledged ? [
    acknowledged.registryGeneration, acknowledged.registryStateDigest,
    acknowledged.entitlementVersion, acknowledged.entitlementDigest,
  ] : [null, null, null, null];
  const actual = [
    nullableNumber(row.acknowledged_registry_generation),
    row.acknowledged_registry_state_digest ?? null,
    nullableNumber(row.acknowledged_entitlement_version),
    row.acknowledged_entitlement_digest ?? null,
  ];
  if (protocol.canonicalJson(actual) !== protocol.canonicalJson(expected)) throw integrityError();
}

function deletionHistory(ctx) {
  const rows = ctx.deletionRows.all(ctx.customerId, ctx.deploymentId);
  if (rows.length > MAX_DELETION_HISTORY_ROWS) throw deletionCapacityError();
  let digest = EMPTY_DELETION_DIGEST;
  let previousEventSeq = 0;
  const events = [];
  for (let index = 0; index < rows.length; index += 1) {
    const event = checkedDeletionRow(rows[index], ctx, index + 1, previousEventSeq);
    digest = nextDeletionDigest(digest, event);
    previousEventSeq = event.eventSeq;
    events.push(event);
  }
  return Object.freeze({
    count: rows.length,
    highWater: previousEventSeq,
    digest,
    events: Object.freeze(events),
  });
}

function assertDeletionAnchor(state, deletion) {
  if (state.deletionCount !== deletion.count
      || state.deletionHighWater !== deletion.highWater
      || state.deletionDigest !== deletion.digest
      || state.historyCount !== deletion.count) throw integrityError();
}

function assertDeletionAppend(prior, current, candidates) {
  if (current.count !== prior.count + candidates.length
      || current.events.length !== current.count
      || prior.events.length !== prior.count
      || protocol.canonicalJson(current.events.slice(0, prior.count))
        !== protocol.canonicalJson(prior.events)) throw integrityError();
  for (let index = 0; index < candidates.length; index += 1) {
    const event = current.events[prior.count + index];
    const pair = candidates[index];
    if (!event || event.scopeSeq !== prior.count + index + 1
        || event.transitionKind !== pair.transitionKind
        || event.pairDigest !== pair.pairDigest
        || event.registryGeneration !== pair.registryGeneration
        || event.entitlementVersion !== pair.entitlementVersion
        || event.appliedAckId !== pair.appliedAck.id
        || event.appliedAckPayloadDigest !== pair.appliedAck.payloadDigest) {
      throw integrityError();
    }
  }
}

function checkedDeletionRow(row, ctx, expectedScopeSeq, previousEventSeq) {
  const event = {
    eventSeq: Number(row.event_seq),
    eventVersion: Number(row.event_version),
    customerId: row.customer_id,
    deploymentId: row.deployment_id,
    scopeSeq: Number(row.scope_seq),
    transitionKind: row.transition_kind,
    pairDigest: row.pair_digest,
    registryGeneration: Number(row.registry_generation),
    entitlementVersion: Number(row.entitlement_version),
    appliedAckId: row.applied_ack_id,
    appliedAckPayloadDigest: row.applied_ack_payload_digest,
    deletedAt: row.deleted_at,
  };
  if (!Number.isSafeInteger(event.eventSeq) || event.eventSeq <= previousEventSeq
      || event.eventVersion !== 1 || event.customerId !== ctx.customerId
      || event.deploymentId !== ctx.deploymentId || event.scopeSeq !== expectedScopeSeq
      || !Object.values(TRANSITION_KINDS).includes(event.transitionKind)
      || !hexDigest(event.pairDigest)
      || !Number.isSafeInteger(event.registryGeneration) || event.registryGeneration < 1
      || !Number.isSafeInteger(event.entitlementVersion) || event.entitlementVersion < 1
      || !/^[\x21-\x7e]{1,256}$/.test(String(event.appliedAckId || ''))
      || !hexDigest(event.appliedAckPayloadDigest)
      || !canonicalIso(event.deletedAt)
      || Buffer.byteLength(protocol.canonicalJson(event), 'utf8') > MAX_DELETION_ROW_BYTES) {
    throw integrityError();
  }
  return Object.freeze(event);
}

function checkedStageInput(ctx, value) {
  const keys = [
    'artifactDigest', 'customerId', 'deploymentId', 'entitlementState',
    'nowMs', 'outboxes', 'registryState',
  ];
  if (!plainRecord(value) || Object.keys(value).sort().join(',') !== keys.sort().join(',')) {
    throw pairInputError();
  }
  assertScope(ctx, value.customerId, value.deploymentId);
  if (!hexDigest(value.artifactDigest) || !plainRecord(value.entitlementState)
      || !plainRecord(value.registryState) || !plainRecord(value.outboxes)
      || !value.outboxes.delivered || !value.outboxes.applied) throw pairInputError();
  return { ...value, nowMs: checkedTime(value.nowMs) };
}

function checkedDisposition(value) {
  if (!plainRecord(value) || !['allow', 'block'].includes(value.protectedEgress)
      || typeof value.mode !== 'string' || (value.reason !== null && typeof value.reason !== 'string')) {
    throw integrityError();
  }
  if (value.protectedEgress === 'allow' && !checkedAuthority(value.authority)) {
    throw integrityError();
  }
  return value;
}

function checkedAuthority(value) {
  if (!plainRecord(value) || !['standard', 'enterprise'].includes(value.plan)
      || !Number.isSafeInteger(value.seats) || value.seats < 0 || value.seats > 1_000_000
      || !Array.isArray(value.features) || value.features.length > 128
      || value.features.some((feature) => !/^[a-z0-9][a-z0-9_.-]{0,63}$/.test(feature))
      || new Set(value.features).size !== value.features.length) throw integrityError();
  return Object.freeze({ plan: value.plan, seats: value.seats, features: Object.freeze([...value.features]) });
}

function intersectAuthority(current, acknowledged) {
  const left = checkedAuthority(current);
  const right = checkedAuthority(acknowledged);
  const allowed = new Set(right.features);
  return Object.freeze({
    plan: left.plan === 'standard' || right.plan === 'standard' ? 'standard' : 'enterprise',
    seats: Math.min(left.seats, right.seats),
    features: Object.freeze(left.features.filter((feature) => allowed.has(feature))),
  });
}

function sameSourcePair(source, pair) {
  const keys = [
    'customerId', 'deploymentId', 'registryGeneration', 'registryStateDigest', 'registryStatus',
    'entitlementVersion', 'entitlementDigest', 'entitlementStatus', 'authority',
    'entitlementIssuedAt', 'entitlementExpiresAt', 'entitlementFallbackUntil',
    'entitlementReasonCode', 'entitlementSigningKeyId',
  ];
  return protocol.canonicalJson(Object.fromEntries(keys.map((key) => [key, source[key]])))
    === protocol.canonicalJson(Object.fromEntries(keys.map((key) => [key, pair[key]])));
}

function transitionKind(prior, candidate) {
  if (!prior || !sameEntitlementLineage(candidate, prior)) {
    return TRANSITION_KINDS.ENTITLEMENT_RELEASE;
  }
  if (candidate.registryGeneration === prior.registryGeneration
      && candidate.registryStateDigest === prior.registryStateDigest
      && candidate.registryStatus === prior.registryStatus) return prior.transitionKind;
  return TRANSITION_KINDS.REGISTRY_ONLY;
}

function sameEntitlementLineage(left, right) {
  const keys = [
    'customerId', 'deploymentId', 'entitlementVersion', 'entitlementDigest',
    'artifactDigest', 'entitlementStatus', 'authority', 'entitlementIssuedAt',
    'entitlementExpiresAt', 'entitlementFallbackUntil', 'entitlementReasonCode',
    'entitlementSigningKeyId', 'deliveredAck', 'appliedAck',
  ];
  return protocol.canonicalJson(Object.fromEntries(keys.map((key) => [key, left[key]])))
    === protocol.canonicalJson(Object.fromEntries(keys.map((key) => [key, right[key]])));
}

function assertSharedAcknowledgementLineage(pairs, prior) {
  const candidate = pairs[0];
  if (pairs.some((pair) => !sameEntitlementLineage(candidate, pair))) {
    throw integrityError();
  }
  const releases = pairs.filter(
    (pair) => pair.transitionKind === TRANSITION_KINDS.ENTITLEMENT_RELEASE,
  );
  if (releases.length > 1) throw integrityError();
  if (releases.length === 0
      && prior.state.acknowledgedPairDigest !== candidate.pairDigest) throw integrityError();
}

function pairBehind(candidate, acknowledged) {
  return candidate.registryGeneration < acknowledged.registryGeneration
    || candidate.entitlementVersion < acknowledged.entitlementVersion;
}

function pairRowParameters(pair, nowMs) {
  return {
    pairDigest: pair.pairDigest,
    customerId: pair.customerId,
    deploymentId: pair.deploymentId,
    transitionKind: pair.transitionKind,
    registryGeneration: pair.registryGeneration,
    registryStateDigest: pair.registryStateDigest,
    registryStatus: pair.registryStatus,
    entitlementVersion: pair.entitlementVersion,
    entitlementDigest: pair.entitlementDigest,
    artifactDigest: pair.artifactDigest,
    entitlementStatus: pair.entitlementStatus,
    authorityJson: protocol.canonicalJson(pair.authority),
    entitlementIssuedAt: pair.entitlementIssuedAt,
    entitlementExpiresAt: pair.entitlementExpiresAt,
    entitlementFallbackUntil: pair.entitlementFallbackUntil,
    entitlementReasonCode: pair.entitlementReasonCode,
    entitlementSigningKeyId: pair.entitlementSigningKeyId,
    deliveredAckId: pair.deliveredAck.id,
    deliveredAckPayloadDigest: pair.deliveredAck.payloadDigest,
    appliedAckId: pair.appliedAck.id,
    appliedAckPayloadDigest: pair.appliedAck.payloadDigest,
    createdAt: new Date(checkedTime(nowMs)).toISOString(),
  };
}

function ackFromRow(row, stage) {
  const prefix = stage === 'delivered' ? 'delivered' : 'applied';
  return {
    id: row[`${prefix}_ack_id`],
    targetKind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    targetVersion: Number(row.entitlement_version),
    targetDigest: row.entitlement_digest,
    lifecycleStage: stage,
    payloadDigest: row[`${prefix}_ack_payload_digest`],
  };
}

function verifiedAuditDetail(ctx, row) {
  if (!row) return null;
  let entry;
  let detail;
  try {
    entry = JSON.parse(row.entry);
    if (!ctx.verifyAuditEntry(entry) || !STATE_ACTIONS.includes(entry.action)
        || entry.action !== row.action || entry.action !== row.connected_entry_action) throw new Error();
    detail = JSON.parse(entry.detail);
  } catch { throw integrityError(); }
  const keys = [
    'acknowledgedPairDigest', 'authorityRef', 'currentPairDigest', 'deletionCount',
    'deletionDigest', 'deletionHighWater', 'historyCount', 'historyDigest',
    'stateDigest', 'transitionKind',
  ];
  if (!plainRecord(detail) || Object.keys(detail).sort().join(',') !== keys.sort().join(',')
      || typeof detail.authorityRef !== 'string' || !hexDigest(detail.currentPairDigest)
      || (detail.acknowledgedPairDigest !== null && !hexDigest(detail.acknowledgedPairDigest))
      || !hexDigest(detail.historyDigest) || !hexDigest(detail.deletionDigest)
      || !hexDigest(detail.stateDigest)
      || !Object.values(TRANSITION_KINDS).includes(detail.transitionKind)
      || !Number.isSafeInteger(detail.historyCount) || detail.historyCount < 0
      || !Number.isSafeInteger(detail.deletionCount) || detail.deletionCount < 0
      || !Number.isSafeInteger(detail.deletionHighWater) || detail.deletionHighWater < 0) {
    throw integrityError();
  }
  return detail;
}

function referenceFor(ctx) {
  const value = ctx.authorityReference(ctx.customerId, ctx.deploymentId);
  if (!/^connected_[A-Za-z0-9_-]{24,96}$/.test(String(value || ''))) throw integrityError();
  return value;
}

function requireCoordinated(ctx) {
  if (!ctx.coordinator.isAuditVerified()) throw integrityError();
}

function requireAuditHealthy(ctx) {
  if (ctx.coordinator.isAuditVerified()) return;
  const result = ctx.verifyAuditState();
  if (!result || result.ok !== true) throw integrityError();
}

function lockAuthority(ctx, mutating) {
  if (typeof ctx.driver.lockAuditAppend === 'function') ctx.driver.lockAuditAppend();
  if (mutating && ctx.authorityCatalogMutationLock) ctx.authorityCatalogMutationLock.run();
  assertNoTemporaryCollision(ctx);
}

function assertNoTemporaryCollision(ctx) {
  if (ctx.tempObjects && ctx.tempObjects.all().length !== 0) throw integrityError();
}

function assertAuthorityCatalog(ctx, expectedIdentity = null) {
  if (ctx.authorityCatalogReadLock) ctx.authorityCatalogReadLock.run();
  const sqliteVersion = ctx.authorityCatalogKind === 'sqlite'
    ? readSqliteSchemaVersion(ctx) : null;
  if (sqliteVersion !== null && sqliteVersion !== ctx.sqliteSchemaVersion) {
    throw integrityError();
  }
  const rows = ctx.authorityCatalogRead.all();
  if (!Array.isArray(rows) || rows.length > MAX_AUTHORITY_CATALOG_ROWS) throw integrityError();
  let identity;
  if (ctx.authorityCatalogKind === 'postgres') {
    validatePostgresAuthorityCatalog(rows);
    identity = sha256(protocol.canonicalJson(rows));
  } else {
    for (const row of rows) {
      const bytes = row.object_sql_bytes === null ? null : Number(row.object_sql_bytes);
      if ((row.object_sql === null) !== (bytes === null)
          || (bytes !== null && (!Number.isSafeInteger(bytes) || bytes < 1
            || bytes > MAX_AUTHORITY_CATALOG_SQL_BYTES
            || Buffer.byteLength(row.object_sql, 'utf8') !== bytes))) throw integrityError();
    }
    identity = sha256(protocol.canonicalJson(rows));
    if (identity !== SQLITE_AUTHORITY_CATALOG_IDENTITY
        || readSqliteSchemaVersion(ctx) !== sqliteVersion) throw integrityError();
  }
  if (expectedIdentity !== null && identity !== expectedIdentity) throw integrityError();
  return identity;
}

function readSqliteSchemaVersion(ctx) {
  const row = ctx.sqliteSchemaVersionRead?.get();
  const value = Number(row?.schema_version);
  if (!Number.isSafeInteger(value) || value < 1) throw integrityError();
  return value;
}

function validatePostgresAuthorityCatalog(rows) {
  if (!Array.isArray(rows)) throw integrityError();
  const parsed = rows.map(parsePostgresCatalogRow);
  const runtime = parsed.filter((row) => row.objectType === 'runtime');
  if (runtime.length !== 1 || runtime[0].objectName.length < 1
      || runtime[0].detail?.currentUser !== runtime[0].objectName) throw integrityError();
  const owner = runtime[0].objectName;
  const objects = parsed.filter((row) => row.objectType !== 'runtime');
  const keys = new Set();
  for (const row of objects) {
    const key = `${row.objectType}:${row.tableName}:${row.objectName}`;
    if (keys.has(key) || !/^\d+$/.test(row.objectOid) || row.objectOid === '0'
        || !/^\d+$/.test(row.objectXmin) || row.objectXmin === '0'
        || row.objectOwner !== owner) throw integrityError();
    keys.add(key);
  }
  validatePostgresRelations(objects.filter((row) => row.objectType === 'relation'));
  validatePostgresColumns(objects.filter((row) => row.objectType === 'column'));
  validatePostgresConstraints(objects.filter((row) => row.objectType === 'constraint'));
  validatePostgresFunctions(objects.filter((row) => row.objectType === 'function'));
  validatePostgresTriggers(objects.filter((row) => row.objectType === 'trigger'), objects);
  validatePostgresPolicies(objects.filter((row) => row.objectType === 'policy'));
  validatePostgresIndexes(objects.filter((row) => row.objectType === 'index'));
}

function parsePostgresCatalogRow(row) {
  let detail;
  const detailBytes = Number(row.object_detail_bytes);
  if (typeof row.object_detail !== 'string'
      || !Number.isSafeInteger(detailBytes) || detailBytes < 2
      || detailBytes > MAX_AUTHORITY_CATALOG_SQL_BYTES
      || Buffer.byteLength(row.object_detail, 'utf8') !== detailBytes) {
    throw integrityError();
  }
  try { detail = JSON.parse(row.object_detail); } catch { throw integrityError(); }
  const value = {
    objectType: String(row.object_type || ''),
    objectName: String(row.object_name || ''),
    tableName: String(row.table_name || ''),
    objectOid: String(row.object_oid || ''),
    objectXmin: String(row.object_xmin || ''),
    objectOwner: String(row.object_owner || ''),
    detail,
  };
  if (!plainRecord(detail) || !/^[a-z]+$/.test(value.objectType)
      || value.objectName.length < 1 || value.objectName.length > 256
      || value.tableName.length > 128 || value.objectOwner.length > 128) throw integrityError();
  return Object.freeze(value);
}

function validatePostgresRelations(rows) {
  if (rows.length !== AUTHORITY_TABLES.length) throw integrityError();
  const expected = new Set(AUTHORITY_TABLES);
  for (const row of rows) {
    if (!expected.delete(row.objectName) || row.tableName !== row.objectName
        || row.detail?.relkind !== 'r' || row.detail?.rowSecurity !== true
        || row.detail?.forceRowSecurity !== true || row.detail?.persistence !== 'p'
        || row.detail?.hasRules !== false || row.detail?.hasTriggers !== true
        || row.detail?.hasIndex !== true) {
      throw integrityError();
    }
  }
  if (expected.size !== 0) throw integrityError();
}

function validatePostgresColumns(rows) {
  const expected = postgresColumnManifest();
  if (rows.length !== expected.size) throw integrityError();
  for (const row of rows) {
    const expectedColumn = expected.get(row.objectName);
    if (!expectedColumn || row.tableName !== expectedColumn.tableName
        || Number(row.detail?.position) !== expectedColumn.position
        || row.detail?.type !== expectedColumn.type
        || row.detail?.notNull !== expectedColumn.notNull
        || row.detail?.identity !== expectedColumn.identity
        || row.detail?.generated !== '' || row.detail?.defaultCollation !== true
        || row.detail?.default !== null) throw integrityError();
    expected.delete(row.objectName);
  }
  if (expected.size !== 0) throw integrityError();
}

function postgresColumnManifest() {
  const manifest = new Map();
  const add = (tableName, columns) => columns.forEach((column, index) => {
    const [name, type = 'text', notNull = true, identity = ''] = column;
    manifest.set(`${tableName}:${name}`, {
      tableName, position: index + 1, type, notNull, identity,
    });
  });
  add('connected_authority_pair_lineage', [
    ['pair_digest'], ['customer_id'], ['deployment_id'], ['transition_kind'],
    ['registry_generation', 'bigint'], ['registry_state_digest'], ['registry_status'],
    ['entitlement_version', 'bigint'], ['entitlement_digest'], ['artifact_digest'],
    ['entitlement_status'], ['authority_json'], ['entitlement_issued_at'],
    ['entitlement_expires_at'], ['entitlement_fallback_until', 'text', false],
    ['entitlement_reason_code'], ['entitlement_signing_key_id'], ['delivered_ack_id'],
    ['delivered_ack_payload_digest'], ['applied_ack_id'], ['applied_ack_payload_digest'],
    ['created_at'],
  ]);
  add('connected_authority_pair_deletions', [
    ['event_seq', 'bigint', true, 'a'], ['event_version', 'smallint'], ['customer_id'],
    ['deployment_id'], ['scope_seq', 'bigint'], ['transition_kind'], ['pair_digest'],
    ['registry_generation', 'bigint'], ['entitlement_version', 'bigint'],
    ['applied_ack_id'], ['applied_ack_payload_digest'], ['deleted_at'],
  ]);
  add('connected_acknowledged_authority_state', [
    ['customer_id'], ['deployment_id'], ['authority_ref'], ['current_pair_digest'],
    ['current_registry_generation', 'bigint'], ['current_registry_state_digest'],
    ['current_entitlement_version', 'bigint'], ['current_entitlement_digest'],
    ['acknowledged_registry_generation', 'bigint', false],
    ['acknowledged_registry_state_digest', 'text', false],
    ['acknowledged_entitlement_version', 'bigint', false],
    ['acknowledged_entitlement_digest', 'text', false],
    ['acknowledged_pair_digest', 'text', false], ['history_count', 'bigint'],
    ['history_digest'], ['deletion_count', 'bigint'], ['deletion_high_water', 'bigint'],
    ['deletion_digest'], ['state_json'], ['updated_at'],
  ]);
  return manifest;
}

function validatePostgresConstraints(rows) {
  const structural = new Map([
    ['connected_authority_pair_lineage:p:pair_digest', /^PRIMARY KEY \(pair_digest\)$/],
    ['connected_authority_pair_lineage:u:customer_id,deployment_id,registry_generation,registry_state_digest,entitlement_version,entitlement_digest,artifact_digest',
      /^UNIQUE \(customer_id, deployment_id, registry_generation, registry_state_digest, entitlement_version, entitlement_digest, artifact_digest\)$/],
    ['connected_authority_pair_lineage:f:customer_id,deployment_id->connected_entitlement_state:customer_id,deployment_id',
      /^FOREIGN KEY \(customer_id, deployment_id\) REFERENCES (?:public\.)?connected_entitlement_state\(customer_id, deployment_id\)$/],
    ['connected_authority_pair_lineage:f:customer_id,deployment_id->connected_online_registry_state:customer_id,deployment_id',
      /^FOREIGN KEY \(customer_id, deployment_id\) REFERENCES (?:public\.)?connected_online_registry_state\(customer_id, deployment_id\)$/],
    ['connected_authority_pair_deletions:p:event_seq', /^PRIMARY KEY \(event_seq\)$/],
    ['connected_authority_pair_deletions:u:customer_id,deployment_id,scope_seq',
      /^UNIQUE \(customer_id, deployment_id, scope_seq\)$/],
    ['connected_acknowledged_authority_state:p:customer_id,deployment_id',
      /^PRIMARY KEY \(customer_id, deployment_id\)$/],
    ['connected_acknowledged_authority_state:u:authority_ref', /^UNIQUE \(authority_ref\)$/],
    ['connected_acknowledged_authority_state:u:current_pair_digest',
      /^UNIQUE \(current_pair_digest\)$/],
    ['connected_acknowledged_authority_state:u:acknowledged_pair_digest',
      /^UNIQUE \(acknowledged_pair_digest\)$/],
    ['connected_acknowledged_authority_state:f:customer_id,deployment_id->connected_entitlement_state:customer_id,deployment_id',
      /^FOREIGN KEY \(customer_id, deployment_id\) REFERENCES (?:public\.)?connected_entitlement_state\(customer_id, deployment_id\)$/],
    ['connected_acknowledged_authority_state:f:customer_id,deployment_id->connected_online_registry_state:customer_id,deployment_id',
      /^FOREIGN KEY \(customer_id, deployment_id\) REFERENCES (?:public\.)?connected_online_registry_state\(customer_id, deployment_id\)$/],
    ['connected_acknowledged_authority_state:f:current_pair_digest->connected_authority_pair_lineage:pair_digest',
      /^FOREIGN KEY \(current_pair_digest\) REFERENCES (?:public\.)?connected_authority_pair_lineage\(pair_digest\)$/],
    ['connected_acknowledged_authority_state:f:acknowledged_pair_digest->connected_authority_pair_lineage:pair_digest',
      /^FOREIGN KEY \(acknowledged_pair_digest\) REFERENCES (?:public\.)?connected_authority_pair_lineage\(pair_digest\)$/],
  ]);
  const checks = postgresCheckManifest();
  if (rows.length !== structural.size + [...checks.values()].reduce(
    (count, values) => count + values.size, 0,
  )) throw integrityError();
  for (const row of rows) {
    const detail = row.detail;
    if (!['c', 'p', 'u', 'f'].includes(detail?.type) || detail.validated !== true
        || detail.deferrable !== false || detail.deferred !== false
        || !Array.isArray(detail.columns)) throw integrityError();
    if (detail.type === 'c') {
      const expected = checks.get(row.tableName);
      const definition = collapseCatalogWhitespace(detail.definition);
      if (!expected || !expected.delete(definition)) throw integrityError();
      continue;
    }
    const columns = detail.columns.join(',');
    let key = `${row.tableName}:${detail.type}:${columns}`;
    if (detail.type === 'f') {
      if (!Array.isArray(detail.referencedColumns)) throw integrityError();
      key += `->${String(detail.referencedTable || '').replace(/^public\./, '')}`
        + `:${detail.referencedColumns.join(',')}`;
    } else if (detail.referencedTable !== null || detail.referencedColumns !== null) {
      throw integrityError();
    }
    const expectedDefinition = structural.get(key);
    if (!expectedDefinition
        || !expectedDefinition.test(collapseCatalogWhitespace(detail.definition))) {
      throw integrityError();
    }
    structural.delete(key);
  }
  if (structural.size !== 0 || [...checks.values()].some((values) => values.size !== 0)) {
    throw integrityError();
  }
}

function postgresCheckManifest() {
  const digest = (name) => `CHECK (${name} ~ '^[0-9a-f]{64}$'::text)`;
  return new Map([
    ['connected_authority_pair_lineage', new Set([
      digest('pair_digest'),
      "CHECK (transition_kind = ANY (ARRAY['entitlement_release'::text, 'registry_only'::text]))",
      'CHECK (registry_generation >= 1)',
      digest('registry_state_digest'),
      "CHECK (registry_status = ANY (ARRAY['active'::text, 'revoked'::text]))",
      'CHECK (entitlement_version >= 1)',
      digest('entitlement_digest'),
      digest('artifact_digest'),
      "CHECK (entitlement_status = ANY (ARRAY['active'::text, 'paused'::text, 'revoked'::text]))",
      'CHECK (octet_length(authority_json) <= 16384)',
      'CHECK (octet_length(delivered_ack_id) >= 1 AND octet_length(delivered_ack_id) <= 256)',
      digest('delivered_ack_payload_digest'),
      'CHECK (octet_length(applied_ack_id) >= 1 AND octet_length(applied_ack_id) <= 256)',
      digest('applied_ack_payload_digest'),
    ])],
    ['connected_authority_pair_deletions', new Set([
      'CHECK (event_version = 1)',
      'CHECK (length(customer_id) >= 2 AND length(customer_id) <= 63)',
      "CHECK (deployment_id ~ '^dep_[0-9a-f]{32}$'::text)",
      'CHECK (scope_seq >= 1)',
      "CHECK (transition_kind = ANY (ARRAY['entitlement_release'::text, 'registry_only'::text]))",
      digest('pair_digest'),
      'CHECK (registry_generation >= 1)',
      'CHECK (entitlement_version >= 1)',
      'CHECK (length(applied_ack_id) >= 1 AND length(applied_ack_id) <= 256)',
      digest('applied_ack_payload_digest'),
      'CHECK (length(deleted_at) = 24)',
    ])],
    ['connected_acknowledged_authority_state', new Set([
      'CHECK (current_registry_generation >= 1)',
      `CHECK (length(current_registry_state_digest) = 64 AND ${digest(
        'current_registry_state_digest',
      ).slice(7, -1)})`,
      'CHECK (current_entitlement_version >= 1)',
      `CHECK (length(current_entitlement_digest) = 64 AND ${digest(
        'current_entitlement_digest',
      ).slice(7, -1)})`,
      'CHECK (acknowledged_registry_generation >= 1)',
      "CHECK (acknowledged_registry_state_digest IS NULL OR acknowledged_registry_state_digest ~ '^[0-9a-f]{64}$'::text)",
      'CHECK (acknowledged_entitlement_version >= 1)',
      "CHECK (acknowledged_entitlement_digest IS NULL OR acknowledged_entitlement_digest ~ '^[0-9a-f]{64}$'::text)",
      'CHECK (history_count >= 0)',
      digest('history_digest'),
      'CHECK (deletion_count >= 0)',
      'CHECK (deletion_high_water >= 0)',
      digest('deletion_digest'),
      'CHECK (acknowledged_registry_generation IS NULL AND acknowledged_registry_state_digest IS NULL AND acknowledged_entitlement_version IS NULL AND acknowledged_entitlement_digest IS NULL AND acknowledged_pair_digest IS NULL OR acknowledged_registry_generation IS NOT NULL AND acknowledged_registry_state_digest IS NOT NULL AND acknowledged_entitlement_version IS NOT NULL AND acknowledged_entitlement_digest IS NOT NULL AND acknowledged_pair_digest IS NOT NULL)',
      'CHECK (deletion_count = 0 AND deletion_high_water = 0 OR deletion_count > 0 AND deletion_high_water > 0)',
      'CHECK (deletion_count = history_count)',
    ])],
  ]);
}

function validatePostgresFunctions(rows) {
  const expectedSources = {
    record_connected_authority_pair_delete: `BEGIN
        INSERT INTO public.connected_authority_pair_deletions
          (event_version, customer_id, deployment_id, scope_seq, transition_kind,
           pair_digest, registry_generation, entitlement_version, applied_ack_id,
           applied_ack_payload_digest, deleted_at)
        SELECT 1, OLD.customer_id, OLD.deployment_id, COALESCE(MAX(scope_seq), 0) + 1,
          OLD.transition_kind, OLD.pair_digest, OLD.registry_generation,
          OLD.entitlement_version, OLD.applied_ack_id, OLD.applied_ack_payload_digest,
          to_char(pg_catalog.clock_timestamp() AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        FROM public.connected_authority_pair_deletions
        WHERE customer_id = OLD.customer_id AND deployment_id = OLD.deployment_id;
        RETURN OLD;
      END;`,
    reject_connected_authority_pair_update: `BEGIN
        RAISE EXCEPTION USING ERRCODE = '55000',
          MESSAGE = 'connected authority pair lineage is immutable';
      END;`,
    reject_connected_authority_pair_deletion_mutation: `BEGIN
        RAISE EXCEPTION USING ERRCODE = '55000',
          MESSAGE = 'connected authority pair deletion log is append-only';
      END;`,
  };
  if (rows.length !== Object.keys(expectedSources).length) throw integrityError();
  const remaining = new Set(Object.keys(expectedSources));
  for (const row of rows) {
    const detail = row.detail;
    if (!remaining.delete(row.objectName) || row.tableName !== '' || detail?.kind !== 'f'
        || detail?.securityDefiner !== false || detail?.volatility !== 'v'
        || detail?.language !== 'plpgsql' || detail?.strict !== false
        || detail?.leakproof !== false || detail?.parallel !== 'u'
        || detail?.arguments !== '' || detail?.returnType !== 'trigger'
        || !Array.isArray(detail?.config) || detail.config.length !== 1
        || detail.config[0] !== 'search_path=pg_catalog'
        || collapseCatalogWhitespace(detail.source)
          !== collapseCatalogWhitespace(expectedSources[row.objectName])) throw integrityError();
  }
  if (remaining.size !== 0) throw integrityError();
}

function validatePostgresTriggers(rows, objects) {
  const functions = new Map(objects.filter((row) => row.objectType === 'function')
    .map((row) => [row.objectName, row.objectOid]));
  const expected = new Map([
    ['connected_authority_pair_record_delete', {
      table: 'connected_authority_pair_lineage', type: 9,
      functionName: 'record_connected_authority_pair_delete',
      definition: /^CREATE TRIGGER connected_authority_pair_record_delete AFTER DELETE ON (?:public\.)?connected_authority_pair_lineage FOR EACH ROW EXECUTE FUNCTION (?:public\.)?record_connected_authority_pair_delete\(\)$/,
    }],
    ['connected_authority_pair_no_update', {
      table: 'connected_authority_pair_lineage', type: 19,
      functionName: 'reject_connected_authority_pair_update',
      definition: /^CREATE TRIGGER connected_authority_pair_no_update BEFORE UPDATE ON (?:public\.)?connected_authority_pair_lineage FOR EACH ROW EXECUTE FUNCTION (?:public\.)?reject_connected_authority_pair_update\(\)$/,
    }],
    ['connected_authority_pair_deletions_no_update', {
      table: 'connected_authority_pair_deletions', type: 19,
      functionName: 'reject_connected_authority_pair_deletion_mutation',
      definition: /^CREATE TRIGGER connected_authority_pair_deletions_no_update BEFORE UPDATE ON (?:public\.)?connected_authority_pair_deletions FOR EACH ROW EXECUTE FUNCTION (?:public\.)?reject_connected_authority_pair_deletion_mutation\(\)$/,
    }],
    ['connected_authority_pair_deletions_no_delete', {
      table: 'connected_authority_pair_deletions', type: 11,
      functionName: 'reject_connected_authority_pair_deletion_mutation',
      definition: /^CREATE TRIGGER connected_authority_pair_deletions_no_delete BEFORE DELETE ON (?:public\.)?connected_authority_pair_deletions FOR EACH ROW EXECUTE FUNCTION (?:public\.)?reject_connected_authority_pair_deletion_mutation\(\)$/,
    }],
  ]);
  if (rows.length !== expected.size) throw integrityError();
  for (const row of rows) {
    const value = expected.get(row.objectName);
    if (!value || row.tableName !== value.table || row.detail?.enabled !== 'O'
        || Number(row.detail?.type) !== value.type
        || String(row.detail?.functionOid) !== functions.get(value.functionName)
        || !value.definition.test(collapseCatalogWhitespace(row.detail?.definition))) {
      throw integrityError();
    }
    expected.delete(row.objectName);
  }
  if (expected.size !== 0) throw integrityError();
}

function validatePostgresPolicies(rows) {
  const expected = new Map([
    ['connected_authority_pair_tenant_isolation', 'connected_authority_pair_lineage'],
    ['connected_authority_pair_deletion_tenant_isolation', 'connected_authority_pair_deletions'],
    ['connected_acknowledged_authority_tenant_isolation',
      'connected_acknowledged_authority_state'],
  ]);
  const expression = "((COALESCE(current_setting('redactwall.org_id'::text, true), ''::text) <> ''::text) AND (customer_id = current_setting('redactwall.org_id'::text, true)))";
  if (rows.length !== expected.size) throw integrityError();
  for (const row of rows) {
    const table = expected.get(row.objectName);
    if (!table || row.tableName !== table || row.detail?.permissive !== true
        || row.detail?.command !== '*' || row.detail?.roles !== '{0}'
        || collapseCatalogWhitespace(row.detail?.using) !== expression
        || collapseCatalogWhitespace(row.detail?.check) !== expression) throw integrityError();
    expected.delete(row.objectName);
  }
  if (expected.size !== 0) throw integrityError();
}

function validatePostgresIndexes(rows) {
  const expected = [
    ['connected_authority_pair_lineage_pkey', 'connected_authority_pair_lineage', true,
      'pair_digest'],
    ['connected_authority_pair_line_customer_id_deployment_id_reg_key',
      'connected_authority_pair_lineage', true,
      'customer_id, deployment_id, registry_generation, registry_state_digest, entitlement_version, entitlement_digest, artifact_digest'],
    ['idx_connected_authority_pair_ack', 'connected_authority_pair_lineage', false,
      'customer_id, deployment_id, applied_ack_id, applied_ack_payload_digest'],
    ['idx_connected_authority_pair_high_water', 'connected_authority_pair_lineage', false,
      'customer_id, deployment_id, registry_generation, entitlement_version'],
    ['connected_authority_pair_deletions_pkey', 'connected_authority_pair_deletions', true,
      'event_seq'],
    ['connected_authority_pair_dele_customer_id_deployment_id_sco_key',
      'connected_authority_pair_deletions', true, 'customer_id, deployment_id, scope_seq'],
    ['idx_connected_authority_pair_deletion_scope',
      'connected_authority_pair_deletions', false,
      'customer_id, deployment_id, scope_seq DESC'],
    ['connected_acknowledged_authority_state_pkey',
      'connected_acknowledged_authority_state', true, 'customer_id, deployment_id'],
    ['connected_acknowledged_authority_state_authority_ref_key',
      'connected_acknowledged_authority_state', true, 'authority_ref'],
    ['connected_acknowledged_authority_state_current_pair_digest_key',
      'connected_acknowledged_authority_state', true, 'current_pair_digest'],
    ['connected_acknowledged_authority_s_acknowledged_pair_digest_key',
      'connected_acknowledged_authority_state', true, 'acknowledged_pair_digest'],
    ['idx_connected_acknowledged_authority_high_water',
      'connected_acknowledged_authority_state', false,
      'customer_id, deployment_id, acknowledged_registry_generation DESC, acknowledged_entitlement_version DESC'],
  ];
  if (rows.length !== expected.length) throw integrityError();
  for (const row of rows) {
    if (row.detail?.valid !== true || row.detail?.ready !== true || row.detail?.live !== true) {
      throw integrityError();
    }
    if (!/^[a-z][a-z0-9_]{0,127}$/.test(row.objectName)) throw integrityError();
    const definition = collapseCatalogWhitespace(row.detail?.definition);
    const index = expected.findIndex(([name, table, unique, columns]) => {
      if (row.objectName !== name || row.tableName !== table) return false;
      const prefix = unique ? 'CREATE UNIQUE INDEX' : 'CREATE INDEX';
      return definition === `${prefix} ${row.objectName} ON public.${table} USING btree (${columns})`
        || definition === `${prefix} ${row.objectName} ON ${table} USING btree (${columns})`;
    });
    if (index < 0) throw integrityError();
    expected.splice(index, 1);
  }
  if (expected.length !== 0) throw integrityError();
}

function collapseCatalogWhitespace(value) {
  return String(value || '').trim().replace(/\s+/g, ' ');
}

function assertLivePairBound(ctx) {
  if (livePairCount(ctx) < 1) throw integrityError();
}

function livePairCount(ctx) {
  const count = Number(ctx.pairCount.get(ctx.customerId, ctx.deploymentId)?.count || 0);
  if (!Number.isSafeInteger(count) || count < 0 || count > MAX_LIVE_PAIR_LINEAGES) {
    throw integrityError();
  }
  return count;
}

function assertScope(ctx, customerId, deploymentId) {
  assertScopeValue(customerId, deploymentId);
  if (customerId !== ctx.customerId || deploymentId !== ctx.deploymentId) throw pairInputError();
}

function assertScopeValue(customerId, deploymentId) {
  if (!/^[a-z0-9][a-z0-9_-]{1,62}$/.test(String(customerId || ''))
      || !isDeploymentId(deploymentId)) throw pairInputError();
}

function initialAcknowledgementRestriction(current) {
  if (current.protectedEgress !== 'allow') {
    return Object.freeze({
      ...current,
      authority: null,
      initialAcknowledgementRequired: true,
    });
  }
  return blocked('connected_initial_acknowledgement_pending', 'blocked', null, true);
}

function blocked(reason, mode = 'blocked', authority = null, initialAckRequired = false) {
  return Object.freeze({
    protectedEgress: 'block',
    mode,
    reason,
    authority,
    ...(initialAckRequired ? { initialAcknowledgementRequired: true } : {}),
  });
}

function nextHistoryDigest(previous, pair) {
  return sha256(`${previous}\0${protocol.canonicalJson(pair)}`);
}

function nextDeletionDigest(previous, event) {
  return sha256(`redactwall.connected-authority-pair-deletions.chain.v1\0${previous}\0${
    protocol.canonicalJson(event)
  }`);
}

function stateDigest(state) {
  return sha256(protocol.canonicalJson(state));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function hexDigest(value) {
  return /^[a-f0-9]{64}$/.test(String(value || ''));
}

function validIso(value) {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function canonicalIso(value) {
  if (typeof value !== 'string' || value.length !== 24) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function nullableNumber(value) {
  return value === null || value === undefined ? null : Number(value);
}

function checkedTime(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw pairInputError();
  return parsed;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.values(value).forEach(deepFreeze);
  return Object.freeze(value);
}

function plainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function receiverless(callback) {
  return (...args) => Reflect.apply(callback, undefined, args);
}

function requireFunction(value, name) {
  if (typeof value !== 'function') throw new TypeError(`${name} is required`);
}

function pairInputError() {
  const error = new Error('connected acknowledged authority input rejected');
  error.code = 'connected_authority_pair_invalid';
  return error;
}

function pairConflict() {
  const error = new Error('connected acknowledged authority pair conflicts with its high-water');
  error.code = 'connected_authority_pair_conflict';
  return error;
}

function integrityError() {
  const error = new Error('connected acknowledged authority is not anchored by audit evidence');
  error.code = 'CONNECTED_ACKNOWLEDGED_AUTHORITY_INTEGRITY';
  return error;
}

function deletionCapacityError() {
  const error = new Error('connected authority deletion history capacity exceeded');
  error.code = 'CONNECTED_AUTHORITY_DELETION_HISTORY_CAPACITY';
  return error;
}

module.exports = Object.freeze({
  EMPTY_DELETION_DIGEST,
  EMPTY_HISTORY_DIGEST,
  MAX_DELETION_HISTORY_ROWS,
  MAX_DELETION_ROW_BYTES,
  MAX_LIVE_PAIR_LINEAGES,
  STATE_ACTIONS,
  TRANSITION_KINDS,
  createConnectedAcknowledgedAuthorityStore,
});
