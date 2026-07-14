'use strict';

/**
 * Live Postgres proof for the unreleased connected-licensing v11-v13 train.
 *
 * The migration must run as the same non-superuser role that directly owns the
 * production database. That is the only way to prove FORCE ROW LEVEL SECURITY
 * covers the owner and that v13 can temporarily inspect an old, otherwise
 * invisible, applied-only outbox before restoring the RLS boundary.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { MIGRATIONS } = require('../server/storage/migrations');
const { createConnectedEntitlementStore } = require('../server/connected-entitlement-store');
const { createPgDriver } = require('../server/storage/pg-driver');

const ADMIN_URL = process.env.REDACTWALL_TEST_PG_URL || '';
const TENANT_GUC = 'redactwall.org_id';
const REQUIRED_CONNECTED_TABLES = [
  'connected_entitlement_state',
  'connected_ack_outbox',
  'connected_online_registry_state',
  'connected_ack_health',
];
const OPTIONAL_CONNECTED_TABLES = [
  'connected_ack_archive',
  'connected_ack_archive_mutations',
];
const NOW = '2026-07-13T12:00:00.000Z';

function quotedIdentifier(value) {
  assert.match(value, /^[a-z][a-z0-9_]+$/);
  return `"${value}"`;
}

function fixtureName(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

async function provisionDatabase() {
  const { Client } = require('pg');
  const role = fixtureName('rw_conn_owner');
  const database = fixtureName('rw_conn_migration');
  const password = crypto.randomBytes(24).toString('hex');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  try {
    await admin.query(
      `CREATE ROLE ${quotedIdentifier(role)} LOGIN PASSWORD '${password}' `
      + 'NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT',
    );
    await admin.query(
      `CREATE DATABASE ${quotedIdentifier(database)} OWNER ${quotedIdentifier(role)}`,
    );
  } catch (error) {
    await admin.query(`DROP DATABASE IF EXISTS ${quotedIdentifier(database)} WITH (FORCE)`).catch(() => {});
    await admin.query(`DROP ROLE IF EXISTS ${quotedIdentifier(role)}`).catch(() => {});
    throw error;
  } finally {
    await admin.end();
  }

  const applicationUrl = new URL(ADMIN_URL);
  applicationUrl.username = role;
  applicationUrl.password = password;
  applicationUrl.pathname = `/${database}`;
  return { role, database, applicationUrl: applicationUrl.toString() };
}

async function destroyDatabase(fixture) {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${quotedIdentifier(fixture.database)} WITH (FORCE)`);
    await admin.query(`DROP ROLE IF EXISTS ${quotedIdentifier(fixture.role)}`);
  } finally {
    await admin.end();
  }
}

async function connectAsOwner(fixture) {
  const { Client } = require('pg');
  const client = new Client({ connectionString: fixture.applicationUrl });
  await client.connect();
  return client;
}

async function assertDirectNonSuperuserOwner(client, fixture) {
  const { rows } = await client.query(`
    SELECT current_user AS current_role,
           session_user AS session_role,
           pg_get_userbyid(d.datdba) AS database_owner,
           r.rolsuper,
           r.rolbypassrls,
           r.rolcreatedb,
           r.rolcreaterole
    FROM pg_database d
    JOIN pg_roles r ON r.rolname = current_user
    WHERE d.datname = current_database()
  `);
  assert.deepStrictEqual(rows, [{
    current_role: fixture.role,
    session_role: fixture.role,
    database_owner: fixture.role,
    rolsuper: false,
    rolbypassrls: false,
    rolcreatedb: false,
    rolcreaterole: false,
  }]);
}

async function ensureMigrationLedger(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      "appliedAt" TEXT NOT NULL
    )
  `);
}

async function applyMigration(client, migration) {
  await client.query('BEGIN');
  try {
    await client.query(migration.postgres);
    await client.query(
      'INSERT INTO schema_migrations (version, name, "appliedAt") VALUES ($1, $2, $3)',
      [migration.version, migration.name, new Date().toISOString()],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  }
}

async function migrateThrough(client, maximumVersion) {
  await ensureMigrationLedger(client);
  for (const migration of MIGRATIONS) {
    if (migration.version > maximumVersion) break;
    await applyMigration(client, migration);
  }
}

async function setTenant(client, customerId) {
  await client.query('SELECT set_config($1, $2, false)', [TENANT_GUC, customerId]);
}

function tenantFixture(suffix) {
  const lower = suffix.toLowerCase();
  return {
    customerId: `customer-connected-${lower}`,
    deploymentId: `dep_${lower.repeat(32).slice(0, 32)}`,
    entitlementDigest: lower.repeat(64).slice(0, 64),
    registryDigest: suffix === 'a' ? '1'.repeat(64) : '2'.repeat(64),
    ackDigest: suffix === 'a' ? '3'.repeat(64) : '4'.repeat(64),
  };
}

async function seedFinalTenantRows(client, fixture, includeArchive) {
  const {
    customerId, deploymentId, entitlementDigest, registryDigest, ackDigest,
  } = fixture;
  await setTenant(client, customerId);
  await client.query(`
    INSERT INTO connected_entitlement_state
      (customer_id, deployment_id, authority_ref, entitlement_version,
       entitlement_digest, state_json, updated_at)
    VALUES ($1, $2, $3, 1, $4, '{}', $5)
  `, [customerId, deploymentId, `entitlement:${customerId}`, entitlementDigest, NOW]);
  await client.query(`
    INSERT INTO connected_online_registry_state
      (customer_id, deployment_id, authority_ref, registry_generation,
       registry_state_digest, status, state_json, updated_at)
    VALUES ($1, $2, $3, 1, $4, 'active', '{}', $5)
  `, [customerId, deploymentId, `registry:${customerId}`, registryDigest, NOW]);
  await client.query(`
    INSERT INTO connected_ack_outbox
      (id, customer_id, deployment_id, target_kind, target_version,
       target_digest, lifecycle_stage, payload_json, payload_digest, status,
       failure_class, attempts, next_attempt_at, created_at, updated_at)
    VALUES ($1, $2, $3, 'entitlement', 1, $4, 'delivered', '{}', $5,
      'pending', NULL, 0, $6, $6, $6)
  `, [`ack-pending-${customerId}`, customerId, deploymentId, entitlementDigest, ackDigest, NOW]);
  await client.query(`
    INSERT INTO connected_ack_health
      (customer_id, deployment_id, authority_ref, state_json, updated_at)
    VALUES ($1, $2, $3, '{}', $4)
  `, [customerId, deploymentId, `ack-health:${customerId}`, NOW]);
  if (includeArchive) {
    await client.query(`
      INSERT INTO connected_ack_archive
        (id, customer_id, deployment_id, target_kind, target_version,
         target_digest, lifecycle_stage, payload_json, payload_digest, status,
         failure_class, attempts, next_attempt_at, created_at, updated_at, archived_at)
      VALUES ($1, $2, $3, 'entitlement', 1, $4, 'applied', '{}', $5,
        'acknowledged', NULL, 1, $6, $6, $6, $6)
    `, [`ack-archive-${customerId}`, customerId, deploymentId, entitlementDigest, ackDigest, NOW]);
  }
}

async function connectedTableNames(client) {
  const expected = [...REQUIRED_CONNECTED_TABLES, ...OPTIONAL_CONNECTED_TABLES];
  const { rows } = await client.query(`
    SELECT c.relname AS table_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY($1::text[])
  `, [expected]);
  const present = rows.map((row) => row.table_name).sort();
  for (const table of REQUIRED_CONNECTED_TABLES) {
    assert.ok(present.includes(table), `${table} must exist after v13`);
  }
  return present;
}

async function assertForceRlsAndPolicies(client, fixture, tables) {
  const { rows: security } = await client.query(`
    SELECT c.relname AS table_name,
           c.relrowsecurity AS enabled,
           c.relforcerowsecurity AS forced,
           pg_get_userbyid(c.relowner) AS owner
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY($1::text[])
  `, [tables]);
  assert.strictEqual(security.length, tables.length);
  for (const table of tables) {
    const row = security.find((entry) => entry.table_name === table);
    assert.deepStrictEqual(row, {
      table_name: table,
      enabled: true,
      forced: true,
      owner: fixture.role,
    });
  }

  const { rows: policies } = await client.query(`
    SELECT tablename, policyname, qual, with_check
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = ANY($1::text[])
  `, [tables]);
  for (const table of tables) {
    const tablePolicies = policies.filter((policy) => policy.tablename === table);
    assert.ok(tablePolicies.length > 0, `${table} must have an RLS policy`);
    assert.ok(tablePolicies.some((policy) => (
      String(policy.qual).includes(TENANT_GUC)
      && String(policy.with_check).includes(TENANT_GUC)
    )), `${table} policy must bind reads and writes to ${TENANT_GUC}`);
  }
}

async function assertArchiveMutationCatalog(client) {
  const { rows: triggers } = await client.query(`
    SELECT t.tgname AS name, t.tgenabled AS enabled
    FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE NOT t.tgisinternal AND n.nspname = 'public'
      AND c.relname = ANY($1::text[])
    ORDER BY t.tgname
  `, [[
    'connected_ack_archive',
    'connected_ack_archive_mutations',
  ]]);
  assert.deepStrictEqual(triggers, [
    { name: 'connected_ack_archive_mutations_no_update', enabled: 'O' },
    { name: 'connected_ack_archive_no_update', enabled: 'O' },
    { name: 'connected_ack_archive_record_mutation', enabled: 'O' },
  ]);
  const { rows: functions } = await client.query(`
    SELECT proname AS name, prosecdef AS security_definer, provolatile AS volatility,
      prosrc AS source, COALESCE(proconfig, ARRAY[]::text[]) AS config
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = ANY($1::text[]) ORDER BY p.proname
  `, [[
    'record_connected_ack_archive_mutation',
    'reject_connected_ack_archive_event_mutation',
    'reject_connected_ack_archive_mutation',
  ]]);
  assert.deepStrictEqual(functions.map(({ name, security_definer, volatility, config }) => ({
    name, security_definer, volatility, config,
  })), [
    { name: 'record_connected_ack_archive_mutation', security_definer: false, volatility: 'v', config: ['search_path=pg_catalog'] },
    { name: 'reject_connected_ack_archive_event_mutation', security_definer: false, volatility: 'v', config: ['search_path=pg_catalog'] },
    { name: 'reject_connected_ack_archive_mutation', security_definer: false, volatility: 'v', config: ['search_path=pg_catalog'] },
  ]);
  assert.match(functions[0].source, /INSERT INTO public\.connected_ack_archive_mutations/);
  assert.match(functions[0].source, /FROM public\.connected_ack_archive_mutations/);
}

function assertRuntimeArchiveCatalog(fixture, tenant) {
  const driver = createPgDriver(fixture.applicationUrl);
  try {
    driver.setTenantContext(tenant.customerId);
    const store = createConnectedEntitlementStore({
      customerId: tenant.customerId,
      deploymentId: tenant.deploymentId,
      driver,
      appendAudit() { throw new Error('empty archive verification must not append audit'); },
      authorityReference(customerId, deploymentId) {
        return `connected:${customerId}:${deploymentId}`;
      },
      ackReference(ackId) { return `ack:${ackId}`; },
      verifyAuditState() { return { ok: true }; },
      verifyAuditEntry() { return false; },
      verificationKeys() { return { publicKeys: {} }; },
      offlinePublicKey() { return ''; },
    });
    assert.deepStrictEqual(
      store.acknowledgementHealth(tenant.customerId, tenant.deploymentId),
      { ok: true },
      'the production store must accept and execute its exact Postgres archive catalog proof',
    );
  } finally {
    driver.close();
  }
}

async function assertTenantVisibility(client, tables, customerId) {
  await setTenant(client, customerId);
  for (const table of tables) {
    const { rows } = await client.query(
      `SELECT DISTINCT customer_id FROM ${quotedIdentifier(table)} ORDER BY customer_id`,
    );
    assert.deepStrictEqual(rows, [{ customer_id: customerId }], `${table}: tenant visibility`);
  }
}

async function proveEmptyUpgradeAndFinalIsolation() {
  const fixture = await provisionDatabase();
  let client;
  try {
    client = await connectAsOwner(fixture);
    await assertDirectNonSuperuserOwner(client, fixture);
    await migrateThrough(client, 12);
    await applyMigration(client, MIGRATIONS.find(({ version }) => version === 13));

    const { rows: versions } = await client.query(
      'SELECT version FROM schema_migrations WHERE version >= 11 ORDER BY version',
    );
    assert.deepStrictEqual(versions, [{ version: 11 }, { version: 12 }, { version: 13 }]);

    const tables = await connectedTableNames(client);
    await assertForceRlsAndPolicies(client, fixture, tables);
    await assertArchiveMutationCatalog(client);
    const includeArchive = tables.includes('connected_ack_archive');
    const tenantA = tenantFixture('a');
    const tenantB = tenantFixture('b');
    assertRuntimeArchiveCatalog(fixture, tenantA);
    await client.query(`CREATE TEMP TABLE connected_ack_archive_mutations
      (LIKE public.connected_ack_archive_mutations INCLUDING ALL)`);
    await client.query("SELECT set_config('search_path', 'pg_temp, public, pg_catalog', false)");
    await seedFinalTenantRows(client, tenantA, includeArchive);
    const { rows: publicMutationRows } = await client.query(`SELECT COUNT(*)::int AS count
      FROM public.connected_ack_archive_mutations`);
    const { rows: tempMutationRows } = await client.query(`SELECT COUNT(*)::int AS count
      FROM pg_temp.connected_ack_archive_mutations`);
    assert.deepStrictEqual(publicMutationRows, [{ count: 1 }],
      'the archive trigger must record through the public authority even under pg_temp shadowing');
    assert.deepStrictEqual(tempMutationRows, [{ count: 0 }],
      'caller-controlled pg_temp must never capture archive mutation evidence');
    await client.query("SELECT set_config('search_path', 'public, pg_catalog', false)");
    await client.query('DROP TABLE pg_temp.connected_ack_archive_mutations');
    await seedFinalTenantRows(client, tenantB, includeArchive);
    await assertTenantVisibility(client, tables, tenantA.customerId);
    await assertTenantVisibility(client, tables, tenantB.customerId);

    await setTenant(client, '');
    for (const table of tables) {
      const { rows } = await client.query(`SELECT customer_id FROM ${quotedIdentifier(table)}`);
      assert.deepStrictEqual(rows, [], `${table}: blank tenant must fail closed for the owner`);
    }

    await setTenant(client, tenantA.customerId);
    await assert.rejects(
      client.query(`
        INSERT INTO connected_entitlement_state
          (customer_id, deployment_id, authority_ref, entitlement_version,
           entitlement_digest, state_json, updated_at)
        VALUES ('customer-connected-cross-tenant', 'dep_cccccccccccccccccccccccccccccccc',
          'entitlement:cross-tenant', 1, $1, '{}', $2)
      `, ['5'.repeat(64), NOW]),
      (error) => error && error.code === '42501',
      'the direct owner must not write another tenant through FORCE RLS',
    );
  } finally {
    if (client) await client.end().catch(() => {});
    await destroyDatabase(fixture);
  }
}

async function seedAppliedOnlyIntermediate(client, tenant) {
  await setTenant(client, tenant.customerId);
  await client.query(`
    INSERT INTO connected_entitlement_state
      (customer_id, deployment_id, authority_ref, entitlement_version,
       entitlement_digest, state_json, updated_at)
    VALUES ($1, $2, $3, 1, $4, '{}', $5)
  `, [
    tenant.customerId,
    tenant.deploymentId,
    `entitlement:legacy:${tenant.customerId}`,
    tenant.entitlementDigest,
    NOW,
  ]);
  await client.query(`
    INSERT INTO connected_ack_outbox
      (id, customer_id, deployment_id, target_kind, target_version,
       target_digest, lifecycle_stage, payload_json, payload_digest, status,
       attempts, next_attempt_at, created_at, updated_at)
    VALUES ($1, $2, $3, 'entitlement', 1, $4, 'applied', '{}', $5,
      'pending', 0, $6, $6, $6)
  `, [
    `ack-legacy-${tenant.customerId}`,
    tenant.customerId,
    tenant.deploymentId,
    tenant.entitlementDigest,
    tenant.ackDigest,
    NOW,
  ]);
}

async function provePopulatedUpgradeRejectsAtomically() {
  const fixture = await provisionDatabase();
  let client;
  try {
    client = await connectAsOwner(fixture);
    await assertDirectNonSuperuserOwner(client, fixture);
    await migrateThrough(client, 12);
    const tenant = tenantFixture('a');
    await seedAppliedOnlyIntermediate(client, tenant);

    // Clear the tenant scope before migration. v13 must use its temporary
    // owner-only NO FORCE boundary to discover the hidden intermediate rows.
    await setTenant(client, '');
    await assert.rejects(
      applyMigration(client, MIGRATIONS.find(({ version }) => version === 13)),
      (error) => error && error.code === '55000'
        && /requires a pre-v11 empty state and re-enrollment/.test(error.message),
    );

    const { rows: versionRows } = await client.query(
      'SELECT version FROM schema_migrations WHERE version >= 11 ORDER BY version',
    );
    assert.deepStrictEqual(versionRows, [{ version: 11 }, { version: 12 }]);

    const { rows: security } = await client.query(`
      SELECT c.relname AS table_name,
             c.relrowsecurity AS enabled,
             c.relforcerowsecurity AS forced
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public'
        AND c.relname = ANY($1::text[])
      ORDER BY c.relname
    `, [['connected_ack_outbox', 'connected_entitlement_state']]);
    assert.deepStrictEqual(security, [
      { table_name: 'connected_ack_outbox', enabled: true, forced: true },
      { table_name: 'connected_entitlement_state', enabled: true, forced: true },
    ]);

    const { rows: hiddenState } = await client.query(
      'SELECT customer_id FROM connected_entitlement_state',
    );
    const { rows: hiddenAcks } = await client.query(
      'SELECT customer_id FROM connected_ack_outbox',
    );
    assert.deepStrictEqual(hiddenState, []);
    assert.deepStrictEqual(hiddenAcks, []);

    await setTenant(client, tenant.customerId);
    const { rows: stateRows } = await client.query(`
      SELECT customer_id, deployment_id, entitlement_version
      FROM connected_entitlement_state
    `);
    const { rows: ackRows } = await client.query(`
      SELECT customer_id, deployment_id, lifecycle_stage, status, attempts
      FROM connected_ack_outbox
    `);
    assert.deepStrictEqual(stateRows, [{
      customer_id: tenant.customerId,
      deployment_id: tenant.deploymentId,
      entitlement_version: '1',
    }]);
    assert.deepStrictEqual(ackRows, [{
      customer_id: tenant.customerId,
      deployment_id: tenant.deploymentId,
      lifecycle_stage: 'applied',
      status: 'pending',
      attempts: 0,
    }]);

    const { rows: rolledBackColumns } = await client.query(`
      SELECT table_name, column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND ((table_name = 'connected_ack_outbox' AND column_name = 'failure_class')
          OR (table_name = 'audit' AND column_name = 'connected_entry_action'))
    `);
    assert.deepStrictEqual(rolledBackColumns, []);
    const { rows: rolledBackTables } = await client.query(`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name = ANY($1::text[])
    `, [[
      'connected_ack_health',
      'connected_ack_archive',
      'connected_ack_archive_mutations',
    ]]);
    assert.deepStrictEqual(rolledBackTables, []);
  } finally {
    if (client) await client.end().catch(() => {});
    await destroyDatabase(fixture);
  }
}

test('connected v11/v12 to v13 migration is atomic and tenant-safe for the direct Postgres owner', {
  skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set',
  timeout: 180_000,
}, async () => {
  await proveEmptyUpgradeAndFinalIsolation();
  await provePopulatedUpgradeRejectsAtomically();
});
