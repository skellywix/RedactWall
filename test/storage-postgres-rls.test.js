'use strict';
/**
 * Row-level-security verification for the tenant-scoping migration (v3) on a
 * real Postgres. Coverage is enumerated from the live catalog so a future
 * orgId-carrying table without an RLS policy FAILS instead of being skipped,
 * and isolation is exercised as a dedicated non-owner, non-BYPASSRLS role
 * (SET ROLE over the admin connection — CI's service user is superuser-ish
 * and would silently bypass RLS). The blank/unset tenant context is pinned as
 * the migration's documented fail-open "operator mode"; store-level RLS via
 * setTenantContext is covered by test/storage-postgres.test.js. Runs when
 * SENTINEL_TEST_PG_URL points at a reachable Postgres (a fresh database is
 * created per run); skips cleanly otherwise.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { openStore, runMigrations } = require('../server/storage');

const ADMIN_URL = process.env.SENTINEL_TEST_PG_URL || '';
// Every table carrying an "orgId" column must be listed here; the test
// cross-checks this list against information_schema AND pg_policies in both
// directions, so tenant-scoping a table without adding its policy fails.
const TENANT_SCOPED_TABLES = ['queries'];
const TENANT_GUC = 'promptwall.org_id';
const SEED_ROWS = [
  ['rls-a-1', 'org-a'],
  ['rls-a-2', 'org-a'],
  ['rls-b-1', 'org-b'],
  ['rls-none-1', null], // legacy row predating tenant scoping
];

async function createFreshDatabase(name) {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const url = new URL(ADMIN_URL);
  url.pathname = '/' + name;
  return url.toString();
}

/** Apply the real migration chain through the production store driver. */
function migrateThroughStore(databaseUrl) {
  const { driver, kind } = openStore({
    env: { SENTINEL_DB_DRIVER: 'postgres', SENTINEL_DATABASE_URL: databaseUrl },
  });
  try {
    const applied = runMigrations(driver, kind);
    assert.ok(applied.some((m) => m.name === 'tenant-scoping'), 'fresh database must apply migration 3');
  } finally {
    driver.close();
  }
}

async function fetchRlsCatalog(client) {
  const tables = await client.query(`
    SELECT table_name FROM information_schema.columns
    WHERE table_schema = 'public' AND column_name = 'orgId'`);
  const policies = await client.query(
    "SELECT tablename, policyname, qual, with_check FROM pg_policies WHERE schemaname = 'public'");
  const security = await client.query(`
    SELECT c.relname AS name, c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced,
           c.relowner::regrole::text AS owner
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'`);
  return {
    orgIdTables: tables.rows.map((row) => row.table_name).sort(),
    policies: policies.rows,
    security: new Map(security.rows.map((row) => [row.name, row])),
  };
}

function assertPolicyCoverage(catalog) {
  assert.deepStrictEqual(catalog.orgIdTables, TENANT_SCOPED_TABLES,
    'tables carrying an orgId column must exactly match the declared tenant-scoped set');
  const policyTables = [...new Set(catalog.policies.map((p) => p.tablename))].sort();
  assert.deepStrictEqual(policyTables, TENANT_SCOPED_TABLES,
    'every tenant-scoped table needs an RLS policy, and only scoped tables may have one');
  for (const table of TENANT_SCOPED_TABLES) {
    const sec = catalog.security.get(table);
    assert.strictEqual(sec.enabled, true, `${table}: row-level security must be ENABLED`);
    assert.strictEqual(sec.forced, true, `${table}: row-level security must be FORCED so the table owner is covered`);
    for (const policy of catalog.policies.filter((p) => p.tablename === table)) {
      assert.ok(policy.qual && policy.qual.includes(TENANT_GUC),
        `${table}/${policy.policyname}: USING must filter on ${TENANT_GUC}`);
      assert.ok(policy.with_check && policy.with_check.includes(TENANT_GUC),
        `${table}/${policy.policyname}: WITH CHECK must filter on ${TENANT_GUC}`);
    }
  }
}

async function createWorkerRole(client, role) {
  await client.query(`CREATE ROLE ${role} NOLOGIN`);
  await client.query(`GRANT ${role} TO CURRENT_USER`);
  await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${role}`);
  await client.query(`GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ${role}`);
}

async function assertRoleCannotBypassRls(client, catalog, role) {
  const { rows } = await client.query('SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1', [role]);
  assert.strictEqual(rows[0].rolsuper, false, 'worker role must not be a superuser');
  assert.strictEqual(rows[0].rolbypassrls, false, 'worker role must not have BYPASSRLS');
  for (const table of TENANT_SCOPED_TABLES) {
    assert.notStrictEqual(catalog.security.get(table).owner, role,
      `${table}: worker role must not own the table (only FORCE covers owners)`);
  }
}

async function seedTenantRows(client) {
  for (const [id, orgId] of SEED_ROWS) {
    await client.query(
      'INSERT INTO queries (id, "createdAt", status, "user", data, "orgId") VALUES ($1, $2, $3, $4, $5, $6)',
      [id, new Date().toISOString(), 'pending', 'rls-worker@example.test', '{}', orgId]);
  }
}

/** Mirrors pg-driver.js setTenantContext: session-scoped custom GUC. */
function setTenant(client, orgId) {
  return client.query('SELECT set_config($1, $2, false)', [TENANT_GUC, String(orgId || '')]);
}

async function assertTenantIsolation(client, { org, ownIds, foreignOrg, foreignId }) {
  await setTenant(client, org);
  const visible = await client.query('SELECT id, "orgId" FROM queries ORDER BY id');
  assert.deepStrictEqual(visible.rows.map((row) => row.id), ownIds,
    `${org}: SELECT must see exactly its own rows (foreign and legacy NULL-org rows invisible)`);
  assert.ok(visible.rows.every((row) => row.orgId === org), `${org}: no foreign orgId may leak`);
  const updated = await client.query('UPDATE queries SET status = $1 WHERE id = $2', ['tampered', foreignId]);
  assert.strictEqual(updated.rowCount, 0, `${org}: UPDATE must not reach ${foreignOrg} rows`);
  const deleted = await client.query('DELETE FROM queries WHERE id = $1', [foreignId]);
  assert.strictEqual(deleted.rowCount, 0, `${org}: DELETE must not reach ${foreignOrg} rows`);
  await assert.rejects(
    client.query('INSERT INTO queries (id, "createdAt", status, data, "orgId") VALUES ($1, $2, $3, $4, $5)',
      [`rls-cross-${org}`, new Date().toISOString(), 'pending', '{}', foreignOrg]),
    /row-level security/, `${org}: INSERT tagged for ${foreignOrg} must fail WITH CHECK`);
  await assert.rejects(
    client.query('UPDATE queries SET "orgId" = $1 WHERE id = $2', [foreignOrg, ownIds[0]]),
    /row-level security/, `${org}: re-tagging an own row to ${foreignOrg} must fail WITH CHECK`);
}

async function assertContextEdgeCases(client) {
  await setTenant(client, 'org-unknown');
  const unknown = await client.query('SELECT count(*)::int AS n FROM queries');
  assert.strictEqual(unknown.rows[0].n, 0, 'an unknown tenant context must see zero rows');
  await setTenant(client, '');
  const blank = await client.query('SELECT count(*)::int AS n FROM queries');
  assert.strictEqual(blank.rows[0].n, SEED_ROWS.length,
    'DOCUMENTED FAIL-OPEN: blank promptwall.org_id is operator mode and sees every tenant row; ' +
    'if this fails the policy went fail-closed — update this test and operator tooling together');
  await client.query('RESET promptwall.org_id');
  const unset = await client.query('SELECT count(*)::int AS n FROM queries');
  assert.strictEqual(unset.rows[0].n, SEED_ROWS.length,
    "DOCUMENTED FAIL-OPEN: an unset promptwall.org_id also sees every tenant row via COALESCE(..., '') = ''");
}

async function dropTestArtifacts(dbName, role) {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.query(`DROP ROLE IF EXISTS ${role}`);
  } finally {
    await admin.end();
  }
}

test('migration 3 row-level security isolates tenants for a non-owner role', { skip: !ADMIN_URL && 'SENTINEL_TEST_PG_URL not set' }, async () => {
  const suffix = crypto.randomBytes(5).toString('hex');
  const dbName = 'promptwall_rls_' + suffix;
  const workerRole = 'promptwall_rls_worker_' + suffix;
  const databaseUrl = await createFreshDatabase(dbName);
  try {
    migrateThroughStore(databaseUrl);
    const { Client } = require('pg');
    const client = new Client({ connectionString: databaseUrl });
    await client.connect();
    try {
      const catalog = await fetchRlsCatalog(client);
      assertPolicyCoverage(catalog);
      await createWorkerRole(client, workerRole);
      await assertRoleCannotBypassRls(client, catalog, workerRole);
      await seedTenantRows(client);
      await client.query(`SET ROLE ${workerRole}`);
      await assertTenantIsolation(client, { org: 'org-a', ownIds: ['rls-a-1', 'rls-a-2'], foreignOrg: 'org-b', foreignId: 'rls-b-1' });
      await assertTenantIsolation(client, { org: 'org-b', ownIds: ['rls-b-1'], foreignOrg: 'org-a', foreignId: 'rls-a-1' });
      await assertContextEdgeCases(client);
      await client.query('RESET ROLE');
    } finally {
      await client.end();
    }
  } finally {
    await dropTestArtifacts(dbName, workerRole);
  }
});
