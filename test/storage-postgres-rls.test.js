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
 * REDACTWALL_TEST_PG_URL points at a reachable Postgres (a fresh database is
 * created per run); skips cleanly otherwise.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { openStore, runMigrations } = require('../server/storage');

const ADMIN_URL = process.env.REDACTWALL_TEST_PG_URL || '';
// Every table carrying an "orgId" column must be listed here; the test
// cross-checks this list against information_schema AND pg_policies in both
// directions, so tenant-scoping a table without adding its policy fails.
const ADMINISTRATION_TABLES = [
  'admin_invitations',
  'admin_users',
  'license_renewal_requests',
  'license_seat_assignments',
];
const TENANT_SCOPED_TABLES = [
  ...ADMINISTRATION_TABLES,
  'ai_incidents',
  'ai_use_cases',
  'ingest_idempotency',
  'queries',
].sort();
const POLICY_SCOPED_TABLES = [...TENANT_SCOPED_TABLES, 'vendor_license_state'].sort();
const TENANT_GUC = 'redactwall.org_id';
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
    env: { REDACTWALL_DB_DRIVER: 'postgres', REDACTWALL_DATABASE_URL: databaseUrl },
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
  assert.deepStrictEqual(policyTables, POLICY_SCOPED_TABLES,
    'every tenant-scoped table needs an RLS policy, and only scoped tables may have one');
  for (const table of POLICY_SCOPED_TABLES) {
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
  for (const table of POLICY_SCOPED_TABLES) {
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

function administrationInsert(table, id, orgId) {
  const now = '2026-07-09T00:00:00.000Z';
  if (table === 'admin_users') {
    return {
      text: 'INSERT INTO admin_users (id, "orgId", "userName", "displayName", role, active, "createdAt", "updatedAt", data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      values: [id, orgId, `${id}@example.test`, id, 'auditor', 1, now, now, '{}'],
    };
  }
  if (table === 'admin_invitations') {
    return {
      text: 'INSERT INTO admin_invitations (id, "orgId", "userName", "tokenHash", status, "expiresAt", "acceptedAt", "createdAt", "updatedAt", data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      values: [id, orgId, `${id}@example.test`, `token-${id}`, 'pending', '2027-01-01T00:00:00.000Z', null, now, now, '{}'],
    };
  }
  if (table === 'license_seat_assignments') {
    return {
      text: 'INSERT INTO license_seat_assignments (id, "orgId", "userKey", "userName", status, reason, actor, "createdAt", "updatedAt", data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      values: [id, orgId, `${id}@example.test`, `${id}@example.test`, 'assigned', 'RLS fixture', 'rls-test', now, now, '{}'],
    };
  }
  if (table === 'license_renewal_requests') {
    return {
      text: 'INSERT INTO license_renewal_requests (id, "orgId", status, "requestedSeats", "contactEmail", "createdAt", "updatedAt", data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      values: [id, orgId, 'requested', 25, `${id}@example.test`, now, now, '{}'],
    };
  }
  throw new Error(`unsupported administration table: ${table}`);
}

function insertAdministrationRow(client, table, id, orgId) {
  const query = administrationInsert(table, id, orgId);
  return client.query(query.text, query.values);
}

async function seedAdministrationTenantRows(client) {
  for (const table of ADMINISTRATION_TABLES) {
    for (const org of ['org-a', 'org-b']) {
      await insertAdministrationRow(client, table, `seed-${table}-${org}`, org);
    }
  }
}

async function seedVendorTenantRows(client) {
  for (const [index, org] of ['org-a', 'org-b'].entries()) {
    await client.query(
      'INSERT INTO vendor_license_state ("customerId", "issuedAt", "contactAt", status) VALUES ($1,$2,$3,$4)',
      [org, 1000 + index, 1000 + index, index ? 'revoked' : 'active'],
    );
  }
}

async function seedIdempotencyTenantRows(client) {
  const sharedKey = 'a'.repeat(64);
  const now = new Date().toISOString();
  await client.query(
    'INSERT INTO audit (id, ts, action, "queryId", actor, "prevHash", hash, entry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8),($9,$2,$3,$10,$5,$6,$11,$8)',
    ['idem-audit-a', now, 'RLS_FIXTURE', 'rls-a-1', 'rls-test', '0'.repeat(64), '1'.repeat(64), '{}',
      'idem-audit-b', 'rls-b-1', '2'.repeat(64)],
  );
  await client.query(
    'INSERT INTO ingest_idempotency (scope, "orgId", "keyHash", "queryId", "auditId", "replaySnapshot", "createdAt") '
      + 'VALUES ($1,$2,$3,$4,$5,$6,$7),($1,$8,$3,$9,$10,$6,$7)',
    ['native_handoff_v1', 'org-a', sharedKey, 'rls-a-1', 'idem-audit-a', '{}', now,
      'org-b', 'rls-b-1', 'idem-audit-b'],
  );
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

async function assertAdministrationTenantIsolation(client, org) {
  const foreignOrg = org === 'org-a' ? 'org-b' : 'org-a';
  await setTenant(client, org);
  for (const table of ADMINISTRATION_TABLES) {
    const ownId = `seed-${table}-${org}`;
    const foreignId = `seed-${table}-${foreignOrg}`;
    const visible = await client.query(`SELECT id, "orgId" FROM ${table} ORDER BY id`);
    assert.deepStrictEqual(visible.rows.map((row) => row.id), [ownId],
      `${table}/${org}: SELECT must expose only the current tenant row`);

    const foreignUpdate = await client.query(`UPDATE ${table} SET data = $1 WHERE id = $2`, ['{"blocked":true}', foreignId]);
    assert.strictEqual(foreignUpdate.rowCount, 0, `${table}/${org}: UPDATE must not reach a foreign row`);
    const foreignDelete = await client.query(`DELETE FROM ${table} WHERE id = $1`, [foreignId]);
    assert.strictEqual(foreignDelete.rowCount, 0, `${table}/${org}: DELETE must not reach a foreign row`);

    await assert.rejects(
      insertAdministrationRow(client, table, `cross-${table}-${org}`, foreignOrg),
      /row-level security/,
      `${table}/${org}: INSERT tagged for ${foreignOrg} must fail WITH CHECK`,
    );

    const crudId = `crud-${table}-${org}`;
    const inserted = await insertAdministrationRow(client, table, crudId, org);
    assert.strictEqual(inserted.rowCount, 1, `${table}/${org}: own-tenant INSERT must succeed`);
    const updated = await client.query(`UPDATE ${table} SET data = $1 WHERE id = $2`, ['{"updated":true}', crudId]);
    assert.strictEqual(updated.rowCount, 1, `${table}/${org}: own-tenant UPDATE must succeed`);
    const deleted = await client.query(`DELETE FROM ${table} WHERE id = $1`, [crudId]);
    assert.strictEqual(deleted.rowCount, 1, `${table}/${org}: own-tenant DELETE must succeed`);
  }
}

async function assertVendorTenantIsolation(client, org) {
  const foreignOrg = org === 'org-a' ? 'org-b' : 'org-a';
  await setTenant(client, org);
  const visible = await client.query('SELECT "customerId", status FROM vendor_license_state');
  assert.deepStrictEqual(visible.rows.map((row) => row.customerId), [org],
    `vendor_license_state/${org}: SELECT must expose only the current customer`);
  const foreignUpdate = await client.query(
    'UPDATE vendor_license_state SET status = $1 WHERE "customerId" = $2', ['active', foreignOrg],
  );
  assert.strictEqual(foreignUpdate.rowCount, 0, `${org}: foreign vendor status cannot be changed`);
  const foreignDelete = await client.query(
    'DELETE FROM vendor_license_state WHERE "customerId" = $1', [foreignOrg],
  );
  assert.strictEqual(foreignDelete.rowCount, 0, `${org}: foreign vendor state cannot be deleted`);
  await assert.rejects(
    client.query(
      'INSERT INTO vendor_license_state ("customerId", "issuedAt", "contactAt", status) VALUES ($1,$2,$3,$4)',
      [`${foreignOrg}-cross`, 2000, 2000, 'active'],
    ),
    /row-level security/,
    `${org}: a foreign customer row must fail WITH CHECK`,
  );
  const ownUpdate = await client.query(
    'UPDATE vendor_license_state SET "contactAt" = "contactAt" + 1 WHERE "customerId" = $1', [org],
  );
  assert.strictEqual(ownUpdate.rowCount, 1, `${org}: own vendor row UPDATE must succeed`);
  const ownDelete = await client.query(
    'DELETE FROM vendor_license_state WHERE "customerId" = $1', [org],
  );
  assert.strictEqual(ownDelete.rowCount, 1, `${org}: own vendor row DELETE must succeed`);
  const ownInsert = await client.query(
    'INSERT INTO vendor_license_state ("customerId", "issuedAt", "contactAt", status) VALUES ($1,$2,$3,$4)',
    [org, 3000, 3000, 'revoked'],
  );
  assert.strictEqual(ownInsert.rowCount, 1, `${org}: own vendor row INSERT must succeed`);
}

async function assertIdempotencyTenantIsolation(client, org) {
  const foreignOrg = org === 'org-a' ? 'org-b' : 'org-a';
  const ownQuery = org === 'org-a' ? 'rls-a-1' : 'rls-b-1';
  const foreignQuery = org === 'org-a' ? 'rls-b-1' : 'rls-a-1';
  await setTenant(client, org);
  const visible = await client.query(
    'SELECT "orgId", "queryId", "keyHash" FROM ingest_idempotency ORDER BY "queryId"',
  );
  assert.deepStrictEqual(visible.rows.map((row) => [row.orgId, row.queryId]), [[org, ownQuery]],
    `ingest_idempotency/${org}: SELECT must expose only the current tenant mapping`);
  assert.strictEqual(visible.rows[0].keyHash, 'a'.repeat(64),
    'the same opaque key may exist independently in each tenant scope');
  const foreignUpdate = await client.query(
    'UPDATE ingest_idempotency SET "createdAt" = $1 WHERE "queryId" = $2',
    [new Date().toISOString(), foreignQuery],
  );
  assert.strictEqual(foreignUpdate.rowCount, 0, `${org}: foreign idempotency mapping cannot be updated`);
  const foreignDelete = await client.query(
    'DELETE FROM ingest_idempotency WHERE "queryId" = $1', [foreignQuery],
  );
  assert.strictEqual(foreignDelete.rowCount, 0, `${org}: foreign idempotency mapping cannot be deleted`);
  const crossAuditId = `idem-audit-cross-${org}`;
  await client.query(
    'INSERT INTO audit (id, ts, action, "queryId", actor, "prevHash", hash, entry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [crossAuditId, new Date().toISOString(), 'RLS_FIXTURE', foreignQuery, 'rls-test', '0'.repeat(64),
      (org === 'org-a' ? '5' : '6').repeat(64), '{}'],
  );
  await assert.rejects(
    client.query(
      'INSERT INTO ingest_idempotency (scope, "orgId", "keyHash", "queryId", "auditId", "replaySnapshot", "createdAt") VALUES ($1,$2,$3,$4,$5,$6,$7)',
      ['native_handoff_v1', foreignOrg, 'b'.repeat(64), foreignQuery, crossAuditId, '{}', new Date().toISOString()],
    ),
    /row-level security/,
    `${org}: a foreign idempotency mapping must fail WITH CHECK`,
  );

  const queryId = `idem-crud-${org}`;
  await client.query(
    'INSERT INTO queries (id, "createdAt", status, data, "orgId") VALUES ($1,$2,$3,$4,$5)',
    [queryId, new Date().toISOString(), 'allowed', '{}', org],
  );
  const auditId = `idem-audit-crud-${org}`;
  await client.query(
    'INSERT INTO audit (id, ts, action, "queryId", actor, "prevHash", hash, entry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [auditId, new Date().toISOString(), 'RLS_FIXTURE', queryId, 'rls-test', '0'.repeat(64),
      (org === 'org-a' ? '3' : '4').repeat(64), '{}'],
  );
  const inserted = await client.query(
    'INSERT INTO ingest_idempotency (scope, "orgId", "keyHash", "queryId", "auditId", "replaySnapshot", "createdAt") VALUES ($1,$2,$3,$4,$5,$6,$7)',
    ['native_handoff_v1', org, 'c'.repeat(64), queryId, auditId, '{}', new Date().toISOString()],
  );
  assert.strictEqual(inserted.rowCount, 1, `${org}: own idempotency mapping INSERT must succeed`);
  const updated = await client.query(
    'UPDATE ingest_idempotency SET "createdAt" = $1 WHERE "queryId" = $2',
    [new Date(Date.now() + 1000).toISOString(), queryId],
  );
  assert.strictEqual(updated.rowCount, 1, `${org}: own idempotency mapping UPDATE must succeed`);
  const deleted = await client.query('DELETE FROM ingest_idempotency WHERE "queryId" = $1', [queryId]);
  assert.strictEqual(deleted.rowCount, 1, `${org}: own idempotency mapping DELETE must succeed`);
  await client.query('DELETE FROM queries WHERE id = $1', [queryId]);
}

async function assertContextEdgeCases(client) {
  await setTenant(client, 'org-unknown');
  const unknown = await client.query('SELECT count(*)::int AS n FROM queries');
  assert.strictEqual(unknown.rows[0].n, 0, 'an unknown tenant context must see zero rows');
  await setTenant(client, '');
  const blank = await client.query('SELECT count(*)::int AS n FROM queries');
  assert.strictEqual(blank.rows[0].n, SEED_ROWS.length,
    'DOCUMENTED FAIL-OPEN: blank redactwall.org_id is operator mode and sees every tenant row; ' +
    'if this fails the policy went fail-closed — update this test and operator tooling together');
  await client.query('RESET redactwall.org_id');
  const unset = await client.query('SELECT count(*)::int AS n FROM queries');
  assert.strictEqual(unset.rows[0].n, SEED_ROWS.length,
    "DOCUMENTED FAIL-OPEN: an unset redactwall.org_id also sees every tenant row via COALESCE(..., '') = ''");
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

test('migration 3 row-level security isolates tenants for a non-owner role', { skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set' }, async () => {
  const suffix = crypto.randomBytes(5).toString('hex');
  const dbName = 'redactwall_rls_' + suffix;
  const workerRole = 'redactwall_rls_worker_' + suffix;
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
      await seedAdministrationTenantRows(client);
      await seedVendorTenantRows(client);
      await seedIdempotencyTenantRows(client);
      await client.query(`SET ROLE ${workerRole}`);
      await assertTenantIsolation(client, { org: 'org-a', ownIds: ['rls-a-1', 'rls-a-2'], foreignOrg: 'org-b', foreignId: 'rls-b-1' });
      await assertAdministrationTenantIsolation(client, 'org-a');
      await assertVendorTenantIsolation(client, 'org-a');
      await assertIdempotencyTenantIsolation(client, 'org-a');
      await assertTenantIsolation(client, { org: 'org-b', ownIds: ['rls-b-1'], foreignOrg: 'org-a', foreignId: 'rls-a-1' });
      await assertAdministrationTenantIsolation(client, 'org-b');
      await assertVendorTenantIsolation(client, 'org-b');
      await assertIdempotencyTenantIsolation(client, 'org-b');
      await assertContextEdgeCases(client);
      await client.query('RESET ROLE');
    } finally {
      await client.end();
    }
  } finally {
    await dropTestArtifacts(dbName, workerRole);
  }
});
