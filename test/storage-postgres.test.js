'use strict';
/**
 * Full db.js contract against a real Postgres via the sync worker bridge.
 * Runs when REDACTWALL_TEST_PG_URL points at a reachable Postgres superuser-ish
 * connection (a fresh database is created per run); skips cleanly otherwise.
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const ADMIN_URL = process.env.REDACTWALL_TEST_PG_URL || '';

async function createFreshDatabase() {
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  const name = 'redactwall_t_' + crypto.randomBytes(5).toString('hex');
  // Superusers bypass row-level security, so run the battery as the same kind
  // of unprivileged application role a production deployment would use.
  await admin.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'redactwall_app') THEN
        CREATE ROLE redactwall_app LOGIN;
      END IF;
    END $$;
  `);
  await admin.query(`CREATE DATABASE ${name} OWNER redactwall_app`);
  await admin.end();
  const url = new URL(ADMIN_URL);
  url.username = 'redactwall_app';
  url.pathname = '/' + name;
  return url.toString();
}

test('db.js contract holds on Postgres (migrations, RLS, immutability, chain)', { skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set' }, async () => {
  const databaseUrl = await createFreshDatabase();
  const output = execFileSync(process.execPath, [path.join(__dirname, 'support', 'pg-battery.js')], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      REDACTWALL_DB_DRIVER: 'postgres',
      REDACTWALL_DATABASE_URL: databaseUrl,
      REDACTWALL_SECRET: 'unit-secret-stable',
      REDACTWALL_DATA_KEY: 'unit-data-key-stable',
      ADMIN_PASSWORD: 'unit-pass',
    },
    encoding: 'utf8',
    timeout: 60000,
  });
  const results = JSON.parse(output);
  const failed = Object.entries(results).filter(([, r]) => !r.ok);
  assert.deepStrictEqual(failed, [], `battery steps failed: ${JSON.stringify(failed)}`);

  assert.strictEqual(results.driverKind.value, 'postgres');
  assert.deepStrictEqual(results.migrations.value.map((m) => m.version), [1, 2, 3]);
  assert.strictEqual(results.queryCrud.value.updatedStatus, 'approved');
  assert.strictEqual(results.queryCrud.value.risk, 42);
  assert.strictEqual(results.auditChain.value.ok, true);
  assert.ok(results.auditChain.value.count >= 2);
  assert.strictEqual(results.auditImmutable.value.blocked, true, 'audit UPDATE must be refused on Postgres');
  assert.deepStrictEqual(results.tenantScoping.value, { alphaOnly: true, betaOnly: true });
  assert.deepStrictEqual(results.rowLevelSecurity.value, {
    betaOnly: true,
    crossTenantInsertBlocked: true,
    allVisible: true,
  }, 'forced row-level security isolates tenants');
  assert.deepStrictEqual(results.transactionsNest.value, { rolledBack: true, chainOk: true });
  assert.deepStrictEqual(results.scimAndLifecycle.value, { inactive: true, revoked: true });
  assert.deepStrictEqual(results.deliveriesAndApps.value, { delivered: true, app: true });
  assert.deepStrictEqual(results.statsAndSeats.value, { total: true, seatUsers: true });
  assert.deepStrictEqual(results.mfaRecovery.value, { first: true, second: false, used: true });
});
