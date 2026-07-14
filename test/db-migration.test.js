'use strict';
/** Legacy JSON store migration should be covered without touching repo data. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const serverRoot = path.join(root, 'server');

function copyDbRuntime(tempRoot) {
  const tempServer = path.join(tempRoot, 'server');
  fs.mkdirSync(tempServer, { recursive: true });
  for (const file of [
    'db.js', 'env.js', 'audit-integrity.js', 'audit-anchor.js', 'file-mutation-lock.js',
    'tenant.js', 'postgres-url.js', 'private-path.js', 'crypto.js', 'detector.js',
    'connected-entitlement-store.js', 'connected-entitlement-state.js',
    'connected-online-registry-store.js', 'connected-online-registry-state.js',
    'connected-online-verdict.js',
    'connected-heartbeat-apply-store.js', 'connected-acknowledged-authority-store.js',
    'connected-license-config.js',
    'customer-diagnostic-storage.js',
    'system-boot-clock.js',
    'deployment-identity.js', 'vendor-control-protocol.js', 'vendor-signed-artifact.js',
  ]) {
    fs.copyFileSync(path.join(serverRoot, file), path.join(tempServer, file));
  }
  fs.cpSync(path.join(serverRoot, 'storage'), path.join(tempServer, 'storage'), { recursive: true });
  fs.cpSync(path.join(root, 'detection-engine'), path.join(tempRoot, 'detection-engine'), { recursive: true });
  return path.join(tempServer, 'db.js');
}

function writeLegacyStore(tempRoot) {
  const dataDir = path.join(tempRoot, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(path.join(dataDir, 'queries.json'), JSON.stringify([
    {
      id: 'legacy-q-1',
      createdAt: '2026-01-01T00:00:00.000Z',
      status: 'pending',
      user: 'analyst@example.test',
      redactedPrompt: 'Member [US_SSN]',
      findings: [{ type: 'US_SSN', masked: '***-**-9043' }],
      _rawPrompt: 'Member synthetic SSN 123-45-6789',
      _tokenVault: { '[[US_SSN_1]]': '123-45-6789' },
    },
    {
      id: 'legacy-q-2',
      createdAt: '2026-01-02T00:00:00.000Z',
      status: 'approved',
      user: 'admin@example.test',
      redactedPrompt: 'Reviewed contract terms',
    },
  ], null, 2));
  fs.writeFileSync(path.join(dataDir, 'audit.json'), JSON.stringify([
    {
      ts: '2026-01-01T00:00:01.000Z',
      action: 'BLOCKED',
      queryId: 'legacy-q-1',
      actor: 'sensor',
      detail: 'structured pii detected for synthetic SSN 123-45-6789',
    },
    {
      ts: '2026-01-02T00:00:01.000Z',
      action: 'APPROVED',
      queryId: 'legacy-q-2',
      actor: 'admin',
      detail: 'approved in legacy store',
    },
  ], null, 2));
}

function runCopiedDb(tempRoot, envOverrides = {}) {
  const dbPath = copyDbRuntime(tempRoot);
  const script = `
    const fs = require('node:fs');
    const path = require('node:path');
    const db = require(process.argv[1]);
    const dataDir = path.join(path.dirname(process.argv[1]), '..', 'data');
    const snapshot = {
      dbPath: db._dbPath,
      queries: db.listQueries({ all: true }),
      audit: db.listAudit(20),
      integrity: db.verifyAuditChain(),
      files: {
        sqlite: fs.existsSync(path.join(dataDir, 'redactwall.db')),
        queriesJson: fs.existsSync(path.join(dataDir, 'queries.json')),
        auditJson: fs.existsSync(path.join(dataDir, 'audit.json')),
        queriesMigrated: fs.existsSync(path.join(dataDir, 'queries.json.migrated')),
        auditMigrated: fs.existsSync(path.join(dataDir, 'audit.json.migrated')),
      },
    };
    db._db.close();
    process.stdout.write(JSON.stringify(snapshot));
  `;
  const child = spawnSync(process.execPath, ['-e', script, dbPath], {
    cwd: tempRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_PATH: path.join(root, 'node_modules'),
      REDACTWALL_ENV_PATH: path.join(tempRoot, 'missing.env'),
      REDACTWALL_DB_PATH: '',
      REDACTWALL_DATA_KEY: '',
      REDACTWALL_SECRET: '',
      ...envOverrides,
    },
  });
  assert.strictEqual(child.status, 0, child.stderr || child.stdout);
  return JSON.parse(child.stdout);
}

test('default SQLite store imports legacy JSON once and preserves audit integrity', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-db-migration-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  writeLegacyStore(tempRoot);

  const snapshot = runCopiedDb(tempRoot);

  assert.deepStrictEqual(snapshot.queries.map((q) => q.id).sort(), ['legacy-q-1', 'legacy-q-2']);
  assert.strictEqual(snapshot.queries.find((q) => q.id === 'legacy-q-1').findings[0].type, 'US_SSN');
  assert.strictEqual(snapshot.queries.find((q) => q.id === 'legacy-q-1')._rawPrompt, undefined);
  assert.strictEqual(snapshot.queries.find((q) => q.id === 'legacy-q-1')._tokenVault, undefined);
  assert.deepStrictEqual(snapshot.queries.find((q) => q.id === 'legacy-q-1').legacySensitiveFieldsDiscarded, ['_rawPrompt', '_tokenVault']);
  assert.strictEqual(snapshot.integrity.ok, true);
  assert.ok(snapshot.audit.some((entry) => entry.action === 'BLOCKED' && entry.queryId === 'legacy-q-1'));
  assert.ok(snapshot.audit.some((entry) => entry.action === 'APPROVED' && entry.queryId === 'legacy-q-2'));
  assert.ok(snapshot.audit.some((entry) => entry.action === 'STORE_MIGRATED'));
  assert.ok(snapshot.audit.every((entry) => !String(entry.detail || '').includes('123-45-6789')));
  assert.ok(snapshot.audit.find((entry) => entry.queryId === 'legacy-q-1').contentHash);
  assert.deepStrictEqual(snapshot.files, {
    sqlite: true,
    queriesJson: false,
    auditJson: false,
    queriesMigrated: false,
    auditMigrated: false,
  });
});

test('legacy sensitive fields are sealed when a stable data key is available', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-db-migration-sealed-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  writeLegacyStore(tempRoot);
  const snapshot = runCopiedDb(tempRoot, { REDACTWALL_DATA_KEY: 'migration-test-key-with-at-least-thirty-two-characters' });
  const query = snapshot.queries.find((item) => item.id === 'legacy-q-1');
  assert.match(query._rawPrompt, /^enc:v1:/);
  assert.match(query._tokenVault, /^enc:v1:/);
  assert.ok(!JSON.stringify(query).includes('123-45-6789'));
  assert.ok(snapshot.audit.every((entry) => !String(entry.detail || '').includes('123-45-6789')));
  assert.strictEqual(snapshot.integrity.ok, true);
  assert.deepStrictEqual(snapshot.files, {
    sqlite: true,
    queriesJson: false,
    auditJson: false,
    queriesMigrated: false,
    auditMigrated: false,
  });
});

test('explicit SQLite path disables legacy JSON auto-migration', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-db-explicit-path-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  writeLegacyStore(tempRoot);
  const explicitDb = path.join(tempRoot, 'custom', 'redactwall.db');

  const snapshot = runCopiedDb(tempRoot, { REDACTWALL_DB_PATH: explicitDb });

  assert.strictEqual(snapshot.dbPath, explicitDb);
  assert.deepStrictEqual(snapshot.queries, []);
  assert.deepStrictEqual(snapshot.audit, []);
  assert.deepStrictEqual(snapshot.integrity, { ok: true, count: 0 });
  assert.deepStrictEqual(snapshot.files, {
    sqlite: false,
    queriesJson: true,
    auditJson: true,
    queriesMigrated: false,
    auditMigrated: false,
  });
});

test('injectable JSON migration skips non-empty stores and re-anchors imported audit rows', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-db-migration-internal-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const dataDir = path.join(tempRoot, 'legacy');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(path.join(dataDir, 'queries.json'), JSON.stringify([
    null,
    { createdAt: '2026-01-01T00:00:00.000Z' },
    { id: 'legacy-q-1', status: 'approved', user: 'analyst@example.test', redactedPrompt: '[US_SSN]' },
  ]));
  fs.writeFileSync(path.join(dataDir, 'audit.json'), JSON.stringify([
    { ts: '2026-01-02T00:00:00.000Z', action: 'APPROVED', queryId: 'legacy-q-1', actor: 'admin', detail: 'later' },
    { ts: '2026-01-01T00:00:00.000Z', action: 'BLOCKED', queryId: 'legacy-q-1', actor: 'sensor', detail: 'earlier' },
  ]));

  const dbModulePath = require.resolve('../server/db');
  const previousDbPath = process.env.REDACTWALL_DB_PATH;
  delete require.cache[dbModulePath];
  process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'current.db');
  const db = require('../server/db');
  try {
    let skippedTransaction = false;
    db._internal.migrateFromJson({
      env: {},
      db: {
        prepare: () => ({ get: () => ({ n: 1 }) }),
        transaction: () => { skippedTransaction = true; },
      },
    });
    assert.strictEqual(skippedTransaction, false);

    const inserted = [];
    const audit = [];
    const removals = [];
    db._internal.migrateFromJson({
      env: {},
      dataDir,
      db: {
        prepare: () => ({ get: () => ({ n: 0 }) }),
        transaction: (fn) => () => fn(),
      },
      qInsert: { run: (row) => inserted.push(row) },
      appendAudit: (entry) => audit.push(entry),
      fs: {
        ...fs,
        rmSync: (file) => {
          removals.push(path.basename(file));
        },
      },
    });

    assert.deepStrictEqual(inserted.map((row) => row.id), ['legacy-q-1']);
    assert.strictEqual(inserted[0].status, 'approved');
    assert.deepStrictEqual(audit.map((entry) => entry.action), ['BLOCKED', 'APPROVED', 'LEGACY_QUERY_IMPORTED', 'STORE_MIGRATED']);
    assert.match(audit[3].detail, /imported 1 queries, 2 audit events/);
    assert.deepStrictEqual(removals, ['queries.json', 'audit.json']);
  } finally {
    db._db.close();
    delete require.cache[dbModulePath];
    if (previousDbPath === undefined) delete process.env.REDACTWALL_DB_PATH;
    else process.env.REDACTWALL_DB_PATH = previousDbPath;
  }
});

test('runMigrations heals stores stamped at baseline without its newer tables', (t) => {
  const Database = require('better-sqlite3');
  const storage = require('../server/storage');
  const d = new Database(':memory:');
  t.after(() => d.close());
  // Old-lineage store: core tables only, then a blind v1-v3 stamp (the
  // pre-2026-07 upgrade bug) leaving newer baseline tables missing.
  d.exec(`
    CREATE TABLE queries (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, createdAt TEXT NOT NULL, status TEXT NOT NULL, user TEXT, data TEXT NOT NULL, orgId TEXT);
    CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, ts TEXT NOT NULL, action TEXT, queryId TEXT, actor TEXT, prevHash TEXT NOT NULL, hash TEXT NOT NULL, entry TEXT NOT NULL);
    CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, appliedAt TEXT NOT NULL);
    INSERT INTO schema_migrations VALUES (1, 'baseline', '2026-07-05T00:00:00.000Z'), (2, 'audit-append-only', '2026-07-05T00:00:00.000Z'), (3, 'tenant-scoping', '2026-07-05T00:00:00.000Z');
    INSERT INTO queries (id, createdAt, status, user, data) VALUES ('q1', '2026-07-01T00:00:00.000Z', 'pending', 'a@example.test', '{}');
  `);

  const results = storage.runMigrations(d, 'sqlite');

  assert.ok(results.some((r) => String(r.name).startsWith('baseline-heal:')), 'heal step reported');
  const hasTable = d.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?");
  for (const table of ['identity_revocations', 'mfa_recovery_used', 'ai_apps', 'deliveries', 'detector_feedback']) {
    assert.ok(hasTable.get(table), `${table} healed into place`);
  }
  assert.strictEqual(d.prepare('SELECT COUNT(*) AS n FROM queries').get().n, 1, 'existing rows untouched');
  assert.deepStrictEqual(storage.runMigrations(d, 'sqlite'), [], 'second run is a no-op');
});

test('migration train reaches connected ACK, diagnostic, and acknowledged-authority schemas', (t) => {
  const Database = require('better-sqlite3');
  const storage = require('../server/storage');
  const d = new Database(':memory:');
  t.after(() => d.close());

  assert.deepStrictEqual(
    storage.MIGRATIONS.map(({ version }) => version),
    Array.from({ length: 16 }, (_value, index) => index + 1),
  );
  storage.runMigrations(d, 'sqlite');
  const ackSchema = d.prepare(`SELECT sql FROM sqlite_master
    WHERE type = 'table' AND name = 'connected_ack_outbox'`).get().sql;
  assert.match(ackSchema, /lifecycle_stage IN \('delivered', 'applied'\)/);
  assert.ok(d.prepare(`SELECT name FROM pragma_table_xinfo('audit')
    WHERE name = 'connected_entry_action'`).get());
  assert.ok(d.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'table' AND name = 'connected_ack_health'`).get());
  assert.ok(d.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'table' AND name = 'connected_ack_archive'`).get());
  assert.ok(d.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'table' AND name = 'connected_ack_archive_mutations'`).get());
  assert.deepStrictEqual(d.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'trigger' AND (name LIKE 'connected_ack_archive_no_%'
      OR name LIKE 'connected_ack_archive_record_%'
      OR name LIKE 'connected_ack_archive_mutations_no_%')
    ORDER BY name`).all().map((row) => row.name), [
    'connected_ack_archive_mutations_no_replace',
    'connected_ack_archive_mutations_no_update',
    'connected_ack_archive_no_update',
    'connected_ack_archive_record_delete',
    'connected_ack_archive_record_insert',
    'connected_ack_archive_record_update',
  ]);
  const plan = d.prepare(`EXPLAIN QUERY PLAN
    SELECT scope_seq, event_seq FROM connected_ack_archive_mutations
    WHERE customer_id = ? AND deployment_id = ?
    ORDER BY scope_seq DESC LIMIT 1`).all('customer', `dep_${'a'.repeat(32)}`);
  assert.ok(plan.some((row) => /idx_connected_ack_archive_mutation_scope/.test(row.detail)));
  for (const table of [
    'customer_diagnostic_outbox',
    'customer_diagnostic_time_high_water',
    'customer_diagnostic_audit',
    'customer_diagnostic_checkpoint',
    'connected_acknowledged_authority_state',
    'connected_authority_pair_lineage',
    'connected_authority_pair_deletions',
  ]) assert.ok(d.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`).get(table));
  assert.ok(d.prepare(`SELECT name FROM pragma_table_xinfo('audit')
    WHERE name = 'diagnostic_checkpoint_ref'`).get());
  assert.ok(d.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'index' AND name = 'idx_audit_diagnostic_checkpoint'`).get());
  assert.deepStrictEqual(d.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'trigger' AND name LIKE 'connected_authority_pair_%'
    ORDER BY name`).all().map((row) => row.name), [
    'connected_authority_pair_deletions_no_delete',
    'connected_authority_pair_deletions_no_update',
    'connected_authority_pair_no_update',
    'connected_authority_pair_record_delete',
  ]);
  const pairPlan = d.prepare(`EXPLAIN QUERY PLAN SELECT pair_digest
    FROM connected_authority_pair_lineage
    WHERE customer_id = ? AND deployment_id = ?
      AND applied_ack_id = ? AND applied_ack_payload_digest = ?`).all(
    'customer', `dep_${'a'.repeat(32)}`, 'ack', 'f'.repeat(64),
  );
  assert.ok(pairPlan.some((row) => /USING (?:COVERING )?INDEX/.test(row.detail)));
  const pairSchema = d.prepare(`SELECT sql FROM sqlite_master
    WHERE type = 'table' AND name = 'connected_authority_pair_lineage'`).get().sql;
  assert.match(pairSchema, /transition_kind IN \('entitlement_release', 'registry_only'\)/);
  assert.match(pairSchema, /length\(CAST\(delivered_ack_id AS BLOB\)\) BETWEEN 1 AND 256/);
  assert.match(pairSchema, /length\(CAST\(applied_ack_id AS BLOB\)\) BETWEEN 1 AND 256/);
  assert.doesNotMatch(
    pairSchema,
    /UNIQUE \(customer_id, deployment_id, applied_ack_id, applied_ack_payload_digest\)/,
  );
  const deletionSchema = d.prepare(`SELECT sql FROM sqlite_master
    WHERE type = 'table' AND name = 'connected_authority_pair_deletions'`).get().sql;
  assert.match(deletionSchema, /event_version\s+INTEGER NOT NULL CHECK \(event_version = 1\)/);
  assert.match(deletionSchema, /transition_kind IN \('entitlement_release', 'registry_only'\)/);
  assert.match(deletionSchema, /applied_ack_payload_digest TEXT NOT NULL CHECK/);
  assert.match(deletionSchema, /length\(applied_ack_id\) BETWEEN 1 AND 256/);
  const authoritySchema = d.prepare(`SELECT sql FROM sqlite_master
    WHERE type = 'table' AND name = 'connected_acknowledged_authority_state'`).get().sql;
  assert.match(authoritySchema, /deletion_digest\s+TEXT NOT NULL CHECK/);
  assert.match(authoritySchema, /CHECK \(deletion_count = history_count\)/);
});

test('Postgres v16 diagnostic checkpoint forces tenant RLS and indexes main audit binding', () => {
  const sql = require('../server/storage/migrations').MIGRATIONS
    .find(({ version }) => version === 16).postgres;
  assert.match(sql, /CREATE TABLE public\.customer_diagnostic_checkpoint/);
  assert.match(sql, /ALTER TABLE public\.customer_diagnostic_checkpoint ENABLE ROW LEVEL SECURITY/);
  assert.match(sql, /ALTER TABLE public\.customer_diagnostic_checkpoint FORCE ROW LEVEL SECURITY/);
  assert.match(sql, /CREATE POLICY customer_diagnostic_checkpoint_tenant_isolation/);
  assert.match(sql, /customer_id = current_setting\('redactwall\.org_id', true\)/);
  assert.match(sql, /GENERATED ALWAYS AS \(\(entry::jsonb ->> 'diagnosticCheckpointRef'\)\) STORED/);
  assert.match(sql, /CREATE INDEX IF NOT EXISTS idx_audit_diagnostic_checkpoint/);
  assert.match(sql, /WHERE diagnostic_checkpoint_ref IS NOT NULL/);
});

test('v15 upgrade never synthesizes acknowledged authority from populated connected state', (t) => {
  const Database = require('better-sqlite3');
  const storage = require('../server/storage');
  const d = new Database(':memory:');
  t.after(() => d.close());
  d.pragma('foreign_keys = ON');
  d.exec(`
    CREATE TABLE connected_entitlement_state (
      customer_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
      PRIMARY KEY (customer_id, deployment_id)
    );
    CREATE TABLE connected_online_registry_state (
      customer_id TEXT NOT NULL, deployment_id TEXT NOT NULL,
      PRIMARY KEY (customer_id, deployment_id)
    );
    INSERT INTO connected_entitlement_state VALUES
      ('customer_upgrade', 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    INSERT INTO connected_online_registry_state VALUES
      ('customer_upgrade', 'dep_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  `);

  d.exec(storage.MIGRATIONS.find(({ version }) => version === 15).sqlite);

  assert.equal(d.prepare(
    'SELECT COUNT(*) AS n FROM connected_acknowledged_authority_state',
  ).get().n, 0);
  assert.equal(d.prepare(
    'SELECT COUNT(*) AS n FROM connected_authority_pair_lineage',
  ).get().n, 0);
});

test('Postgres archive mutation functions pin their namespace and never resolve through pg_temp', () => {
  const sql = require('../server/storage/migrations').MIGRATIONS
    .find(({ version }) => version === 13).postgres;
  const recordFunction = sql.match(/CREATE OR REPLACE FUNCTION public\.record_connected_ack_archive_mutation\(\)[\s\S]*?\$connected_ack_archive_record\$;/)?.[0] || '';
  assert.match(recordFunction, /SET search_path = pg_catalog/);
  assert.match(recordFunction, /INSERT INTO public\.connected_ack_archive_mutations/g);
  assert.match(recordFunction, /FROM public\.connected_ack_archive_mutations/g);
  assert.doesNotMatch(recordFunction, /(?:INSERT INTO|FROM) connected_ack_archive_mutations/);
});

test('Postgres v15 acknowledged-authority tables force tenant RLS and pin trigger namespaces', () => {
  const sql = require('../server/storage/migrations').MIGRATIONS
    .find(({ version }) => version === 15).postgres;
  const policies = [
    ['connected_authority_pair_lineage', 'connected_authority_pair_tenant_isolation'],
    ['connected_authority_pair_deletions', 'connected_authority_pair_deletion_tenant_isolation'],
    ['connected_acknowledged_authority_state', 'connected_acknowledged_authority_tenant_isolation'],
  ];
  assert.match(sql, /transition_kind IN \('entitlement_release', 'registry_only'\)/);
  assert.match(sql, /event_version\s+SMALLINT NOT NULL CHECK \(event_version = 1\)/);
  assert.match(sql, /applied_ack_payload_digest TEXT NOT NULL CHECK/);
  assert.match(sql, /octet_length\(delivered_ack_id\) BETWEEN 1 AND 256/);
  assert.match(sql, /octet_length\(applied_ack_id\) BETWEEN 1 AND 256/);
  assert.match(sql, /deletion_digest\s+TEXT NOT NULL CHECK/);
  assert.match(sql, /CHECK \(deletion_count = history_count\)/);
  assert.doesNotMatch(
    sql,
    /UNIQUE \(customer_id, deployment_id, applied_ack_id, applied_ack_payload_digest\)/,
  );
  for (const [table, policy] of policies) {
    assert.ok(sql.includes(`ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;`));
    assert.ok(sql.includes(`ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY;`));
    const policyBody = sql.match(new RegExp(
      `CREATE POLICY ${policy}\\s+ON public\\.${table}([\\s\\S]*?);`,
    ))?.[1] || '';
    assert.match(policyBody, /current_setting\('redactwall\.org_id', true\)/);
    assert.match(policyBody, /USING \(/);
    assert.match(policyBody, /WITH CHECK \(/);
  }

  const recordFunction = sql.match(
    /CREATE OR REPLACE FUNCTION public\.record_connected_authority_pair_delete\(\)[\s\S]*?\$connected_authority_pair_delete\$;/,
  )?.[0] || '';
  assert.match(recordFunction, /SET search_path = pg_catalog/);
  assert.match(recordFunction, /INSERT INTO public\.connected_authority_pair_deletions/);
  assert.match(recordFunction, /FROM public\.connected_authority_pair_deletions/);
  assert.match(recordFunction, /OLD\.transition_kind/);
  assert.match(recordFunction, /OLD\.applied_ack_payload_digest/);
  assert.match(recordFunction, /clock_timestamp\(\) AT TIME ZONE 'UTC'/);
  assert.doesNotMatch(
    recordFunction,
    /(?:INSERT INTO|FROM) connected_authority_pair_deletions/,
  );
  for (const functionName of [
    'reject_connected_authority_pair_update',
    'reject_connected_authority_pair_deletion_mutation',
  ]) {
    const functionBody = sql.match(new RegExp(
      `CREATE OR REPLACE FUNCTION public\\.${functionName}\\(\\)[\\s\\S]*?;\\n      END;`,
    ))?.[0] || '';
    assert.match(functionBody, /SET search_path = pg_catalog/);
    assert.match(functionBody, /ERRCODE = '55000'/);
  }
});

test('v15 runtime attests the complete SQLite and PostgreSQL authority catalogs', () => {
  const source = fs.readFileSync(
    path.join(serverRoot, 'connected-acknowledged-authority-store.js'), 'utf8',
  );
  assert.match(source, /FROM main\.sqlite_schema/);
  assert.match(source, /FROM temp\.sqlite_schema/);
  for (const catalog of [
    'pg_class', 'pg_attribute', 'pg_constraint', 'pg_proc', 'pg_trigger',
    'pg_policy', 'pg_index',
  ]) assert.match(source, new RegExp(`FROM pg_catalog\\.${catalog}`));
  assert.match(source, /pg_catalog\.pg_get_constraintdef/);
  assert.match(source, /pg_catalog\.pg_get_triggerdef/);
  assert.match(source, /pg_catalog\.pg_get_indexdef/);
  assert.match(source, /pg_catalog\.pg_get_userbyid/);
  assert.match(source, /LOCK TABLE[\s\S]*IN SHARE MODE/);
  assert.match(source, /LOCK TABLE[\s\S]*IN SHARE ROW EXCLUSIVE MODE/);
  assert.match(source, /PRAGMA main\.schema_version/);
  assert.match(source, /assertDeletionAppend/);
  assert.match(source, /assertAuthorityCatalog\(ctx, catalogIdentity\)/);
  assert.match(source, /rowSecurity.*forceRowSecurity/s);
  assert.match(source, /search_path=pg_catalog/);
  assert.match(source, /validatePostgresConstraints/);
  assert.match(source, /validatePostgresFunctions/);
  assert.match(source, /validatePostgresPolicies/);
  assert.match(source, /validatePostgresIndexes/);
  assert.match(source, /function collapseCatalogWhitespace\(value\)/);
  assert.match(source, /trim\(\)\.replace\(\/\\s\+\/g, ' '\)/);
  assert.doesNotMatch(source, /normalizeCatalog.*toLowerCase|replace\([^\n]*\\\(|replace\([^\n]*\\\)/);
  assert.match(source, /LIMIT \$\{MAX_LIVE_PAIR_LINEAGES \+ 1\}/);
});

test('Postgres migration runner pins public before any ledger or DDL lookup', () => {
  const source = fs.readFileSync(path.join(serverRoot, 'storage', 'index.js'), 'utf8');
  const runner = source.match(/function runMigrations\(driver, kind, options = \{\}\) \{[\s\S]*?\n\}/)?.[0] || '';
  assert.match(runner, /driver\.exec\('SET LOCAL search_path = public, pg_catalog, pg_temp'\)/);
  assert.ok(
    runner.indexOf("SET LOCAL search_path = public, pg_catalog, pg_temp")
      < runner.indexOf('pg_advisory_xact_lock'),
    'search path is pinned before the migration ledger and DDL are resolved',
  );
  assert.match(source, /pg_catalog\.to_regclass\('public\.' \|\| \?\)/);
  assert.doesNotMatch(source, /SELECT to_regclass\(\?\)/);
  assert.match(source, /SELECT version FROM \$\{ledger\} WHERE version = \?/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS \$\{ledger\}/);
  assert.match(source, /INSERT INTO \$\{ledger\}/);
  assert.doesNotMatch(source, /(?:SELECT version FROM|CREATE TABLE IF NOT EXISTS|INSERT INTO) schema_migrations\b/);
});

test('populated applied-only v11 connected state is rejected before v13 durability', (t) => {
  const Database = require('better-sqlite3');
  const storage = require('../server/storage');
  const d = new Database(':memory:');
  t.after(() => d.close());

  const stopBeforeV13 = new Error('stop before v13');
  assert.throws(() => storage.runMigrations(d, 'sqlite', {
    beforeMigration({ migration }) {
      if (migration.version === 13) throw stopBeforeV13;
    },
  }), (error) => error === stopBeforeV13);
  assert.strictEqual(
    d.prepare('SELECT MAX(version) AS version FROM schema_migrations').get().version,
    12,
  );

  const now = '2026-07-13T12:00:00.000Z';
  d.prepare(`INSERT INTO connected_entitlement_state
    (customer_id, deployment_id, authority_ref, entitlement_version,
     entitlement_digest, state_json, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run('tenant_guard', `dep_${'a'.repeat(32)}`, 'authority-ref', 1, 'digest', '{}', now);
  d.prepare(`INSERT INTO connected_ack_outbox
    (id, customer_id, deployment_id, target_kind, target_version, target_digest,
     lifecycle_stage, payload_json, payload_digest, status, attempts,
     next_attempt_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 'applied', ?, ?, 'pending', 0, ?, ?, ?)`)
    .run(
      'ack-applied-only', 'tenant_guard', `dep_${'a'.repeat(32)}`,
      'entitlement.release.v1', 1, 'digest', '{}', 'payload-digest', now, now, now,
    );

  assert.throws(() => storage.runMigrations(d, 'sqlite'), /populated = 0/);
  assert.strictEqual(
    d.prepare('SELECT COUNT(*) AS count FROM schema_migrations WHERE version = 13').get().count,
    0,
  );
  assert.strictEqual(d.prepare('SELECT COUNT(*) AS count FROM connected_ack_outbox').get().count, 1);
  assert.equal(d.prepare(`SELECT name FROM pragma_table_xinfo('audit')
    WHERE name = 'connected_entry_action'`).get(), undefined);
  assert.equal(d.prepare(`SELECT name FROM sqlite_master
    WHERE type = 'table' AND name IN
      ('connected_ack_health', 'connected_ack_archive', 'connected_ack_archive_mutations')
    LIMIT 1`).get(), undefined);
});

test('unusable configured SQLite path falls back to local temp storage with a warning', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-db-fallback-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const dbPath = copyDbRuntime(tempRoot);
  const blockingFile = path.join(tempRoot, 'not-a-directory');
  fs.writeFileSync(blockingFile, 'blocks mkdir');
  const badPath = path.join(blockingFile, 'redactwall.db');
  const script = `
    const fs = require('node:fs');
    const db = require(process.argv[1]);
    const snapshot = { dbPath: db._dbPath, exists: fs.existsSync(db._dbPath), integrity: db.verifyAuditChain() };
    db._db.close();
    process.stdout.write(JSON.stringify(snapshot));
  `;

  const child = spawnSync(process.execPath, ['-e', script, dbPath], {
    cwd: tempRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_PATH: path.join(root, 'node_modules'),
      REDACTWALL_ENV_PATH: path.join(tempRoot, 'missing.env'),
      REDACTWALL_DB_PATH: badPath,
      TMP: tempRoot,
      TEMP: tempRoot,
      TMPDIR: tempRoot,
    },
  });

  assert.strictEqual(child.status, 0, child.stderr || child.stdout);
  const snapshot = JSON.parse(child.stdout);
  assert.notStrictEqual(snapshot.dbPath, badPath);
  assert.match(snapshot.dbPath.replace(/\\/g, '/'), /redactwall\/redactwall\.db$/);
  assert.strictEqual(snapshot.exists, true);
  assert.deepStrictEqual(snapshot.integrity, { ok: true, count: 0 });
  assert.match(child.stderr, /falling back/);
});

test('original DB module falls back in-process when configured SQLite path is unusable', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-db-fallback-in-process-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const blockingFile = path.join(tempRoot, 'not-a-directory');
  fs.writeFileSync(blockingFile, 'blocks mkdir');
  const badPath = path.join(blockingFile, 'redactwall.db');
  const dbModulePath = require.resolve('../server/db');
  const previous = {
    REDACTWALL_DB_PATH: process.env.REDACTWALL_DB_PATH,
    REDACTWALL_ENV_PATH: process.env.REDACTWALL_ENV_PATH,
    TMP: process.env.TMP,
    TEMP: process.env.TEMP,
    TMPDIR: process.env.TMPDIR,
  };
  const originalError = console.error;
  const errors = [];
  try {
    delete require.cache[dbModulePath];
    process.env.REDACTWALL_DB_PATH = badPath;
    process.env.REDACTWALL_ENV_PATH = path.join(tempRoot, 'missing.env');
    process.env.TMP = tempRoot;
    process.env.TEMP = tempRoot;
    process.env.TMPDIR = tempRoot;
    console.error = (...args) => errors.push(args.join(' '));

    const db = require('../server/db');

    assert.notStrictEqual(db._dbPath, badPath);
    assert.match(db._dbPath.replace(/\\/g, '/'), /redactwall\/redactwall\.db$/);
    assert.deepStrictEqual(db.verifyAuditChain(), { ok: true, count: 0 });
    assert.match(errors.join('\n'), /falling back/);
    db._db.close();
  } finally {
    console.error = originalError;
    delete require.cache[dbModulePath];
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
