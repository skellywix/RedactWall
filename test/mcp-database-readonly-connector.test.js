'use strict';
/** Database read-only MCP connector must sanitize rows before model use. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const Database = require('better-sqlite3');
const {
  createDatabaseReadonlyQueryTool,
  createDatabaseSchemaTool,
  databasePathFromDsn,
  databaseReadonlyConnectorHealth,
  databaseScopes,
  fetchDatabaseRows,
  fetchDatabaseRowsWithBudget,
  fetchDatabaseSchema,
  rejectUnsafeSql,
  sanitizeDatabaseRows,
} = require('../sensors/mcp-guard/connectors/database-readonly');

function tempDb(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-mcp-db-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const dbPath = path.join(dir, 'member-data.db');
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE members (id INTEGER PRIMARY KEY, name TEXT, note TEXT);
    INSERT INTO members (name, note) VALUES
      ('Public Branch', 'Hours only'),
      ('Private Member', 'SSN 524-71-9043 and card 4111 1111 1111 1111');
  `);
  db.close();
  return dbPath;
}

test('databasePathFromDsn accepts only SQLite read paths', () => {
  assert.match(databasePathFromDsn('sqlite:///C:/data/pilot.db'), /C:[\\/]data[\\/]pilot\.db$/);
  assert.match(databasePathFromDsn('file:///C:/data/pilot.db?mode=ro'), /C:[\\/]data[\\/]pilot\.db$/);
  assert.throws(() => databasePathFromDsn('postgres://localhost/db'), /supports sqlite/);
  assert.throws(() => databasePathFromDsn('file:///C:/data/pilot.db?mode=rw'), /read-only/);
});

test('rejectUnsafeSql permits bounded reads and blocks write-capable statements', () => {
  assert.strictEqual(rejectUnsafeSql('select id, name from members'), 'select id, name from members');
  assert.strictEqual(rejectUnsafeSql('WITH recent AS (SELECT * FROM members) SELECT * FROM recent'), 'WITH recent AS (SELECT * FROM members) SELECT * FROM recent');
  assert.throws(() => rejectUnsafeSql('update members set name = "x"'), /only allows SELECT/);
  assert.throws(() => rejectUnsafeSql('select * from members; drop table members'), /single statement/);
  assert.throws(() => rejectUnsafeSql('select * from members -- comment'), /comments/);
  assert.throws(() => rejectUnsafeSql('select * from pragma_table_info("members")'), /forbidden SQL operation/);
});

test('fetchDatabaseRows runs read-only SQLite queries with bounded structured metadata', (t) => {
  const dbPath = tempDb(t);
  const result = fetchDatabaseRows({ sql: 'select id, name, note from members order by id', limit: 1 }, {
    databasePath: dbPath,
    label: 'pilot-member-db',
  });

  assert.ok(result.content[0].text.includes('Public Branch'));
  assert.ok(!JSON.stringify(result.structuredContent).includes(dbPath));
  assert.strictEqual(result.structuredContent.connector, 'database_readonly');
  assert.strictEqual(result.structuredContent.operation, 'query.readonly');
  assert.strictEqual(result.structuredContent.rowCount, 1);
  assert.strictEqual(result.structuredContent.columnCount, 3);
  assert.strictEqual(result.structuredContent.truncated, true);
  assert.match(result.structuredContent.queryHash, /^[a-f0-9]{16}$/);
});

test('fetchDatabaseSchema returns schema without exposing the database path', (t) => {
  const dbPath = tempDb(t);
  const result = fetchDatabaseSchema({}, {
    databasePath: dbPath,
    label: 'pilot-member-db',
  });

  assert.ok(result.content[0].text.includes('"members"'));
  assert.ok(result.content[0].text.includes('"note"'));
  assert.ok(!JSON.stringify(result).includes(dbPath));
  assert.strictEqual(result.structuredContent.operation, 'schema.readonly');
  assert.strictEqual(result.structuredContent.objectCount, 1);
});

test('sanitizeDatabaseRows redacts row content before returning MCP output', async (t) => {
  const dbPath = tempDb(t);
  let outbound;
  const sanitized = await sanitizeDatabaseRows({ sql: 'select note from members order by id desc', limit: 1 }, {
    databasePath: dbPath,
    label: 'pilot-member-db',
    guardOptions: {
      server: 'https://redactwall.test',
      key: 'unit-ingest-key',
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async (url, opts = {}) => {
        outbound = { url, body: JSON.parse(opts.body), headers: opts.headers };
        return { ok: true };
      },
    },
  });

  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(sanitized.findings.includes('CREDIT_CARD'));
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
  assert.ok(!JSON.stringify(sanitized.result).includes('4111 1111 1111 1111'));
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
  assert.strictEqual(outbound.body.destination, 'database_readonly.query.readonly');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.ok(!JSON.stringify(outbound.body).includes(dbPath));
});

test('database connector tools return sanitized MCP results only', async (t) => {
  const dbPath = tempDb(t);
  const queryTool = createDatabaseReadonlyQueryTool({
    databasePath: dbPath,
    guardOptions: { policy: { ignore: [], disabledDetectors: [] }, fetchImpl: async () => ({ ok: true }) },
  });
  const rows = await queryTool({ sql: 'select note from members order by id desc', limit: 1 });
  assert.ok(rows.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(rows).includes('524-71-9043'));

  const schemaTool = createDatabaseSchemaTool({
    databasePath: dbPath,
    guardOptions: { policy: { ignore: [], disabledDetectors: [] }, fetchImpl: async () => ({ ok: true }) },
  });
  const schema = await schemaTool({});
  assert.ok(schema.content[0].text.includes('members'));
});

test('database connector errors and health evidence are secret-free', (t) => {
  const dbPath = tempDb(t);
  assert.throws(
    () => fetchDatabaseRows({ sql: 'select * from missing_table' }, { databasePath: dbPath }),
    (err) => {
      assert.ok(!err.message.includes(dbPath));
      assert.ok(!err.message.includes('524-71-9043'));
      return true;
    }
  );

  const check = databaseReadonlyConnectorHealth({
    label: 'core-banking-reporting',
    scopes: ['readonly'],
    dsn: 'sqlite:///secret/path/member.db',
  }, true, 'readonly probe ok');
  assert.strictEqual(check.id, 'mcp_connector_database_read_only');
  assert.ok(check.detail.includes('tenant:core-banking-reporting'));
  assert.ok(check.detail.includes('scopes:1'));
  assert.ok(!JSON.stringify(check).includes('sqlite:///secret'));
  assert.deepStrictEqual(databaseScopes({ env: {} }), ['readonly']);
});

test('database query worker terminates recursive work at the execution budget', async (t) => {
  const dbPath = tempDb(t);
  const startedAt = Date.now();
  await assert.rejects(
    () => fetchDatabaseRowsWithBudget({
      sql: 'WITH RECURSIVE forever(x) AS (VALUES(1) UNION ALL SELECT x + 1 FROM forever) SELECT sum(x) FROM forever',
    }, { databasePath: dbPath, queryTimeoutMs: 50 }),
    (err) => err && err.code === 'REDACTWALL_DATABASE_QUERY_TIMEOUT'
  );
  assert.ok(Date.now() - startedAt < 2000, 'recursive query worker must be killable without wedging the test event loop');

  const normal = await fetchDatabaseRowsWithBudget({ sql: 'SELECT count(*) AS total FROM members' }, {
    databasePath: dbPath,
    queryTimeoutMs: 1000,
  });
  assert.match(normal.content[0].text, /"total": 2/);
});

test('database query worker contains native and V8 memory amplification', async (t) => {
  const dbPath = tempDb(t);
  const beforeRss = process.memoryUsage().rss;
  await assert.rejects(
    () => fetchDatabaseRowsWithBudget({ sql: 'SELECT hex(zeroblob(16777216)) AS amplified' }, {
      databasePath: dbPath,
      queryTimeoutMs: 3000,
      queryMemoryBytes: 8 * 1024 * 1024,
      maxBytes: 64,
    }),
    /Database read-only query failed/
  );
  assert.ok(process.memoryUsage().rss - beforeRss < 32 * 1024 * 1024, 'large SQLite result must stay isolated from the parent process');

  const normal = await fetchDatabaseRowsWithBudget({ sql: 'SELECT 1 AS alive' }, {
    databasePath: dbPath,
    queryTimeoutMs: 1000,
  });
  assert.match(normal.content[0].text, /"alive": 1/);
});

test('database query capacity remains reserved until each worker actually exits', async (t) => {
  const dbPath = tempDb(t);
  const workers = [];
  const forkImpl = () => {
    const worker = new EventEmitter();
    worker.kill = () => true;
    worker.send = (_payload, callback) => {
      callback(null);
      setImmediate(() => worker.emit('message', {
        ok: true,
        result: { content: [], structuredContent: {} },
      }));
    };
    workers.push(worker);
    return worker;
  };

  const pending = Array.from({ length: 4 }, () => fetchDatabaseRowsWithBudget(
    { sql: 'SELECT 1 AS alive' },
    { databasePath: dbPath, queryTimeoutMs: 1000, forkImpl },
  ));
  await new Promise((resolve) => setImmediate(() => setImmediate(resolve)));
  await assert.rejects(
    () => fetchDatabaseRowsWithBudget(
      { sql: 'SELECT 1 AS alive' },
      { databasePath: dbPath, queryTimeoutMs: 1000, forkImpl },
    ),
    (error) => error && error.code === 'REDACTWALL_DATABASE_QUERY_BUSY',
  );

  for (const worker of workers) worker.emit('exit', 0, null);
  await Promise.all(pending);
  const recovered = await fetchDatabaseRowsWithBudget({ sql: 'SELECT 1 AS alive' }, {
    databasePath: dbPath,
    queryTimeoutMs: 1000,
  });
  assert.match(recovered.content[0].text, /"alive": 1/);
});
