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
  for (const file of ['db.js', 'env.js', 'audit-integrity.js']) {
    fs.copyFileSync(path.join(serverRoot, file), path.join(tempServer, file));
  }
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
      detail: 'structured pii detected',
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
        sqlite: fs.existsSync(path.join(dataDir, 'sentinel.db')),
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
      SENTINEL_ENV_PATH: path.join(tempRoot, 'missing.env'),
      PROMPTWALL_ENV_PATH: '',
      SENTINEL_DB_PATH: '',
      PROMPTWALL_DB_PATH: '',
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
  assert.strictEqual(snapshot.integrity.ok, true);
  assert.ok(snapshot.audit.some((entry) => entry.action === 'BLOCKED' && entry.queryId === 'legacy-q-1'));
  assert.ok(snapshot.audit.some((entry) => entry.action === 'APPROVED' && entry.queryId === 'legacy-q-2'));
  assert.ok(snapshot.audit.some((entry) => entry.action === 'STORE_MIGRATED'));
  assert.ok(snapshot.audit.find((entry) => entry.queryId === 'legacy-q-1').contentHash);
  assert.deepStrictEqual(snapshot.files, {
    sqlite: true,
    queriesJson: false,
    auditJson: false,
    queriesMigrated: true,
    auditMigrated: true,
  });
});

test('explicit SQLite path disables legacy JSON auto-migration', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-db-explicit-path-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  writeLegacyStore(tempRoot);
  const explicitDb = path.join(tempRoot, 'custom', 'sentinel.db');

  const snapshot = runCopiedDb(tempRoot, { SENTINEL_DB_PATH: explicitDb });

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
