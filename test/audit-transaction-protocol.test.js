'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');
const {
  installAuditTransactionProtocol,
  isAuditCommitUncertainError,
} = require('../server/storage');
const { openAuditAnchor } = require('../server/audit-anchor');
const auditIntegrity = require('../server/audit-integrity');

function transactionDriver(events) {
  let depth = 0;
  let failCommit = false;
  return {
    failNextCommit() { failCommit = true; },
    transaction(fn) {
      return (...args) => {
        const outer = depth === 0;
        events.push(outer ? 'BEGIN' : 'SAVEPOINT');
        depth += 1;
        try {
          const result = fn(...args);
          if (outer && failCommit) {
            failCommit = false;
            throw new Error('synthetic Postgres COMMIT failure');
          }
          events.push(outer ? 'COMMIT' : 'RELEASE');
          return result;
        } catch (error) {
          events.push(outer ? 'ROLLBACK' : 'ROLLBACK TO');
          throw error;
        } finally {
          depth -= 1;
        }
      };
    },
  };
}

test('transaction protocol prepares a merged batch before outer COMMIT', () => {
  const events = [];
  const driver = transactionDriver(events);
  const anchor = {
    prepareTransactionCommit(_driver, entries) {
      events.push(`PREPARE:${entries.map((entry) => entry.id).join(',')}`);
    },
    transactionCommitted() { events.push('ANCHOR COMMIT'); },
    transactionCommitUncertain() { events.push('ANCHOR UNCERTAIN'); },
  };
  const record = installAuditTransactionProtocol(driver, anchor);
  const inner = driver.transaction(() => { record({ id: 'a_inner' }); });
  const outer = driver.transaction(() => {
    record({ id: 'a_first' });
    inner();
    record({ id: 'a_last' });
  });

  outer();
  assert.deepStrictEqual(events, [
    'BEGIN',
    'SAVEPOINT',
    'RELEASE',
    'PREPARE:a_first,a_inner,a_last',
    'COMMIT',
    'ANCHOR COMMIT',
  ]);
});

test('Postgres-compatible COMMIT response failure is treated as commit-uncertain', () => {
  const events = [];
  const driver = transactionDriver(events);
  const anchor = {
    prepareTransactionCommit() { events.push('PREPARE'); },
    transactionCommitted() { events.push('ANCHOR COMMIT'); },
    transactionCommitUncertain() { events.push('ANCHOR UNCERTAIN'); },
  };
  const record = installAuditTransactionProtocol(driver, anchor);
  const transaction = driver.transaction(() => record({ id: 'a_rollback' }));
  driver.failNextCommit();

  let error;
  try { transaction(); } catch (caught) { error = caught; }
  assert.match(error.message, /synthetic Postgres COMMIT failure/);
  assert.equal(isAuditCommitUncertainError(error), true);
  assert.deepStrictEqual(events, [
    'BEGIN',
    'PREPARE',
    'ROLLBACK',
    'ANCHOR UNCERTAIN',
  ]);
});

test('uncertainty cleanup never masks frozen or primitive COMMIT errors', () => {
  for (const original of [Object.freeze(new Error('frozen commit failure')), 0]) {
    const driver = {
      transaction(callback) {
        return () => {
          callback();
          throw original;
        };
      },
    };
    const record = installAuditTransactionProtocol(driver, {
      prepareTransactionCommit() {},
      transactionCommitted() {},
      transactionCommitUncertain() { throw new Error('uncertainty cleanup failed'); },
    });
    let caught = Symbol('not thrown');
    try { driver.transaction(() => record({ id: 'a_uncertain' }))(); }
    catch (error) { caught = error; }
    if (typeof original === 'object') assert.strictEqual(caught, original);
    else assert.strictEqual(caught.cause, original);
    assert.equal(isAuditCommitUncertainError(caught), true);
  }
});

test('rolled-back nested savepoint entries never enter the outer pending batch', () => {
  const events = [];
  const driver = transactionDriver(events);
  const prepared = [];
  const anchor = {
    prepareTransactionCommit(_driver, entries) { prepared.push(entries.map((entry) => entry.id)); },
    transactionCommitted() {},
    transactionCommitUncertain() {},
  };
  const record = installAuditTransactionProtocol(driver, anchor);
  const inner = driver.transaction(() => {
    record({ id: 'a_rolled_back' });
    throw new Error('savepoint failure');
  });
  const outer = driver.transaction(() => {
    record({ id: 'a_kept' });
    assert.throws(inner, /savepoint failure/);
  });

  outer();
  assert.deepStrictEqual(prepared, [['a_kept']]);
});

function commitResponseLosingDriver(database) {
  let loseResponse = false;
  const afterCommit = (result) => {
    if (!loseResponse) return result;
    loseResponse = false;
    throw new Error('synthetic COMMIT response lost after apply');
  };
  return {
    prepare: database.prepare.bind(database),
    loseNextCommitResponse() { loseResponse = true; },
    transaction(fn) {
      const native = database.transaction(fn);
      const run = (...args) => afterCommit(native(...args));
      run.immediate = (...args) => afterCommit(native.immediate(...args));
      return run;
    },
  };
}

test('applied COMMIT with a lost response retains pending proof and restart rejects tail deletion', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-audit-commit-uncertain-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, 'audit.db');
  let database = new Database(file);
  database.exec(`
    CREATE TABLE audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, entry TEXT NOT NULL);
    CREATE TABLE queries (id TEXT PRIMARY KEY, data TEXT NOT NULL);
  `);
  const options = {
    directory: path.join(root, 'anchor'),
    allowBootstrap: true,
    env: { REDACTWALL_AUDIT_KEY: 'unit-commit-uncertain-key' },
  };
  const anchor = openAuditAnchor(options);
  assert.deepStrictEqual(anchor.verifyDatabase(database), { ok: true, count: 0 });
  const driver = commitResponseLosingDriver(database);
  const record = installAuditTransactionProtocol(driver, anchor);
  let committed;
  const append = driver.transaction(() => {
    committed = anchor.authenticate(auditIntegrity.ZERO, {
      id: 'a_commit_applied',
      ts: '2026-07-10T12:00:00.000Z',
      action: 'COMMIT_APPLIED_RESPONSE_LOST',
      queryId: '',
      actor: 'test',
      detail: 'sanitized',
    });
    driver.prepare('INSERT INTO audit (id, entry) VALUES (?, ?)')
      .run(committed.id, JSON.stringify(committed));
    record(committed);
  });
  driver.loseNextCommitResponse();

  assert.throws(append, /COMMIT response lost after apply/);
  assert.strictEqual(database.prepare('SELECT COUNT(*) n FROM audit').get().n, 1,
    'the database applied COMMIT even though the caller saw an error');
  const pending = JSON.parse(fs.readFileSync(anchor.paths.pendingPath, 'utf8'));
  assert.strictEqual(pending.entryId, committed.id, 'commit uncertainty retains the new high-water');
  assert.strictEqual(anchor.status().reason, 'commit-uncertain');

  database.prepare('DELETE FROM audit WHERE id = ?').run(committed.id);
  database.close();
  database = new Database(file);
  const restarted = openAuditAnchor({ ...options, allowBootstrap: false });
  assert.deepStrictEqual(restarted.verifyDatabase(database), {
    ok: false,
    count: 0,
    reason: 'checkpoint-truncated',
  });
  database.close();
});
