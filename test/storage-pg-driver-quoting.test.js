'use strict';
/**
 * Regression coverage for the Postgres sync-bridge identifier quoting and the
 * request/reply desync guard — both exercised without a live Postgres (pure
 * translation + a stubbed FIFO port), so they run in the default CI gate.
 */
const test = require('node:test');
const assert = require('node:assert');
const { quoteCamelIdentifiers, translateSql, takeReply, hash32 } = require('../server/storage/pg-driver');
const { MIGRATIONS } = require('../server/storage/migrations');

test('camelCase words inside a string literal are NOT quoted', () => {
  // The v3 backfill reads a JSON key literally named orgId; quoting it there
  // (->> '"orgId"') would look up a key that never exists and NULL every row.
  const sql = "UPDATE queries SET orgId = NULLIF(data::jsonb->>'orgId', '')";
  const out = quoteCamelIdentifiers(sql);
  assert.ok(out.includes("->>'orgId'"), 'JSON key literal must stay intact');
  assert.ok(!out.includes(`'"orgId"'`), 'must not quote inside the literal');
  assert.ok(/SET "orgId" =/.test(out), 'the real column identifier is still quoted');
});

test('the shipped v3 Postgres migration survives quoting unchanged where it matters', () => {
  const v3 = MIGRATIONS.find((m) => m.version === 3).postgres;
  const out = quoteCamelIdentifiers(v3);
  assert.ok(out.includes("data::jsonb->>'orgId'"), 'backfill source key preserved');
  assert.ok(out.includes("current_setting('redactwall.org_id', true)"), 'GUC name literal preserved');
});

test('already-quoted identifiers are not double-quoted and @params are untouched', () => {
  assert.strictEqual(quoteCamelIdentifiers('SELECT "orgId" FROM queries'), 'SELECT "orgId" FROM queries');
  const { text } = translateSql('INSERT INTO queries (orgId, createdAt) VALUES (@orgId, @createdAt)');
  assert.ok(/"orgId", "createdAt"/.test(text), 'column list quoted');
  assert.ok(/VALUES \(\$1, \$2\)/.test(text), '@params still bind positionally');
});

test('every mixed-case column introduced by migration 7 is quoted in runtime SQL', () => {
  const v7 = MIGRATIONS.find((migration) => migration.version === 7).postgres;
  const mixedCaseColumns = [...new Set(
    [...v7.matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"/g)]
      .map((match) => match[1])
      .filter((name) => /[A-Z]/.test(name)),
  )].sort();

  assert.deepStrictEqual(mixedCaseColumns, [
    'acceptedAt',
    'contactEmail',
    'createdAt',
    'displayName',
    'expiresAt',
    'orgId',
    'requestedSeats',
    'tokenHash',
    'updatedAt',
    'userKey',
    'userName',
  ]);
  for (const column of mixedCaseColumns) {
    assert.strictEqual(
      quoteCamelIdentifiers(`SELECT ${column} FROM administration_test`),
      `SELECT "${column}" FROM administration_test`,
      `${column} must not be folded to lowercase by Postgres`,
    );
  }
});

test('native idempotency columns stay quoted in migration and runtime SQL', () => {
  const v10 = MIGRATIONS.find((migration) => migration.version === 10).postgres;
  for (const column of ['auditId', 'createdAt', 'ingestIdentityHash', 'keyHash', 'orgId', 'queryId', 'replaySnapshot']) {
    assert.ok(v10.includes(`"${column}"`), `migration 10 must quote ${column}`);
    assert.strictEqual(
      quoteCamelIdentifiers(`SELECT ${column} FROM ingest_idempotency`),
      `SELECT "${column}" FROM ingest_idempotency`,
      `${column} must not be folded to lowercase by Postgres`,
    );
  }
  const translated = translateSql(
    'SELECT queryId FROM ingest_idempotency WHERE scope = @scope AND orgId = @orgId AND keyHash = @keyHash',
  );
  assert.match(translated.text, /SELECT "queryId"/);
  assert.match(translated.text, /"orgId" = \$2/);
  assert.match(translated.text, /"keyHash" = \$3/);
});

test('takeReply discards a stale reply then returns the matching one', () => {
  // Simulate the FIFO after a timed-out call: reply seq=1 arrives late, then the
  // real reply seq=2. The bridge must drop #1 and return #2, not #1's rows.
  const queue = [{ message: { seq: 1, result: 'STALE' } }, { message: { seq: 2, result: 'FRESH' } }];
  const receive = () => queue.shift() || null;
  const reply = takeReply(receive, 2);
  assert.strictEqual(reply.result, 'FRESH');
  assert.strictEqual(queue.length, 0, 'stale reply was drained, not left to poison the next call');
});

test('takeReply returns null when its reply has not arrived yet', () => {
  assert.strictEqual(takeReply(() => null, 5), null);
  const queue = [{ message: { seq: 9, result: 'OTHER' } }];
  assert.strictEqual(takeReply(() => queue.shift() || null, 5), null, 'no match -> null, do not return a foreign reply');
});

test('hash32 is deterministic and stays a signed 32-bit int for advisory keys', () => {
  assert.strictEqual(hash32('q_abc'), hash32('q_abc'));
  assert.notStrictEqual(hash32('q_abc'), hash32('q_abd'));
  const h = hash32('q_' + 'x'.repeat(64));
  assert.ok(Number.isInteger(h) && h >= -2147483648 && h <= 2147483647);
});
