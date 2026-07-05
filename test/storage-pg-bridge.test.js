'use strict';
/**
 * Sync-bridge hardening for the Postgres driver: session statement_timeout,
 * bounded connect retry/backoff, and reconnect after connection loss.
 * Config tests always run; live tests need REDACTWALL_TEST_PG_URL and skip
 * cleanly otherwise (same convention as test/storage-postgres.test.js).
 */
const test = require('node:test');
const assert = require('node:assert');
const { resolveBridgeConfig, createPgDriver } = require('../server/storage/pg-driver');

const ADMIN_URL = process.env.REDACTWALL_TEST_PG_URL || '';

function withEnv(overrides, fn) {
  const previous = {};
  for (const [key, value] of Object.entries(overrides)) {
    previous[key] = process.env[key];
    process.env[key] = value;
  }
  try {
    return fn();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test('bridge config defaults keep the DB cancel below the Atomics.wait cap', () => {
  const cfg = resolveBridgeConfig({});
  assert.strictEqual(cfg.statementTimeoutMs, 25000);
  assert.strictEqual(cfg.callTimeoutMs, 30000); // pre-hardening bridge cap preserved
  assert.ok(cfg.statementTimeoutMs < cfg.callTimeoutMs);
  assert.strictEqual(cfg.connectAttempts, 5);
  assert.strictEqual(cfg.connectBaseDelayMs, 200);
  assert.strictEqual(cfg.connectTimeoutMs, 5000);
});

test('bridge config clamps env values and keeps the cancel-before-bridge invariant', () => {
  const raised = resolveBridgeConfig({ REDACTWALL_PG_STATEMENT_TIMEOUT_MS: '120000' });
  assert.strictEqual(raised.statementTimeoutMs, 120000);
  assert.strictEqual(raised.callTimeoutMs, 125000);

  const floored = resolveBridgeConfig({
    REDACTWALL_PG_STATEMENT_TIMEOUT_MS: '1',
    REDACTWALL_PG_CONNECT_ATTEMPTS: '0',
    REDACTWALL_PG_CONNECT_BASE_DELAY_MS: '-5',
    REDACTWALL_PG_CONNECT_TIMEOUT_MS: '1',
  });
  assert.strictEqual(floored.statementTimeoutMs, 1000);
  assert.strictEqual(floored.connectAttempts, 1);
  assert.strictEqual(floored.connectBaseDelayMs, 10);
  assert.strictEqual(floored.connectTimeoutMs, 500);

  assert.strictEqual(resolveBridgeConfig({ REDACTWALL_PG_STATEMENT_TIMEOUT_MS: 'soon' }).statementTimeoutMs, 25000);
  assert.strictEqual(resolveBridgeConfig({ REDACTWALL_PG_CONNECT_ATTEMPTS: '999' }).connectAttempts, 20);
});

test('connect retry is bounded and fails with a clear error, never an infinite loop', () => {
  withEnv({
    REDACTWALL_PG_CONNECT_ATTEMPTS: '2',
    REDACTWALL_PG_CONNECT_BASE_DELAY_MS: '10',
    REDACTWALL_PG_CONNECT_TIMEOUT_MS: '500',
  }, () => {
    // Port 1 refuses immediately; no Postgres needed for this path.
    const driver = createPgDriver('postgresql://nobody@127.0.0.1:1/redactwall_nowhere');
    try {
      const started = Date.now();
      assert.throws(() => driver.prepare('SELECT 1 AS n').get(), /connect failed after 2 attempt/);
      assert.ok(Date.now() - started < 10000, 'retry cycle must stay bounded');
    } finally {
      driver.close();
    }
  });
});

test('statement_timeout is set on the session and cancels runaway statements', { skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set' }, () => {
  withEnv({ REDACTWALL_PG_STATEMENT_TIMEOUT_MS: '1500' }, () => {
    const driver = createPgDriver(ADMIN_URL);
    try {
      assert.strictEqual(driver.prepare('SHOW statement_timeout').get().statement_timeout, '1500ms');
      const started = Date.now();
      assert.throws(() => driver.prepare('SELECT pg_sleep(30)').get(), (err) => err.code === '57014');
      assert.ok(Date.now() - started < 6500, 'the database cancel must beat the bridge cap');
      // The connection survives a statement cancel.
      assert.strictEqual(driver.prepare('SELECT 1 AS n').get().n, 1);
    } finally {
      driver.close();
    }
  });
});

test('bridge reconnects after connection loss without replaying statements', { skip: !ADMIN_URL && 'REDACTWALL_TEST_PG_URL not set' }, async () => {
  const driver = createPgDriver(ADMIN_URL);
  const { Client } = require('pg');
  const admin = new Client({ connectionString: ADMIN_URL });
  await admin.connect();
  try {
    const pid = driver.prepare('SELECT pg_backend_pid() AS pid').get().pid;
    await admin.query('SELECT pg_terminate_backend($1)', [pid]);
    await new Promise((resolve) => setTimeout(resolve, 300));

    let value = null;
    for (let attempt = 0; attempt < 3 && value === null; attempt++) {
      try {
        value = driver.prepare('SELECT 41 + 1 AS n').get().n;
      } catch { /* the killed connection may surface one failed call */ }
    }
    assert.strictEqual(value, 42, 'driver must recover on a fresh connection');
    assert.notStrictEqual(driver.prepare('SELECT pg_backend_pid() AS pid').get().pid, pid);
  } finally {
    await admin.end();
    driver.close();
  }
});
