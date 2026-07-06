'use strict';
/**
 * Worker thread that owns the Postgres connection for the sync bridge.
 * The main thread blocks on Atomics.wait while this worker runs the query,
 * so the synchronous db.js interface keeps working unchanged on Postgres.
 *
 * Connection hardening (tuning arrives via workerData from
 * pg-driver.js#resolveBridgeConfig):
 *  - a session statement_timeout set just below the bridge's Atomics.wait cap,
 *    so the database cancels a runaway statement (SQLSTATE 57014) and keeps
 *    the connection alive instead of the bridge abandoning the worker;
 *  - bounded exponential-backoff reconnect on initial connection and after
 *    connection loss. Each call that needs a connection runs at most
 *    connectAttempts attempts and then fails with a clear error — never an
 *    infinite loop. Failed statements are never replayed; the caller decides.
 */
const { workerData, parentPort } = require('worker_threads');
const pg = require('pg');

// COUNT(*)/BIGSERIAL come back as int8; parse to JS numbers so `.get().n`
// arithmetic keeps behaving exactly like better-sqlite3.
pg.types.setTypeParser(20, (value) => parseInt(value, 10));

const flag = new Int32Array(workerData.shared);
const port = workerData.port;
const config = {
  connectionString: workerData.connectionString,
  statementTimeoutMs: workerData.statementTimeoutMs || 25000,
  connectAttempts: workerData.connectAttempts || 5,
  connectBaseDelayMs: workerData.connectBaseDelayMs || 200,
  connectTimeoutMs: workerData.connectTimeoutMs || 5000,
};
const MAX_BACKOFF_MS = 15000;

let client = null; // live connected client, or null when down
let connecting = null; // in-flight connect cycle shared by concurrent callers
let generation = 0; // bumped on every successful physical connection
let txGeneration = null; // the generation an open transaction began on, or null
let tenantOrgId = ''; // RLS tenant GUC, re-applied on every (re)connect

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function reply(message) {
  port.postMessage(message);
  Atomics.store(flag, 0, 1);
  Atomics.notify(flag, 0);
}

async function connectOnce() {
  const candidate = new pg.Client({
    connectionString: config.connectionString,
    connectionTimeoutMillis: config.connectTimeoutMs,
  });
  await candidate.connect();
  // statementTimeoutMs is a bounded integer from resolveBridgeConfig, never
  // raw user text. Session-level, so it survives BEGIN/COMMIT and SAVEPOINTs.
  await candidate.query(`SET statement_timeout = ${config.statementTimeoutMs}`);
  // Re-assert the tenant RLS context on the fresh session so it survives
  // reconnects rather than silently reverting to fail-open.
  if (tenantOrgId) {
    await candidate.query({ text: "SELECT set_config('redactwall.org_id', $1, false)", values: [tenantOrgId] });
  }
  // Backend loss emits 'error' on the idle client; drop it so the next call
  // reconnects instead of crashing the worker on an unhandled 'error' event.
  candidate.on('error', () => { if (client === candidate) client = null; });
  generation += 1;
  return candidate;
}

/** Classify a statement's role in transaction control so a mid-transaction
 *  connection loss surfaces as an error instead of silently autocommitting on
 *  a fresh session. Savepoint statements stay inside the enclosing tx. */
function txKind(sql) {
  const s = String(sql || '').replace(/^[\s(]+/, '').toUpperCase();
  if (s.startsWith('BEGIN')) return 'begin';
  if (s.startsWith('COMMIT')) return 'commit';
  if (/^ROLLBACK\s+TO\b/.test(s)) return 'other';
  if (s.startsWith('ROLLBACK')) return 'rollback';
  return 'other';
}

async function setTenant(orgId) {
  tenantOrgId = String(orgId || '');
  const connected = await ensureClient();
  await connected.query({ text: "SELECT set_config('redactwall.org_id', $1, false)", values: [tenantOrgId] });
  return true;
}

async function connectWithRetry() {
  let lastError = null;
  for (let attempt = 1; attempt <= config.connectAttempts; attempt++) {
    try {
      return await connectOnce();
    } catch (err) {
      lastError = err;
      if (attempt < config.connectAttempts) {
        await delay(Math.min(config.connectBaseDelayMs * 2 ** (attempt - 1), MAX_BACKOFF_MS));
      }
    }
  }
  throw new Error(`postgres connect failed after ${config.connectAttempts} attempt(s): ${(lastError && lastError.message) || 'unknown error'}`);
}

function ensureClient() {
  if (client) return Promise.resolve(client);
  if (!connecting) {
    connecting = connectWithRetry()
      .then((connected) => { client = connected; return connected; })
      .finally(() => { connecting = null; });
  }
  return connecting;
}

async function runQuery(sql, params) {
  const kind = txKind(sql);
  const lostMidTx = txGeneration !== null && (!client || generation !== txGeneration);
  // A transaction whose connection was lost must NOT continue on a fresh
  // session (that would autocommit stray statements and turn COMMIT into a
  // no-op). Fail such statements; only a COMMIT surfaces the loss to the
  // caller, while ROLLBACK of already-discarded work is a safe no-op.
  if (kind === 'commit') {
    txGeneration = null;
    if (lostMidTx) throw new Error('postgres transaction aborted: connection lost before COMMIT');
  } else if (kind === 'rollback') {
    txGeneration = null;
  } else if (kind !== 'begin' && lostMidTx) {
    throw new Error('postgres transaction aborted: connection lost mid-transaction');
  }
  const connected = await ensureClient();
  const res = Array.isArray(params) && params.length
    ? await connected.query({ text: sql, values: params })
    : await connected.query(sql); // simple protocol: multi-statement exec works
  if (kind === 'begin') txGeneration = generation;
  const last = Array.isArray(res) ? res[res.length - 1] : res;
  return { rows: last.rows || [], rowCount: last.rowCount || 0 };
}

async function closeClient() {
  const current = client;
  client = null;
  if (current) await current.end().catch(() => {});
  return true;
}

async function dispatch(op, sql, params) {
  if (op === 'close') return closeClient();
  if (op === 'setTenant') return setTenant(params && params[0]);
  return runQuery(sql, params);
}

parentPort.on('message', async ({ op, sql, params, seq }) => {
  // Echo seq so the bridge can discard a stale reply left by a timed-out call.
  try {
    reply({ seq, result: await dispatch(op, sql, params) });
  } catch (err) {
    reply({ seq, error: err.message || String(err), code: err.code });
  }
});

// Warm the connection eagerly; a failure here is not fatal — it surfaces on
// the first call, which starts its own bounded retry cycle.
ensureClient().catch(() => {});
