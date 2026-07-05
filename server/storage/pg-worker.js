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
  // Backend loss emits 'error' on the idle client; drop it so the next call
  // reconnects instead of crashing the worker on an unhandled 'error' event.
  candidate.on('error', () => { if (client === candidate) client = null; });
  return candidate;
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
  const connected = await ensureClient();
  const res = Array.isArray(params) && params.length
    ? await connected.query({ text: sql, values: params })
    : await connected.query(sql); // simple protocol: multi-statement exec works
  const last = Array.isArray(res) ? res[res.length - 1] : res;
  return { rows: last.rows || [], rowCount: last.rowCount || 0 };
}

async function closeClient() {
  const current = client;
  client = null;
  if (current) await current.end().catch(() => {});
  return true;
}

parentPort.on('message', async ({ op, sql, params }) => {
  try {
    reply({ result: op === 'close' ? await closeClient() : await runQuery(sql, params) });
  } catch (err) {
    reply({ error: err.message || String(err), code: err.code });
  }
});

// Warm the connection eagerly; a failure here is not fatal — it surfaces on
// the first call, which starts its own bounded retry cycle.
ensureClient().catch(() => {});
