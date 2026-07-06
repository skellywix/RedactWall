'use strict';
/**
 * Synchronous Postgres driver exposing the better-sqlite3 surface db.js uses:
 * prepare().get/.all/.run, exec(), transaction(), pragma() (no-op), close().
 *
 * Queries run on a worker thread that owns the pg connection; the calling
 * thread blocks on Atomics.wait, so the whole control plane keeps its
 * synchronous storage contract without an async rewrite.
 */
const path = require('path');
const { Worker, MessageChannel, receiveMessageOnPort } = require('worker_threads');

const DEFAULT_STATEMENT_TIMEOUT_MS = 25000;
const BRIDGE_GRACE_MS = 5000;

function boundedInt(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

/**
 * Bridge and session tuning from the environment. The session
 * statement_timeout stays below the Atomics.wait cap (callTimeoutMs =
 * statement timeout + grace) so Postgres cancels a runaway statement — and
 * keeps the connection alive — before the bridge gives up on the worker.
 */
function resolveBridgeConfig(env = process.env) {
  const statementTimeoutMs = boundedInt(env.REDACTWALL_PG_STATEMENT_TIMEOUT_MS, DEFAULT_STATEMENT_TIMEOUT_MS, 1000, 600000);
  return {
    statementTimeoutMs,
    callTimeoutMs: statementTimeoutMs + BRIDGE_GRACE_MS,
    connectAttempts: boundedInt(env.REDACTWALL_PG_CONNECT_ATTEMPTS, 5, 1, 20),
    connectBaseDelayMs: boundedInt(env.REDACTWALL_PG_CONNECT_BASE_DELAY_MS, 200, 10, 10000),
    connectTimeoutMs: boundedInt(env.REDACTWALL_PG_CONNECT_TIMEOUT_MS, 5000, 500, 60000),
  };
}

// Runtime SQL is written in db.js with camelCase identifiers (which Postgres
// would fold to lowercase) and a `user` column (reserved in Postgres), so
// quote the known column set to keep row keys byte-identical across drivers.
// The lookbehind skips @named parameters and already-quoted identifiers.
const CAMEL_IDENTIFIERS = [
  'createdAt', 'updatedAt', 'queryId', 'detectorId', 'dedupeKey', 'destId',
  'canonicalHost', 'firstSeen', 'lastSeen', 'userName', 'displayName',
  'revokedAt', 'usedAt', 'codeIndex', 'prevHash', 'orgId', 'user',
];
const CAMEL_RE = new RegExp(`(?<!["@])\\b(${CAMEL_IDENTIFIERS.join('|')})\\b`, 'g');

// Quote the known camelCase columns, but ONLY outside string/identifier
// literals: a camelCase word inside a '...' literal (e.g. the JSON key in
// data::jsonb->>'orgId') must be left byte-for-byte intact, or migrations and
// runtime SQL that reference such keys silently read/write the wrong column.
function quoteCamelIdentifiers(sql) {
  let out = '';
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i];
    if (ch === "'" || ch === '"') {
      const start = i++;
      while (i < sql.length) { // copy the literal verbatim; '' / "" escapes the quote
        if (sql[i] === ch) {
          if (sql[i + 1] === ch) { i += 2; continue; }
          i++;
          break;
        }
        i++;
      }
      out += sql.slice(start, i);
    } else {
      const start = i;
      while (i < sql.length && sql[i] !== "'" && sql[i] !== '"') i++;
      out += sql.slice(start, i).replace(CAMEL_RE, '"$1"');
    }
  }
  return out;
}

/** Rewrite @name / ? placeholders to $1..$n; returns binder for call args. */
function translateSql(sql) {
  const quoted = quoteCamelIdentifiers(sql);
  const named = [];
  let text = quoted.replace(/@([A-Za-z_][A-Za-z0-9_]*)/g, (_, name) => {
    let index = named.indexOf(name);
    if (index === -1) { named.push(name); index = named.length - 1; }
    return '$' + (index + 1);
  });
  if (named.length) {
    return { text, bind: (args) => named.map((name) => normalizeValue((args[0] || {})[name])) };
  }
  let position = 0;
  text = text.replace(/\?/g, () => '$' + (++position));
  return { text, bind: (args) => args.map(normalizeValue) };
}

function normalizeValue(value) {
  return value === undefined ? null : value;
}

/**
 * Pull the reply matching `seq` from a FIFO port, discarding stale replies left
 * behind by an earlier call that timed out. Returns the matching reply message
 * or null when it has not arrived yet. `receive` yields the next queued
 * { message } envelope (or null/undefined when the port is empty).
 */
function takeReply(receive, seq) {
  let envelope = receive();
  while (envelope) {
    if (envelope.message.seq === seq) return envelope.message;
    envelope = receive(); // stale reply from a timed-out call — drop it
  }
  return null;
}

/** Stable 32-bit hash (FNV-1a) for deriving advisory-lock keys from a row id. */
function hash32(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h | 0;
}

function createPgDriver(connectionString) {
  const config = resolveBridgeConfig(process.env);
  const shared = new SharedArrayBuffer(4);
  const flag = new Int32Array(shared);
  const { port1, port2 } = new MessageChannel();
  const worker = new Worker(path.join(__dirname, 'pg-worker.js'), {
    workerData: { shared, port: port2, connectionString, ...config },
    transferList: [port2],
  });
  worker.unref();
  // A worker that dies (e.g. a require failure) can never signal the flag;
  // record the fault and wake the bridge so callers fail fast, not by timeout.
  let workerFault = null;
  const recordFault = (err) => {
    if (!workerFault) workerFault = err;
    Atomics.store(flag, 0, 1);
    Atomics.notify(flag, 0);
  };
  worker.once('error', recordFault);
  worker.once('exit', (code) => {
    if (code !== 0) recordFault(new Error(`worker exited with code ${code}`));
  });
  let txDepth = 0;
  let callSeq = 0;

  function call(op, sql, params) {
    if (workerFault) throw new Error(`postgres bridge worker failed: ${workerFault.message}`);
    const seq = ++callSeq;
    Atomics.store(flag, 0, 0);
    worker.postMessage({ op, sql, params, seq });
    const deadline = Date.now() + config.callTimeoutMs;
    for (;;) {
      // Drain queued replies and match on seq. A reply whose seq is not ours is
      // the late result of a call that already timed out; discard it so the
      // request/reply stream cannot desynchronize (every later call would
      // otherwise return the previous call's rows). See takeReply().
      const reply = takeReply(() => receiveMessageOnPort(port1), seq);
      if (reply) {
        if (reply.error) { const err = new Error(reply.error); err.code = reply.code; throw err; }
        return reply.result;
      }
      if (workerFault) throw new Error(`postgres bridge worker failed: ${workerFault.message}`);
      if (Date.now() > deadline) throw new Error('postgres bridge timeout');
      Atomics.store(flag, 0, 0); // re-arm; a missed notify self-heals on the 100ms slice
      Atomics.wait(flag, 0, 0, 100);
    }
  }

  function prepare(sql) {
    const { text, bind } = translateSql(sql);
    return {
      get: (...args) => call('query', text, bind(args)).rows[0],
      all: (...args) => call('query', text, bind(args)).rows,
      run: (...args) => ({ changes: call('query', text, bind(args)).rowCount }),
    };
  }

  function transaction(fn) {
    return (...args) => {
      const savepoint = txDepth > 0 ? `pw_sp_${txDepth}` : null;
      call('query', savepoint ? `SAVEPOINT ${savepoint}` : 'BEGIN', []);
      txDepth += 1;
      try {
        const result = fn(...args);
        call('query', savepoint ? `RELEASE SAVEPOINT ${savepoint}` : 'COMMIT', []);
        return result;
      } catch (err) {
        call('query', savepoint ? `ROLLBACK TO SAVEPOINT ${savepoint}` : 'ROLLBACK', []);
        throw err;
      } finally {
        txDepth -= 1;
      }
    };
  }

  return {
    kind: 'postgres',
    prepare,
    exec: (sql) => { call('query', quoteCamelIdentifiers(sql), []); },
    transaction,
    // Serialize audit-chain appends across app instances sharing one database:
    // a transaction-scoped advisory lock makes the read-head-then-insert append
    // atomic, so two instances cannot both link a new entry to the same
    // prevHash and permanently fork the chain. Released on COMMIT/ROLLBACK.
    lockAuditAppend: () => { call('query', 'SELECT pg_advisory_xact_lock($1)', [4021990]); },
    // Serialize a read-modify-write on one query id across instances sharing the
    // database: a transaction-scoped advisory lock keyed on the id makes
    // updateQuery's SELECT-then-UPDATE atomic so two concurrent patches can't
    // both read the pre-image and lose one write. Released on COMMIT/ROLLBACK.
    lockRowForUpdate: (key) => { call('query', 'SELECT pg_advisory_xact_lock($1, $2)', [4021991, hash32(String(key))]); },
    pragma: () => undefined,
    // Dedicated op so the worker REMEMBERS the tenant GUC and re-applies it on
    // every reconnect; a plain session-level set_config would be silently lost
    // the first time the bridge reconnects, leaving RLS fail-open.
    setTenantContext: (orgId) => { call('setTenant', null, [String(orgId || '')]); },
    close: () => {
      try { call('close'); } catch { /* already gone */ }
      worker.terminate();
    },
  };
}

module.exports = { createPgDriver, translateSql, quoteCamelIdentifiers, resolveBridgeConfig, takeReply, hash32 };
