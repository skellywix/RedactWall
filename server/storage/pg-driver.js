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

const CALL_TIMEOUT_MS = 30000;

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

function quoteCamelIdentifiers(sql) {
  return sql.replace(CAMEL_RE, '"$1"');
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

function createPgDriver(connectionString) {
  const shared = new SharedArrayBuffer(4);
  const flag = new Int32Array(shared);
  const { port1, port2 } = new MessageChannel();
  const worker = new Worker(path.join(__dirname, 'pg-worker.js'), {
    workerData: { shared, port: port2, connectionString },
    transferList: [port2],
  });
  worker.unref();
  let txDepth = 0;

  function call(op, sql, params) {
    Atomics.store(flag, 0, 0);
    worker.postMessage({ op, sql, params });
    const deadline = Date.now() + CALL_TIMEOUT_MS;
    while (Atomics.load(flag, 0) === 0) {
      if (Date.now() > deadline) throw new Error('postgres bridge timeout');
      Atomics.wait(flag, 0, 0, 100);
    }
    const msg = receiveMessageOnPort(port1);
    if (!msg) throw new Error('postgres bridge: missing reply');
    if (msg.message.error) {
      const err = new Error(msg.message.error);
      err.code = msg.message.code;
      throw err;
    }
    return msg.message.result;
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
    pragma: () => undefined,
    setTenantContext: (orgId) => {
      call('query', 'SELECT set_config($1, $2, false)', ['promptwall.org_id', String(orgId || '')]);
    },
    close: () => {
      try { call('close'); } catch { /* already gone */ }
      worker.terminate();
    },
  };
}

module.exports = { createPgDriver, translateSql, quoteCamelIdentifiers };
