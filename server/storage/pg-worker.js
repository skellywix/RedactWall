'use strict';
/**
 * Worker thread that owns the Postgres connection for the sync bridge.
 * The main thread blocks on Atomics.wait while this worker runs the query,
 * so the synchronous db.js interface keeps working unchanged on Postgres.
 */
const { workerData, parentPort } = require('worker_threads');
const pg = require('pg');

// COUNT(*)/BIGSERIAL come back as int8; parse to JS numbers so `.get().n`
// arithmetic keeps behaving exactly like better-sqlite3.
pg.types.setTypeParser(20, (value) => parseInt(value, 10));

const flag = new Int32Array(workerData.shared);
const port = workerData.port;
const client = new pg.Client({ connectionString: workerData.connectionString });
const ready = client.connect();

function reply(message) {
  port.postMessage(message);
  Atomics.store(flag, 0, 1);
  Atomics.notify(flag, 0);
}

parentPort.on('message', async ({ op, sql, params }) => {
  try {
    await ready;
    if (op === 'close') {
      await client.end();
      reply({ result: true });
      return;
    }
    const res = Array.isArray(params) && params.length
      ? await client.query({ text: sql, values: params })
      : await client.query(sql); // simple protocol: multi-statement exec works
    const last = Array.isArray(res) ? res[res.length - 1] : res;
    reply({ result: { rows: last.rows || [], rowCount: last.rowCount || 0 } });
  } catch (err) {
    reply({ error: err.message || String(err), code: err.code });
  }
});
