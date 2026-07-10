'use strict';

const { fetchDatabaseRows } = require('./database-readonly');

process.once('message', (message = {}) => {
  try {
    const result = fetchDatabaseRows(message.args, message.opts);
    if (process.send) process.send({ ok: true, result });
  } catch {
    if (process.send) process.send({ ok: false });
  }
});
