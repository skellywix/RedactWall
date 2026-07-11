'use strict';

const fs = require('node:fs');
const path = require('node:path');

const mode = process.env.AUDIT_WORKER_MODE;
if (mode === 'concurrent') {
  const coordination = path.resolve(process.env.AUDIT_COORDINATION_DIRECTORY);
  const id = String(process.env.AUDIT_WORKER_ID);
  fs.writeFileSync(path.join(coordination, `ready-${id}`), String(process.pid), { flag: 'wx' });
  const go = path.join(coordination, 'go');
  const sleep = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + 20_000;
  while (!fs.existsSync(go)) {
    if (Date.now() > deadline) throw new Error('audit worker barrier timed out');
    Atomics.wait(sleep, 0, 0, 10);
  }
}
const db = require('../../server/db');

function output(value, code = 0) {
  process.stdout.write(JSON.stringify(value));
  process.exit(code);
}

function pending() {
  const file = db._auditAnchorPaths.pendingPath;
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null;
}

function appendBatch(prefix, count) {
  return db.appendAudits(Array.from({ length: count }, (_, index) => ({
    action: `${prefix}_${index + 1}`,
    actor: 'audit-crash-worker',
    detail: 'sanitized crash-boundary proof',
  })));
}

if (mode === 'append-crash') {
  const entries = appendBatch('CRASH_BATCH', Number(process.env.AUDIT_BATCH_SIZE || 1));
  output({ entries, pending: pending() }, 73);
}

if (mode === 'verify') {
  const result = db.verifyAuditChain();
  output({ result, pending: pending(), health: db.auditHealth() });
}

if (mode === 'rollback') {
  const retained = db.appendAudit({
    action: 'ROLLBACK_RETAINED', actor: 'audit-crash-worker', detail: 'sanitized retained proof',
  });
  let failure = '';
  try {
    db._db.transaction(() => {
      db.appendAudit({
        action: 'ROLLBACK_DISCARDED', actor: 'audit-crash-worker', detail: 'sanitized rollback proof',
      });
      throw new Error('synthetic callback rollback');
    })();
  } catch (error) {
    failure = error.message;
  }
  const rows = db._db.prepare('SELECT entry FROM audit ORDER BY seq ASC').all().map((row) => JSON.parse(row.entry));
  output({ failure, retained, rows, pending: pending() });
}

if (mode === 'concurrent') {
  const id = String(process.env.AUDIT_WORKER_ID);
  const entries = appendBatch(`CONCURRENT_${id}`, 2);
  const result = db.verifyAuditChain();
  output({ entries: entries.map((entry) => entry.id), result });
}

throw new Error(`unsupported audit worker mode: ${mode}`);
