'use strict';
/**
 * SQLite read-only database connector for MCP runtimes.
 *
 * Executes bounded read-only SQLite queries, then routes the tabular result
 * through the MCP connector SDK before any model receives it.
 */
const crypto = require('crypto');
const path = require('path');
const { fork } = require('child_process');
const Database = require('better-sqlite3');
const { connectorHealthCheck, executeConnectorTool } = require('../sdk');

const DEFAULT_MAX_ROWS = 50;
const MAX_ROWS = 500;
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_SCOPES = ['readonly'];
const DEFAULT_QUERY_TIMEOUT_MS = 1000;
const DEFAULT_QUERY_MEMORY_BYTES = 32 * 1024 * 1024;
const CHILD_V8_HEAP_MB = 64;
const MAX_CONCURRENT_QUERIES = 4;
let activeQueryWorkers = 0;

function compactLabel(value, fallback = '', max = 120) {
  return String(value == null ? fallback : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function envValue(names, env = process.env) {
  for (const name of names) {
    const value = env[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function maxRows(value) {
  const n = Number(value == null ? DEFAULT_MAX_ROWS : value);
  if (!Number.isFinite(n)) return DEFAULT_MAX_ROWS;
  return Math.max(1, Math.min(MAX_ROWS, Math.floor(n)));
}

function maxBytes(opts = {}) {
  const n = Number(opts.maxBytes ?? DEFAULT_MAX_BYTES);
  if (!Number.isFinite(n)) return DEFAULT_MAX_BYTES;
  return Math.max(1, Math.min(5 * 1024 * 1024, Math.floor(n)));
}

function databaseLabel(opts = {}) {
  return compactLabel(opts.label || opts.databaseLabel || envValue(['MCP_DATABASE_LABEL', 'DATABASE_READONLY_LABEL'], opts.env), 'read-only-db', 80);
}

function databaseScopes(opts = {}) {
  if (Array.isArray(opts.scopes)) return opts.scopes.filter(Boolean).map((scope) => compactLabel(scope, '', 64));
  const raw = envValue(['MCP_DATABASE_SCOPES', 'DATABASE_READONLY_SCOPES'], opts.env);
  if (!raw) return DEFAULT_SCOPES;
  return raw.split(/[,\s]+/).map((scope) => compactLabel(scope, '', 64)).filter(Boolean);
}

function databaseReadonlyConnectorHealth(opts = {}, ok = true, detail = 'configured') {
  return connectorHealthCheck({
    id: 'Database Read-Only',
    tenantId: databaseLabel(opts),
    scopes: databaseScopes(opts),
  }, ok, detail);
}

function databasePathFromDsn(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (/^sqlite:\/\//i.test(raw)) {
    const withoutScheme = raw.replace(/^sqlite:\/\//i, '');
    return decodeURIComponent(withoutScheme.replace(/^\/([A-Za-z]:)/, '$1'));
  }
  if (/^file:/i.test(raw)) {
    const url = new URL(raw);
    if (url.searchParams.has('mode') && url.searchParams.get('mode') !== 'ro') {
      throw new Error('Database connector requires read-only SQLite mode');
    }
    return decodeURIComponent(url.pathname.replace(/^\/([A-Za-z]:)/, '$1'));
  }
  if (/^[A-Za-z]:[\\/]/.test(raw) || raw.startsWith('/') || raw.startsWith('\\\\')) return raw;
  throw new Error('Database connector supports sqlite://, file:, or absolute SQLite paths only');
}

function configuredDatabasePath(opts = {}) {
  const raw = opts.databasePath || opts.dsn || envValue(['MCP_DATABASE_DSN', 'DATABASE_READONLY_DSN'], opts.env);
  const resolved = databasePathFromDsn(raw);
  if (!resolved) throw new Error('Database read-only DSN is required');
  return path.resolve(resolved);
}

function rejectUnsafeSql(sql) {
  const text = String(sql || '').trim();
  if (!text) throw new Error('Database read-only query is required');
  if (text.length > 5000) throw new Error('Database read-only query is too long');
  if (/[;]/.test(text)) throw new Error('Database read-only query must be a single statement');
  if (/--|\/\*/.test(text)) throw new Error('Database read-only query must not include comments');
  if (!/^(select|with)\b/i.test(text)) throw new Error('Database connector only allows SELECT or WITH queries');
  const forbidden = /\b(insert|update|delete|replace|create|drop|alter|truncate|attach|detach|vacuum|reindex|analyze|begin|commit|rollback|savepoint|release)\b|\bpragma(?:\b|_)/i;
  if (forbidden.test(text)) throw new Error('Database read-only query contains a forbidden SQL operation');
  return text;
}

function openReadonlyDatabase(opts = {}) {
  const db = new Database(configuredDatabasePath(opts), {
    readonly: true,
    fileMustExist: true,
  });
  if (opts.hardHeapLimitBytes) db.pragma(`hard_heap_limit = ${Math.floor(opts.hardHeapLimitBytes)}`);
  return db;
}

function normalizeCell(value) {
  if (value == null) return null;
  if (Buffer.isBuffer(value)) return `[binary ${value.length} bytes]`;
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Date) return value.toISOString();
  return value;
}

function normalizeRows(rows = []) {
  return rows.map((row) => Object.fromEntries(
    Object.entries(row || {}).map(([key, value]) => [compactLabel(key, 'column', 80), normalizeCell(value)])
  ));
}

function queryHash(sql) {
  return crypto.createHash('sha256').update(String(sql || '')).digest('hex').slice(0, 16);
}

function queryTimeoutMs(opts = {}) {
  const value = Number(opts.queryTimeoutMs ?? opts.timeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS);
  if (!Number.isFinite(value)) return DEFAULT_QUERY_TIMEOUT_MS;
  return Math.max(10, Math.min(30000, Math.floor(value)));
}

function queryMemoryBytes(opts = {}) {
  const value = Number(opts.queryMemoryBytes ?? DEFAULT_QUERY_MEMORY_BYTES);
  if (!Number.isFinite(value)) return DEFAULT_QUERY_MEMORY_BYTES;
  return Math.max(8 * 1024 * 1024, Math.min(128 * 1024 * 1024, Math.floor(value)));
}

function workerQueryOptions(opts = {}) {
  if (opts.db) throw new Error('Database query budget requires a file-backed database');
  return {
    databasePath: configuredDatabasePath(opts),
    label: databaseLabel(opts),
    maxBytes: maxBytes(opts),
    maxRows: maxRows(opts.maxRows),
    hardHeapLimitBytes: queryMemoryBytes(opts),
  };
}

function workerQueryArgs(args = {}, opts = {}) {
  return {
    sql: rejectUnsafeSql(args.sql || args.query || opts.sql || opts.query),
    limit: maxRows(args.limit ?? args.maxRows ?? opts.limit ?? opts.maxRows),
  };
}

function workerQueryPromise(worker, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let outcome = null;
    let processClosed = false;
    let capacityReleased = false;
    let timer;
    const settleAfterExit = () => {
      processClosed = true;
      if (!capacityReleased) {
        capacityReleased = true;
        activeQueryWorkers = Math.max(0, activeQueryWorkers - 1);
      }
      if (settled) return;
      if (!outcome) outcome = { fn: reject, value: new Error('Database read-only query failed') };
      settled = true;
      outcome.fn(outcome.value);
    };
    const finish = (fn, value, terminate = false) => {
      if (outcome) return;
      outcome = { fn, value };
      clearTimeout(timer);
      if (terminate) worker.kill();
      if (processClosed) settleAfterExit();
    };
    timer = setTimeout(() => {
      const err = new Error(`Database read-only query exceeded ${timeoutMs} ms execution budget`);
      err.code = 'REDACTWALL_DATABASE_QUERY_TIMEOUT';
      finish(reject, err, true);
    }, timeoutMs);
    worker.once('message', (message) => message && message.ok
      ? finish(resolve, message.result, true)
      : finish(reject, new Error('Database read-only query failed'), true));
    worker.once('error', () => finish(reject, new Error('Database read-only query failed'), true));
    worker.once('exit', settleAfterExit);
    // A failed spawn may emit `error` and `close` without `exit`. `close`
    // proves the child has no remaining stdio/IPC resources and is the only
    // safe fallback for releasing that reserved capacity slot.
    worker.once('close', settleAfterExit);
    worker.send(payload, (err) => {
      if (err) finish(reject, new Error('Database read-only query failed'), true);
    });
  });
}

function fetchDatabaseRowsWithBudget(args = {}, opts = {}) {
  if (activeQueryWorkers >= MAX_CONCURRENT_QUERIES) {
    const err = new Error('Database read-only query capacity is busy');
    err.code = 'REDACTWALL_DATABASE_QUERY_BUSY';
    return Promise.reject(err);
  }
  const timeoutMs = queryTimeoutMs(opts);
  const safeOpts = workerQueryOptions(opts);
  const safeArgs = workerQueryArgs(args, opts);
  const forkImpl = opts.forkImpl || fork;
  const worker = forkImpl(path.join(__dirname, 'database-readonly-worker.js'), [], {
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    windowsHide: true,
    execArgv: [`--max-old-space-size=${CHILD_V8_HEAP_MB}`],
  });
  activeQueryWorkers += 1;
  return workerQueryPromise(worker, { args: safeArgs, opts: safeOpts }, timeoutMs);
}

function boundedJsonText(value, label, opts = {}) {
  const text = JSON.stringify(value, null, 2);
  const sizeBytes = Buffer.byteLength(text, 'utf8');
  const limit = maxBytes(opts);
  if (sizeBytes > limit) throw new Error(`Database ${label} exceeds ${limit} byte limit`);
  return { text, sizeBytes };
}

function fetchDatabaseRows(args = {}, opts = {}) {
  const sql = rejectUnsafeSql(args.sql || args.query || opts.sql || opts.query);
  const limit = maxRows(args.limit ?? args.maxRows ?? opts.limit ?? opts.maxRows);
  const db = opts.db || openReadonlyDatabase(opts);
  const close = !opts.db;
  try {
    const wrapped = `SELECT * FROM (${sql}) AS redactwall_readonly LIMIT ?`;
    const rows = normalizeRows(db.prepare(wrapped).all(limit + 1));
    const truncated = rows.length > limit;
    const visibleRows = truncated ? rows.slice(0, limit) : rows;
    const payload = {
      label: databaseLabel(opts),
      rows: visibleRows,
      truncated,
    };
    const body = boundedJsonText(payload, 'query result', opts);
    const columns = visibleRows[0] ? Object.keys(visibleRows[0]).length : 0;
    return {
      content: [{ type: 'text', text: body.text }],
      structuredContent: {
        connector: 'database_readonly',
        operation: 'query.readonly',
        contentType: 'application/json',
        sizeBytes: body.sizeBytes,
        rowCount: visibleRows.length,
        columnCount: columns,
        truncated,
        queryHash: queryHash(sql),
      },
    };
  } finally {
    if (close) db.close();
  }
}

function fetchDatabaseSchema(args = {}, opts = {}) {
  const limit = maxRows(args.limit ?? args.maxRows ?? opts.limit ?? opts.maxRows);
  const db = opts.db || openReadonlyDatabase(opts);
  const close = !opts.db;
  try {
    const objects = db.prepare(`
      SELECT type, name
      FROM sqlite_master
      WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
      ORDER BY type, name
      LIMIT ?
    `).all(limit + 1);
    const rows = objects.slice(0, limit).map((object) => {
      const columns = db.prepare('SELECT name, type, "notnull" AS not_null, pk FROM pragma_table_info(?)').all(object.name)
        .map((column) => ({
          name: compactLabel(column.name, 'column', 80),
          type: compactLabel(column.type, 'unknown', 40),
          notNull: column.not_null === 1,
          primaryKey: column.pk === 1,
        }));
      return {
        type: compactLabel(object.type, 'table', 20),
        name: compactLabel(object.name, 'table', 80),
        columns,
      };
    });
    const payload = {
      label: databaseLabel(opts),
      objects: rows,
      truncated: objects.length > limit,
    };
    const body = boundedJsonText(payload, 'schema result', opts);
    return {
      content: [{ type: 'text', text: body.text }],
      structuredContent: {
        connector: 'database_readonly',
        operation: 'schema.readonly',
        contentType: 'application/json',
        sizeBytes: body.sizeBytes,
        objectCount: rows.length,
        truncated: objects.length > limit,
      },
    };
  } finally {
    if (close) db.close();
  }
}

async function sanitizeDatabaseRows(args = {}, opts = {}) {
  return executeConnectorTool((toolArgs) => fetchDatabaseRowsWithBudget(toolArgs, opts), args, {
    agent: opts.agent,
    connector: 'database_readonly',
    tool: 'query.readonly',
  }, opts.guardOptions || {});
}

async function sanitizeDatabaseSchema(args = {}, opts = {}) {
  return executeConnectorTool((toolArgs) => fetchDatabaseSchema(toolArgs, opts), args, {
    agent: opts.agent,
    connector: 'database_readonly',
    tool: 'schema.readonly',
  }, opts.guardOptions || {});
}

function createDatabaseReadonlyQueryTool(opts = {}) {
  return async function databaseReadonlyQueryTool(args) {
    const sanitized = await sanitizeDatabaseRows(args, opts);
    return sanitized.result;
  };
}

function createDatabaseSchemaTool(opts = {}) {
  return async function databaseSchemaTool(args) {
    const sanitized = await sanitizeDatabaseSchema(args, opts);
    return sanitized.result;
  };
}

module.exports = {
  createDatabaseReadonlyQueryTool,
  createDatabaseSchemaTool,
  databasePathFromDsn,
  databaseReadonlyConnectorHealth,
  databaseScopes,
  fetchDatabaseRows,
  fetchDatabaseRowsWithBudget,
  fetchDatabaseSchema,
  rejectUnsafeSql,
  sanitizeDatabaseRows,
  sanitizeDatabaseSchema,
};
