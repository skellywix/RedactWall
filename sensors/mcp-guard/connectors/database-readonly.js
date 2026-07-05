'use strict';
/**
 * SQLite read-only database connector for MCP runtimes.
 *
 * Executes bounded read-only SQLite queries, then routes the tabular result
 * through the MCP connector SDK before any model receives it.
 */
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');
const { connectorHealthCheck, sanitizeToolResult } = require('../sdk');

const DEFAULT_MAX_ROWS = 50;
const MAX_ROWS = 500;
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_SCOPES = ['readonly'];

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
  return new Database(configuredDatabasePath(opts), {
    readonly: true,
    fileMustExist: true,
  });
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
  const raw = fetchDatabaseRows(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'database_readonly',
    tool: 'query.readonly',
  }, opts.guardOptions || {});
}

async function sanitizeDatabaseSchema(args = {}, opts = {}) {
  const raw = fetchDatabaseSchema(args, opts);
  return sanitizeToolResult(raw, {
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
  fetchDatabaseSchema,
  rejectUnsafeSql,
  sanitizeDatabaseRows,
  sanitizeDatabaseSchema,
};
