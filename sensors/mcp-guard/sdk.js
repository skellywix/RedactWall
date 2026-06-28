'use strict';
/**
 * Connector-facing MCP guard helpers.
 *
 * Connectors should call sanitizeToolResult() on every tool response before the
 * result is returned to the model. The guard remains the redaction boundary;
 * this file only preserves useful MCP result shapes and standardizes connector
 * health evidence.
 */
const { guardToolResult } = require('./guard');

const MAX_LABEL = 80;
const MAX_DETAIL = 160;

function trimString(value, fallback = '', max = MAX_LABEL) {
  const text = String(value == null ? fallback : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return text.slice(0, max);
}

function normalizeCheckId(value) {
  const base = trimString(value, 'unknown', 96)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return (`mcp_connector_${base || 'unknown'}`).slice(0, MAX_LABEL);
}

function redactOperationalDetail(value) {
  return trimString(value, '', MAX_DETAIL)
    .replace(/\b(token|secret|key|password|bearer)\b\s*[:=]?\s*[A-Za-z0-9._+/=-]{4,}/gi, '$1 [redacted]')
    .replace(/\b[A-Za-z0-9._+/=-]{32,}\b/g, '[redacted]');
}

function stringifySafe(value) {
  const seen = new WeakSet();
  return JSON.stringify(value, (key, item) => {
    if (typeof item === 'bigint') return item.toString();
    if (item && typeof item === 'object') {
      if (seen.has(item)) return '[Circular]';
      seen.add(item);
    }
    return item;
  });
}

function contentTextParts(content = []) {
  return content
    .map((item) => {
      if (!item || typeof item !== 'object') return '';
      if (typeof item.text === 'string') return item.text;
      if (item.resource && typeof item.resource.text === 'string') return item.resource.text;
      return '';
    })
    .filter(Boolean);
}

function toolResultText(result) {
  if (result == null) return '';
  if (typeof result === 'string') return result;
  if (Buffer.isBuffer(result)) return result.toString('utf8');
  if (typeof result !== 'object') return String(result);

  const parts = Array.isArray(result.content) ? contentTextParts(result.content) : [];
  if (Array.isArray(result.content)) {
    const envelope = { ...result };
    delete envelope.content;
    if (Object.keys(envelope).length) parts.push(stringifySafe(envelope));
  }
  if (parts.length) return parts.join('\n\n');
  return stringifySafe(result) || '';
}

function redactedToolResult(original, safeText) {
  const content = [{ type: 'text', text: safeText }];
  if (typeof original === 'string' || Buffer.isBuffer(original)) return safeText;
  if (!original || typeof original !== 'object') return safeText;
  if (Array.isArray(original.content)) {
    const result = { content };
    if (original.isError === true) result.isError = true;
    return result;
  }
  if (typeof original.text === 'string') return { text: safeText };
  return { content };
}

function connectorContext(ctx = {}) {
  const agent = trimString(ctx.agent || ctx.user, 'mcp-agent');
  const connector = trimString(ctx.connector || ctx.connectorId || ctx.name, '');
  const tool = trimString(ctx.tool || ctx.operation || ctx.action, '');
  const destination = connector && tool && !tool.startsWith(`${connector}.`)
    ? `${connector}.${tool}`
    : (tool || connector || 'mcp-tool');
  return {
    agent,
    tool: trimString(destination, 'mcp-tool'),
  };
}

async function sanitizeToolResult(result, ctx = {}, opts = {}) {
  const text = toolResultText(result);
  const guarded = await guardToolResult(text, connectorContext(ctx), opts);
  return {
    result: guarded.redacted ? redactedToolResult(result, guarded.text) : result,
    text: guarded.text,
    redacted: guarded.redacted,
    findings: guarded.findings,
  };
}

function wrapConnectorTool(handler, ctx = {}, opts = {}) {
  if (typeof handler !== 'function') throw new TypeError('handler must be a function');
  return async function guardedConnectorTool(args) {
    const result = await handler(args);
    const context = typeof ctx === 'function' ? ctx(args) : ctx;
    const sanitized = await sanitizeToolResult(result, context, opts);
    return sanitized.result;
  };
}

function connectorHealthCheck(connector = {}, ok = false, detail = '') {
  const name = trimString(connector.id || connector.name || connector.connector, 'unknown');
  const tenant = trimString(connector.tenantId || connector.tenant || '', '');
  const scopes = Array.isArray(connector.scopes)
    ? connector.scopes.map((scope) => trimString(scope, '', 48)).filter(Boolean)
    : [];
  const parts = [name];
  if (tenant) parts.push(`tenant:${tenant}`);
  if (scopes.length) parts.push(`scopes:${scopes.length}`);
  const safeDetail = redactOperationalDetail(detail);
  if (safeDetail) parts.push(safeDetail);
  return {
    id: normalizeCheckId(name),
    ok: ok === true,
    detail: trimString(parts.join(' | '), ok ? 'ok' : 'attention', MAX_DETAIL),
  };
}

module.exports = {
  connectorContext,
  connectorHealthCheck,
  sanitizeToolResult,
  toolResultText,
  wrapConnectorTool,
};
