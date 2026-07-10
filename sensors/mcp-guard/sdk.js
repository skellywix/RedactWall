'use strict';
/**
 * Connector-facing MCP guard helpers.
 *
 * Connectors should use wrapConnectorTool() or executeConnectorTool() so tool
 * policy is checked before an upstream read or side effect, then every result
 * is sanitized before model delivery. The guard remains the policy/redaction
 * boundary; this file preserves MCP shapes and standardizes connector health.
 */
const {
  blockUninspectableToolResult,
  blockUnscannableToolResult,
  carriesUnscannableToolResult,
  guardToolArguments,
  guardToolRequest,
  guardToolResult,
} = require('./guard');

const MAX_LABEL = 80;
const MAX_DETAIL = 160;
const MAX_ARGUMENT_SCAN_CHARS = 200000;

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

/** Decode the small HTML entity set Graph/Confluence payloads actually emit. */
function decodeHtmlEntities(text) {
  return String(text || '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, code) => {
      const n = Number(code);
      return Number.isFinite(n) && n >= 32 && n <= 0xffff ? String.fromCharCode(n) : '';
    });
}

/** Strip markup from connector HTML into detector-ready plain text. */
function htmlToText(html) {
  return decodeHtmlEntities(String(html || '')
    .replace(/<\s*br\s*\/?>/gi, '\n')
    .replace(/<\s*\/p\s*>/gi, '\n')
    .replace(/<\s*\/div\s*>/gi, '\n')
    .replace(/<[^>]+>/g, ' '))
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function toolResultText(result) {
  if (result == null) return '';
  if (typeof result === 'string') return result;
  if (Buffer.isBuffer(result)) return result.toString('utf8');
  if (typeof result !== 'object') return String(result);
  // Scan the complete JSON envelope. Extracting only known text part shapes
  // can return an original object with unscanned URI, name, or vendor fields.
  return stringifySafe(result) || '';
}

// Return plain JSON data parsed from the one serialization that is scanned.
// Never return a structured connector object whose getters/toJSON can change.
function isOpaqueBinary(value) {
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return true;
  return typeof ArrayBuffer !== 'undefined'
    && (value instanceof ArrayBuffer || ArrayBuffer.isView(value));
}

function needsReplacementScan(holder, key, item) {
  if (typeof item === 'string' || isOpaqueBinary(item)) return true;
  if (!item || typeof item !== 'object') return false;
  const descriptor = Object.getOwnPropertyDescriptor(holder, key);
  return !descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')
    || descriptor.value !== item;
}

function trackSerializationPath(holder, item, ancestors) {
  if (!item || typeof item !== 'object') return;
  while (ancestors.length && ancestors[ancestors.length - 1] !== holder) ancestors.pop();
  if (ancestors.includes(item)) throw new TypeError('MCP tool result contains a cycle');
  ancestors.push(item);
}

function inspectToolResult(result) {
  if (typeof result === 'string') return { text: result, snapshot: result };
  let unscannable = false;
  const ancestors = [];
  const text = JSON.stringify(result, function inspectReplacement(key, item) {
    if (needsReplacementScan(this, key, item) && carriesUnscannableToolResult(item)) {
      unscannable = true;
      return null;
    }
    if (typeof item === 'bigint') return item.toString();
    trackSerializationPath(this, item, ancestors);
    return item;
  });
  if (typeof text !== 'string') throw new TypeError('MCP tool result is not serializable');
  return { text, snapshot: JSON.parse(text), unscannable };
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

async function sanitizeToolResultWithContext(result, contextForSnapshot, fallbackContext, opts) {
  let context = fallbackContext;
  try {
    const inspected = inspectToolResult(result);
    context = contextForSnapshot(inspected.snapshot);
    const unscannable = inspected.unscannable
      || carriesUnscannableToolResult(result)
      || carriesUnscannableToolResult(inspected.snapshot);
    const guarded = unscannable
      ? await blockUnscannableToolResult(context, opts)
      : await guardToolResult(inspected.text, context, opts);
    return sanitizedToolResult(inspected.snapshot, guarded);
  } catch (_) {
    return sanitizedToolResult(null, await blockUninspectableToolResult(context, opts), true);
  }
}

async function sanitizeToolResult(result, ctx = {}, opts = {}) {
  const context = connectorContext(ctx);
  return sanitizeToolResultWithContext(result, () => context, context, opts);
}

function sanitizedToolResult(original, guarded, forceStructured = false) {
  const result = forceStructured || guarded.blocked
    ? { content: [{ type: 'text', text: guarded.text }] }
    : (guarded.redacted ? redactedToolResult(original, guarded.text) : original);
  return {
    result,
    text: guarded.text,
    redacted: guarded.redacted,
    ...(guarded.blocked ? { blocked: true } : {}),
    findings: guarded.findings,
  };
}

function blockedConnectorResult(decision = {}) {
  const reason = trimString(decision.reason, 'MCP tool policy blocked execution', MAX_DETAIL);
  const text = `[BLOCKED: ${reason}]`;
  return {
    result: { content: [{ type: 'text', text }] },
    text,
    redacted: true,
    blocked: true,
    findings: ['MCP_TOOL_POLICY'],
  };
}

function connectorContexts(ctx, args) {
  const raw = typeof ctx === 'function' ? ctx(args) : ctx;
  const list = Array.isArray(raw) ? (raw.length ? raw : [undefined]) : [raw];
  const seen = new Set();
  return list.map(connectorContext).filter((context) => {
    if (seen.has(context.tool)) return false;
    seen.add(context.tool);
    return true;
  });
}

function resultContext(contexts, result) {
  const structured = result && result.structuredContent;
  const operation = structured && structured.operation;
  if (typeof operation !== 'string' || !operation) return contexts[0];
  return contexts.find((context) => (
    context.tool === operation || context.tool.endsWith(`.${operation}`)
  )) || contexts[0];
}

function argumentScanText(value) {
  const parts = [];
  let length = 0;
  function add(item) {
    const text = String(item);
    length += text.length + 1;
    if (length > MAX_ARGUMENT_SCAN_CHARS) throw new RangeError('MCP tool arguments exceed the scan limit');
    parts.push(text);
  }
  function visit(item, depth) {
    if (depth > 64) throw new RangeError('MCP tool arguments exceed the nesting limit');
    if (typeof item === 'string' || typeof item === 'number' || typeof item === 'bigint') {
      add(item);
      return;
    }
    if (!item || typeof item !== 'object') return;
    if (Array.isArray(item)) {
      for (const child of item) visit(child, depth + 1);
      return;
    }
    for (const key of Object.keys(item)) {
      add(key);
      visit(item[key], depth + 1);
    }
  }
  visit(value, 0);
  return parts.join('\n');
}

async function executeConnectorTool(handler, args, ctx = {}, opts = {}) {
  if (typeof handler !== 'function') throw new TypeError('handler must be a function');
  const fallbackContext = connectorContext(typeof ctx === 'function' ? {} : ctx);
  let inspected;
  let contexts;
  try {
    inspected = inspectToolResult(args == null ? {} : args);
    contexts = connectorContexts(ctx, inspected.snapshot);
  } catch (_) {
    return blockedConnectorResult({ reason: 'MCP tool arguments could not be safely inspected' });
  }
  for (const context of contexts) {
    const decision = await guardToolRequest(context, opts);
    if (!decision.allowed) return blockedConnectorResult(decision);
  }
  let scanText;
  try {
    scanText = argumentScanText(inspected.snapshot);
  } catch (_) {
    return blockedConnectorResult({ reason: 'MCP tool arguments could not be safely inspected' });
  }
  const unscannable = inspected.unscannable || carriesUnscannableToolResult(inspected.snapshot);
  const argumentDecision = await guardToolArguments(
    scanText,
    contexts[0] || fallbackContext,
    opts,
    { unscannable },
  );
  if (!argumentDecision.allowed) return blockedConnectorResult(argumentDecision);
  const result = await handler(inspected.snapshot);
  return sanitizeToolResultWithContext(
    result,
    (snapshot) => resultContext(contexts, snapshot),
    contexts[0],
    opts,
  );
}

function wrapConnectorTool(handler, ctx = {}, opts = {}) {
  if (typeof handler !== 'function') throw new TypeError('handler must be a function');
  return async function guardedConnectorTool(args) {
    const sanitized = await executeConnectorTool(handler, args, ctx, opts);
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
  decodeHtmlEntities,
  executeConnectorTool,
  htmlToText,
  sanitizeToolResult,
  toolResultText,
  wrapConnectorTool,
};
