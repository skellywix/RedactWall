'use strict';
/**
 * Microsoft 365 Graph file-content connector for MCP runtimes.
 *
 * Fetches text-readable driveItem content, then routes the result through the
 * MCP connector SDK before any model receives it.
 */
const { fetchWithTimeout } = require('../guard');
const { connectorHealthCheck, sanitizeToolResult } = require('../sdk');

const DEFAULT_GRAPH_ROOT = 'https://graph.microsoft.com/v1.0';
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_SCOPES = ['Files.Read'];
const TEXT_CONTENT_TYPES = [
  /^text\//i,
  /^application\/json\b/i,
  /^application\/xml\b/i,
  /^application\/xhtml\+xml\b/i,
  /^application\/csv\b/i,
];

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

function accessToken(opts = {}) {
  return compactLabel(opts.accessToken || envValue([
    'M365_GRAPH_ACCESS_TOKEN',
    'MICROSOFT_GRAPH_ACCESS_TOKEN',
  ], opts.env), '', 10000);
}

function normalizeGraphRoot(value = DEFAULT_GRAPH_ROOT) {
  const url = new URL(value || DEFAULT_GRAPH_ROOT);
  if (url.protocol !== 'https:') {
    throw new Error('Microsoft 365 Graph root must use https');
  }
  return url.toString().replace(/\/+$/, '');
}

function graphPathSegment(value, label) {
  const text = String(value == null ? '' : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) throw new Error(`Microsoft 365 ${label} is required`);
  if (text.length > 512) throw new Error(`Microsoft 365 ${label} is too long`);
  if (/[\\/]/.test(text)) throw new Error(`Microsoft 365 ${label} must be an opaque id`);
  return encodeURIComponent(text);
}

function buildDriveItemContentUrl(args = {}, opts = {}) {
  const root = normalizeGraphRoot(opts.graphRoot || DEFAULT_GRAPH_ROOT);
  const driveId = graphPathSegment(args.driveId || opts.driveId, 'driveId');
  const itemId = graphPathSegment(args.itemId || opts.itemId, 'itemId');
  return `${root}/drives/${driveId}/items/${itemId}/content`;
}

function headerValue(headers, name) {
  if (!headers) return '';
  if (typeof headers.get === 'function') return headers.get(name) || '';
  return headers[name] || headers[name.toLowerCase()] || '';
}

function responseContentType(response) {
  return compactLabel(headerValue(response.headers, 'content-type').split(';')[0], 'unknown', 80);
}

function responseContentLength(response) {
  const raw = headerValue(response.headers, 'content-length');
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function maxBytes(opts = {}) {
  const n = Number(opts.maxBytes ?? DEFAULT_MAX_BYTES);
  if (!Number.isFinite(n)) return DEFAULT_MAX_BYTES;
  return Math.max(1, Math.min(5 * 1024 * 1024, Math.floor(n)));
}

function isTextContentType(contentType, opts = {}) {
  if (opts.allowUnknownContentType && contentType === 'unknown') return true;
  const allowed = Array.isArray(opts.allowedContentTypes) && opts.allowedContentTypes.length
    ? opts.allowedContentTypes.map((item) => new RegExp(item, 'i'))
    : TEXT_CONTENT_TYPES;
  return allowed.some((pattern) => pattern.test(contentType));
}

async function readBoundedText(response, opts = {}) {
  const limit = maxBytes(opts);
  const declared = responseContentLength(response);
  if (declared != null && declared > limit) {
    throw new Error(`Microsoft 365 content exceeds ${limit} byte limit`);
  }

  if (response.body && typeof response.body.getReader === 'function') {
    const decoder = new TextDecoder();
    const reader = response.body.getReader();
    let total = 0;
    let text = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) throw new Error(`Microsoft 365 content exceeds ${limit} byte limit`);
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return { text, sizeBytes: total };
  }

  if (typeof response.arrayBuffer === 'function') {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > limit) throw new Error(`Microsoft 365 content exceeds ${limit} byte limit`);
    return { text: buffer.toString('utf8'), sizeBytes: buffer.length };
  }

  const text = typeof response.text === 'function' ? await response.text() : '';
  const size = Buffer.byteLength(text, 'utf8');
  if (size > limit) throw new Error(`Microsoft 365 content exceeds ${limit} byte limit`);
  return { text, sizeBytes: size };
}

function graphScopes(opts = {}) {
  if (Array.isArray(opts.scopes)) return opts.scopes.filter(Boolean).map((scope) => compactLabel(scope, '', 64));
  const raw = envValue(['M365_GRAPH_SCOPES', 'MICROSOFT_GRAPH_SCOPES'], opts.env);
  if (!raw) return DEFAULT_SCOPES;
  return raw.split(/[,\s]+/).map((scope) => compactLabel(scope, '', 64)).filter(Boolean);
}

function microsoft365ConnectorHealth(opts = {}, ok = true, detail = 'configured') {
  return connectorHealthCheck({
    id: 'Microsoft 365 Graph',
    tenantId: opts.tenantId || envValue(['M365_TENANT_ID', 'AZURE_TENANT_ID'], opts.env),
    scopes: graphScopes(opts),
  }, ok, detail);
}

async function fetchDriveItemContent(args = {}, opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Microsoft 365 access token is required');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');

  const response = await fetchWithTimeout(fetchImpl, buildDriveItemContentUrl(args, opts), {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'text/plain, application/json, application/xml, text/*;q=0.9, */*;q=0.1',
    },
  }, opts);

  if (!response || !response.ok) {
    const status = response && response.status ? response.status : 'unknown';
    throw new Error(`Microsoft 365 content fetch failed with HTTP ${status}`);
  }

  const contentType = responseContentType(response);
  if (!isTextContentType(contentType, opts)) {
    throw new Error(`Microsoft 365 content type is not text-readable: ${contentType}`);
  }

  const body = await readBoundedText(response, opts);
  return {
    content: [{ type: 'text', text: body.text }],
    structuredContent: {
      connector: 'microsoft365',
      operation: 'driveItem.getContent',
      contentType,
      sizeBytes: body.sizeBytes,
    },
  };
}

async function sanitizeDriveItemContent(args = {}, opts = {}) {
  const raw = await fetchDriveItemContent(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'microsoft365',
    tool: 'driveItem.getContent',
  }, opts.guardOptions || {});
}

function createDriveItemContentTool(opts = {}) {
  return async function microsoft365DriveItemContentTool(args) {
    const sanitized = await sanitizeDriveItemContent(args, opts);
    return sanitized.result;
  };
}

module.exports = {
  buildDriveItemContentUrl,
  createDriveItemContentTool,
  fetchDriveItemContent,
  graphScopes,
  microsoft365ConnectorHealth,
  sanitizeDriveItemContent,
};
