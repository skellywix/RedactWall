'use strict';
/**
 * Microsoft 365 Graph content connector for MCP runtimes.
 *
 * Fetches text-readable driveItem content, SharePoint site page text, and
 * SharePoint list item fields, then routes every result through the MCP
 * connector SDK before any model receives it.
 */
const { fetchWithTimeout } = require('../guard');
const { connectorHealthCheck, htmlToText, sanitizeToolResult } = require('../sdk');

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

function graphSiteId(value) {
  const text = String(value == null ? '' : value).trim();
  if (!text) throw new Error('Microsoft 365 siteId is required');
  if (text.length > 512) throw new Error('Microsoft 365 siteId is too long');
  if (!/^[A-Za-z0-9._,-]+$/.test(text) || !/[A-Za-z0-9]/.test(text)) {
    throw new Error('Microsoft 365 siteId contains unsupported characters');
  }
  return text;
}

function graphResourceId(value, label) {
  const text = String(value == null ? '' : value).trim();
  if (!text) throw new Error(`Microsoft 365 ${label} is required`);
  if (!/^(?:\d{1,32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.test(text)) {
    throw new Error(`Microsoft 365 ${label} must be a numeric or GUID id`);
  }
  return text;
}

function buildSitePageUrl(args = {}, opts = {}) {
  const root = normalizeGraphRoot(opts.graphRoot || DEFAULT_GRAPH_ROOT);
  const siteId = graphSiteId(args.siteId || opts.siteId);
  const pageId = graphResourceId(args.pageId || opts.pageId, 'pageId');
  return `${root}/sites/${siteId}/pages/${pageId}/microsoft.graph.sitePage?$expand=canvasLayout`;
}

function buildListItemUrl(args = {}, opts = {}) {
  const root = normalizeGraphRoot(opts.graphRoot || DEFAULT_GRAPH_ROOT);
  const siteId = graphSiteId(args.siteId || opts.siteId);
  const listId = graphResourceId(args.listId || opts.listId, 'listId');
  const itemId = graphResourceId(args.itemId || opts.itemId, 'itemId');
  return `${root}/sites/${siteId}/lists/${listId}/items/${itemId}?$expand=fields`;
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

function microsoft365ConnectorHealth(opts = {}, ok = true,
  detail = 'configured: driveItem.getContent sites.page.get sites.listItem.get') {
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

async function fetchGraphJson(url, operation, opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Microsoft 365 access token is required');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');

  const response = await fetchWithTimeout(fetchImpl, url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  }, opts);

  if (!response || !response.ok) {
    const status = response && response.status ? response.status : 'unknown';
    throw new Error(`Microsoft 365 ${operation} failed with HTTP ${status}`);
  }
  const body = await readBoundedText(response, opts);
  const parsed = JSON.parse(body.text || '{}');
  if (parsed && parsed.error) {
    const code = compactLabel(parsed.error.code || 'graph_error', 'graph_error', 80);
    throw new Error(`Microsoft 365 ${operation} failed: ${code}`);
  }
  return parsed || {};
}

function canvasWebParts(canvasLayout) {
  const layout = canvasLayout && typeof canvasLayout === 'object' ? canvasLayout : {};
  const sections = Array.isArray(layout.horizontalSections) ? layout.horizontalSections : [];
  const webParts = [];
  for (const section of sections) {
    const columns = Array.isArray(section && section.columns) ? section.columns : [];
    for (const column of columns) {
      if (Array.isArray(column && column.webparts)) webParts.push(...column.webparts);
    }
  }
  if (layout.verticalSection && Array.isArray(layout.verticalSection.webparts)) {
    webParts.push(...layout.verticalSection.webparts);
  }
  return webParts;
}

function sitePageToText(page = {}, webParts = canvasWebParts(page.canvasLayout)) {
  const title = compactLabel(page.title, '', 240);
  const parts = title ? [`Title: ${title}`] : [];
  for (const webPart of webParts) {
    if (!webPart || typeof webPart.innerHtml !== 'string') continue;
    const text = htmlToText(webPart.innerHtml);
    if (text) parts.push(text);
  }
  return parts.join('\n\n').trim();
}

function includedListItemField(key, value) {
  if (typeof key !== 'string' || !key) return false;
  if (/^@odata/i.test(key) || /^(?:id|contenttype|edit)$/i.test(key) || /^linktitle/i.test(key)) return false;
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function listItemFieldLines(fields) {
  const source = fields && typeof fields === 'object' ? fields : {};
  const lines = [];
  for (const [key, value] of Object.entries(source)) {
    if (!includedListItemField(key, value)) continue;
    lines.push(`${compactLabel(key, '', 80)}: ${compactLabel(value, '', 4000)}`);
  }
  return lines;
}

function boundedConnectorText(text, label, opts = {}) {
  const safe = String(text || '').trim() || `[No Microsoft 365 ${label} content returned]`;
  const sizeBytes = Buffer.byteLength(safe, 'utf8');
  const limit = maxBytes(opts);
  if (sizeBytes > limit) throw new Error(`Microsoft 365 ${label} content exceeds ${limit} byte limit`);
  return { text: safe, sizeBytes };
}

async function fetchSitePageContent(args = {}, opts = {}) {
  const page = await fetchGraphJson(buildSitePageUrl(args, opts), 'sites.page.get', opts);
  const webParts = canvasWebParts(page.canvasLayout);
  const text = boundedConnectorText(sitePageToText(page, webParts), 'site page', opts);
  return {
    content: [{ type: 'text', text: text.text }],
    structuredContent: {
      connector: 'microsoft365',
      operation: 'sites.page.get',
      contentType: 'text/plain',
      sizeBytes: text.sizeBytes,
      webPartCount: webParts.length,
    },
  };
}

async function fetchListItemFields(args = {}, opts = {}) {
  const item = await fetchGraphJson(buildListItemUrl(args, opts), 'sites.listItem.get', opts);
  const lines = listItemFieldLines(item.fields);
  const text = boundedConnectorText(lines.join('\n'), 'list item', opts);
  return {
    content: [{ type: 'text', text: text.text }],
    structuredContent: {
      connector: 'microsoft365',
      operation: 'sites.listItem.get',
      contentType: 'text/plain',
      sizeBytes: text.sizeBytes,
      fieldCount: lines.length,
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

async function sanitizeSitePageContent(args = {}, opts = {}) {
  const raw = await fetchSitePageContent(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'microsoft365',
    tool: 'sites.page.get',
  }, opts.guardOptions || {});
}

async function sanitizeListItemFields(args = {}, opts = {}) {
  const raw = await fetchListItemFields(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'microsoft365',
    tool: 'sites.listItem.get',
  }, opts.guardOptions || {});
}

function createDriveItemContentTool(opts = {}) {
  return async function microsoft365DriveItemContentTool(args) {
    const sanitized = await sanitizeDriveItemContent(args, opts);
    return sanitized.result;
  };
}

function createSitePageContentTool(opts = {}) {
  return async function microsoft365SitePageContentTool(args) {
    const sanitized = await sanitizeSitePageContent(args, opts);
    return sanitized.result;
  };
}

function createListItemFieldsTool(opts = {}) {
  return async function microsoft365ListItemFieldsTool(args) {
    const sanitized = await sanitizeListItemFields(args, opts);
    return sanitized.result;
  };
}

module.exports = {
  buildDriveItemContentUrl,
  buildListItemUrl,
  buildSitePageUrl,
  createDriveItemContentTool,
  createListItemFieldsTool,
  createSitePageContentTool,
  fetchDriveItemContent,
  fetchListItemFields,
  fetchSitePageContent,
  graphScopes,
  microsoft365ConnectorHealth,
  sanitizeDriveItemContent,
  sanitizeListItemFields,
  sanitizeSitePageContent,
};
