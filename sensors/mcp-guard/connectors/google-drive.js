'use strict';
/**
 * Google Drive file-content connector for MCP runtimes.
 *
 * Fetches Drive blob files or exports Google Workspace documents, then routes
 * the result through the MCP connector SDK before any model receives it.
 */
const { fetchWithTimeout } = require('../guard');
const { connectorHealthCheck, sanitizeToolResult } = require('../sdk');

const DEFAULT_DRIVE_ROOT = 'https://www.googleapis.com/drive/v3';
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_SCOPES = ['https://www.googleapis.com/auth/drive.readonly'];
const TEXT_CONTENT_TYPES = [
  /^text\//i,
  /^application\/json\b/i,
  /^application\/xml\b/i,
  /^application\/xhtml\+xml\b/i,
  /^application\/csv\b/i,
  /^image\/svg\+xml\b/i,
];
const WORKSPACE_EXPORT_TYPES = {
  'application/vnd.google-apps.document': 'text/plain',
  'application/vnd.google-apps.presentation': 'text/plain',
  'application/vnd.google-apps.spreadsheet': 'text/csv',
  'application/vnd.google-apps.drawing': 'image/svg+xml',
};

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
  return compactLabel(opts.accessToken || opts.token || envValue([
    'GOOGLE_DRIVE_ACCESS_TOKEN',
    'GOOGLE_WORKSPACE_ACCESS_TOKEN',
  ], opts.env), '', 10000);
}

function normalizeDriveRoot(value = DEFAULT_DRIVE_ROOT) {
  const url = new URL(value || DEFAULT_DRIVE_ROOT);
  if (url.protocol !== 'https:') {
    throw new Error('Google Drive API root must use https');
  }
  return url.toString().replace(/\/+$/, '');
}

function drivePathSegment(value, label) {
  const text = String(value == null ? '' : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) throw new Error(`Google Drive ${label} is required`);
  if (text.length > 512) throw new Error(`Google Drive ${label} is too long`);
  if (/[\\/]/.test(text)) throw new Error(`Google Drive ${label} must be an opaque id`);
  return encodeURIComponent(text);
}

function buildDriveFileMetadataUrl(args = {}, opts = {}) {
  const root = normalizeDriveRoot(opts.driveRoot || DEFAULT_DRIVE_ROOT);
  const fileId = drivePathSegment(args.fileId || opts.fileId, 'fileId');
  return `${root}/files/${fileId}?fields=id,mimeType,name,size,modifiedTime`;
}

function buildDriveFileMediaUrl(args = {}, opts = {}) {
  const root = normalizeDriveRoot(opts.driveRoot || DEFAULT_DRIVE_ROOT);
  const fileId = drivePathSegment(args.fileId || opts.fileId, 'fileId');
  return `${root}/files/${fileId}?alt=media`;
}

function buildDriveFileExportUrl(args = {}, opts = {}) {
  const root = normalizeDriveRoot(opts.driveRoot || DEFAULT_DRIVE_ROOT);
  const fileId = drivePathSegment(args.fileId || opts.fileId, 'fileId');
  const exportMimeType = compactLabel(args.exportMimeType || opts.exportMimeType || exportMimeTypeFor(args.mimeType || opts.mimeType), 'text/plain', 120);
  return `${root}/files/${fileId}/export?mimeType=${encodeURIComponent(exportMimeType)}`;
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

function isWorkspaceMimeType(mimeType) {
  return /^application\/vnd\.google-apps\./i.test(String(mimeType || ''));
}

function exportMimeTypeFor(mimeType, fallback = 'text/plain') {
  const normalized = String(mimeType || '').toLowerCase();
  return WORKSPACE_EXPORT_TYPES[normalized] || fallback;
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
    throw new Error(`Google Drive content exceeds ${limit} byte limit`);
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
      if (total > limit) throw new Error(`Google Drive content exceeds ${limit} byte limit`);
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return { text, sizeBytes: total };
  }

  if (typeof response.arrayBuffer === 'function') {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > limit) throw new Error(`Google Drive content exceeds ${limit} byte limit`);
    return { text: buffer.toString('utf8'), sizeBytes: buffer.length };
  }

  const text = typeof response.text === 'function' ? await response.text() : '';
  const size = Buffer.byteLength(text, 'utf8');
  if (size > limit) throw new Error(`Google Drive content exceeds ${limit} byte limit`);
  return { text, sizeBytes: size };
}

function driveScopes(opts = {}) {
  if (Array.isArray(opts.scopes)) return opts.scopes.filter(Boolean).map((scope) => compactLabel(scope, '', 96));
  const raw = envValue(['GOOGLE_DRIVE_SCOPES', 'GOOGLE_WORKSPACE_SCOPES'], opts.env);
  if (!raw) return DEFAULT_SCOPES;
  return raw.split(/[,\s]+/).map((scope) => compactLabel(scope, '', 96)).filter(Boolean);
}

function googleTenant(opts = {}) {
  return compactLabel(opts.customerId || opts.workspaceDomain || envValue([
    'GOOGLE_WORKSPACE_CUSTOMER_ID',
    'GOOGLE_WORKSPACE_DOMAIN',
  ], opts.env), '', 120);
}

function googleDriveConnectorHealth(opts = {}, ok = true, detail = 'configured') {
  return connectorHealthCheck({
    id: 'Google Drive',
    tenantId: googleTenant(opts),
    scopes: driveScopes(opts),
  }, ok, detail);
}

async function fetchJson(url, opts = {}) {
  const response = await fetchWithTimeout(opts.fetchImpl, url, {
    headers: {
      Authorization: `Bearer ${opts.token}`,
      Accept: 'application/json',
    },
  }, opts);
  if (!response || !response.ok) {
    const status = response && response.status ? response.status : 'unknown';
    throw new Error(`Google Drive metadata fetch failed with HTTP ${status}`);
  }
  if (typeof response.json === 'function') return response.json();
  const body = await readBoundedText(response, { ...opts, maxBytes: Math.min(maxBytes(opts), 64 * 1024) });
  return JSON.parse(body.text || '{}');
}

async function driveFileMetadata(args = {}, opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Google Drive access token is required');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');
  return fetchJson(buildDriveFileMetadataUrl(args, opts), { ...opts, fetchImpl, token });
}

async function fetchDriveFileContent(args = {}, opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Google Drive access token is required');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');

  let metadata = null;
  if (opts.fetchMetadata !== false && !args.mimeType && !opts.mimeType && !args.exportMimeType && !opts.exportMimeType) {
    metadata = await driveFileMetadata(args, { ...opts, token, fetchImpl });
  }
  const mimeType = compactLabel(args.mimeType || opts.mimeType || (metadata && metadata.mimeType), '', 120);
  const useExport = Boolean(args.exportMimeType || opts.exportMimeType || isWorkspaceMimeType(mimeType));
  const url = useExport
    ? buildDriveFileExportUrl({ ...args, mimeType }, opts)
    : buildDriveFileMediaUrl(args, opts);

  const response = await fetchWithTimeout(fetchImpl, url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: useExport
        ? 'text/plain, text/csv, text/*;q=0.9, */*;q=0.1'
        : 'text/plain, application/json, application/xml, text/*;q=0.9, */*;q=0.1',
    },
  }, opts);

  if (!response || !response.ok) {
    const status = response && response.status ? response.status : 'unknown';
    throw new Error(`Google Drive content fetch failed with HTTP ${status}`);
  }

  const contentType = responseContentType(response);
  if (!isTextContentType(contentType, opts)) {
    throw new Error(`Google Drive content type is not text-readable: ${contentType}`);
  }

  const body = await readBoundedText(response, opts);
  return {
    content: [{ type: 'text', text: body.text }],
    structuredContent: {
      connector: 'google_drive',
      operation: useExport ? 'files.export' : 'files.get',
      contentType,
      sizeBytes: body.sizeBytes,
      transferMode: useExport ? 'export' : 'media',
      mimeType: mimeType || 'unknown',
    },
  };
}

async function sanitizeDriveFileContent(args = {}, opts = {}) {
  const raw = await fetchDriveFileContent(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'google_drive',
    tool: raw.structuredContent.operation,
  }, opts.guardOptions || {});
}

function createDriveFileContentTool(opts = {}) {
  return async function googleDriveFileContentTool(args) {
    const sanitized = await sanitizeDriveFileContent(args, opts);
    return sanitized.result;
  };
}

module.exports = {
  buildDriveFileExportUrl,
  buildDriveFileMediaUrl,
  buildDriveFileMetadataUrl,
  createDriveFileContentTool,
  driveFileMetadata,
  driveScopes,
  exportMimeTypeFor,
  fetchDriveFileContent,
  googleDriveConnectorHealth,
  isWorkspaceMimeType,
  sanitizeDriveFileContent,
};
