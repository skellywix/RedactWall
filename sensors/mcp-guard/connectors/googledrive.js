'use strict';
/**
 * Google Drive file-content connector for MCP runtimes.
 *
 * Fetches text-readable Drive file content (via files.get?alt=media, or the
 * Docs/Sheets export endpoints), then routes the result through the MCP
 * connector SDK before any model receives it — the same sanitize-before-model
 * contract as the Microsoft 365 connector. Bounded read, https-only, text
 * content types only.
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
];
// Native Google editor types export to a text-readable MIME rather than stream raw.
const EXPORT_MIME = {
  'application/vnd.google-apps.document': 'text/plain',
  'application/vnd.google-apps.spreadsheet': 'text/csv',
  'application/vnd.google-apps.presentation': 'text/plain',
};

function compactLabel(value, fallback = '', max = 120) {
  return String(value == null ? fallback : value).replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

function envValue(names, env = process.env) {
  for (const name of names) {
    const value = env[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function accessToken(opts = {}) {
  return compactLabel(opts.accessToken || envValue(['GOOGLE_DRIVE_ACCESS_TOKEN', 'GOOGLE_OAUTH_ACCESS_TOKEN'], opts.env), '', 10000);
}

function normalizeDriveRoot(value = DEFAULT_DRIVE_ROOT) {
  const url = new URL(value || DEFAULT_DRIVE_ROOT);
  if (url.protocol !== 'https:') throw new Error('Google Drive root must use https');
  return url.toString().replace(/\/+$/, '');
}

function fileIdSegment(value) {
  const text = compactLabel(value, '', 512);
  if (!text) throw new Error('Google Drive fileId is required');
  if (/[\\/]/.test(text)) throw new Error('Google Drive fileId must be an opaque id');
  return encodeURIComponent(text);
}

// files.get with alt=media for binary/text files; files.export for native docs.
function buildFileContentUrl(args = {}, opts = {}) {
  const root = normalizeDriveRoot(opts.driveRoot || DEFAULT_DRIVE_ROOT);
  const fileId = fileIdSegment(args.fileId || opts.fileId);
  const nativeMime = args.mimeType && EXPORT_MIME[args.mimeType];
  if (nativeMime) {
    return `${root}/files/${fileId}/export?mimeType=${encodeURIComponent(nativeMime)}`;
  }
  return `${root}/files/${fileId}?alt=media`;
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
  const n = Number(headerValue(response.headers, 'content-length'));
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
  if (declared != null && declared > limit) throw new Error(`Google Drive content exceeds ${limit} byte limit`);
  if (response.body && typeof response.body.getReader === 'function') {
    const decoder = new TextDecoder();
    const reader = response.body.getReader();
    let total = 0; let text = '';
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
  if (Array.isArray(opts.scopes)) return opts.scopes.filter(Boolean).map((s) => compactLabel(s, '', 96));
  const raw = envValue(['GOOGLE_DRIVE_SCOPES'], opts.env);
  if (!raw) return DEFAULT_SCOPES;
  return raw.split(/[,\s]+/).map((s) => compactLabel(s, '', 96)).filter(Boolean);
}

function googleDriveConnectorHealth(opts = {}, ok = true, detail = 'configured') {
  return connectorHealthCheck({ id: 'Google Drive', scopes: driveScopes(opts) }, ok, detail);
}

async function fetchFileContent(args = {}, opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Google Drive access token is required');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');

  const response = await fetchWithTimeout(fetchImpl, buildFileContentUrl(args, opts), {
    headers: { Authorization: `Bearer ${token}`, Accept: 'text/plain, application/json, text/*;q=0.9, */*;q=0.1' },
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
    structuredContent: { connector: 'googledrive', operation: 'files.getContent', contentType, sizeBytes: body.sizeBytes },
  };
}

async function sanitizeFileContent(args = {}, opts = {}) {
  const raw = await fetchFileContent(args, opts);
  return sanitizeToolResult(raw, { agent: opts.agent, connector: 'googledrive', tool: 'files.getContent' }, opts.guardOptions || {});
}

function createFileContentTool(opts = {}) {
  return async function googleDriveFileContentTool(args) {
    const sanitized = await sanitizeFileContent(args, opts);
    return sanitized.result;
  };
}

module.exports = {
  buildFileContentUrl,
  createFileContentTool,
  fetchFileContent,
  driveScopes,
  googleDriveConnectorHealth,
  sanitizeFileContent,
  EXPORT_MIME,
};
