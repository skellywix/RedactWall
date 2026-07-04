'use strict';
/**
 * Slack connector for MCP runtimes.
 *
 * Fetches bounded Slack conversation history or text-readable Slack file
 * content, then routes the result through the MCP connector SDK before any
 * model receives it.
 */
const { fetchWithTimeout } = require('../guard');
const { connectorHealthCheck, sanitizeToolResult } = require('../sdk');

const DEFAULT_SLACK_ROOT = 'https://slack.com/api';
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_HISTORY_LIMIT = 15;
const MAX_HISTORY_LIMIT = 100;
const DEFAULT_SCOPES = ['channels:history', 'groups:history', 'files:read'];
const TEXT_CONTENT_TYPES = [
  /^text\//i,
  /^application\/json\b/i,
  /^application\/xml\b/i,
  /^application\/xhtml\+xml\b/i,
  /^application\/csv\b/i,
  /^image\/svg\+xml\b/i,
];
const SLACK_FILE_HOSTS = [
  'files.slack.com',
  'files.slack-edge.com',
  'slack-files.com',
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
  return compactLabel(opts.accessToken || opts.botToken || opts.token || envValue([
    'SLACK_BOT_TOKEN',
    'SLACK_CONNECTOR_TOKEN',
  ], opts.env), '', 10000);
}

function normalizeSlackRoot(value = DEFAULT_SLACK_ROOT) {
  const url = new URL(value || DEFAULT_SLACK_ROOT);
  if (url.protocol !== 'https:') {
    throw new Error('Slack API root must use https');
  }
  return url.toString().replace(/\/+$/, '');
}

function slackOpaqueId(value, label) {
  const text = String(value == null ? '' : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) throw new Error(`Slack ${label} is required`);
  if (text.length > 256) throw new Error(`Slack ${label} is too long`);
  if (/[\\/\s]/.test(text)) throw new Error(`Slack ${label} must be an opaque id`);
  return text;
}

function slackCursor(value) {
  const text = compactLabel(value, '', 4096);
  if (!text) return '';
  if (/[\r\n]/.test(text)) throw new Error('Slack cursor must be a single line');
  return text;
}

function slackTimestamp(value, label) {
  if (value == null || value === '') return '';
  const text = compactLabel(value, '', 40);
  if (!/^\d{1,16}(?:\.\d{1,8})?$/.test(text)) {
    throw new Error(`Slack ${label} must be a Slack timestamp`);
  }
  return text;
}

function historyLimit(value) {
  const n = Number(value == null ? DEFAULT_HISTORY_LIMIT : value);
  if (!Number.isFinite(n)) return DEFAULT_HISTORY_LIMIT;
  return Math.max(1, Math.min(MAX_HISTORY_LIMIT, Math.floor(n)));
}

function buildSlackApiUrl(method, params = {}, opts = {}) {
  const root = normalizeSlackRoot(opts.slackRoot || DEFAULT_SLACK_ROOT);
  const safeMethod = compactLabel(method, '', 80);
  if (!/^[a-z.]+$/i.test(safeMethod)) throw new Error('Slack API method is invalid');
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return `${root}/${safeMethod}${qs ? `?${qs}` : ''}`;
}

function buildConversationHistoryUrl(args = {}, opts = {}) {
  const params = {
    channel: slackOpaqueId(args.channel || args.channelId || opts.channel || opts.channelId, 'channel'),
    limit: historyLimit(args.limit ?? opts.limit),
  };
  const cursor = slackCursor(args.cursor || opts.cursor);
  const oldest = slackTimestamp(args.oldest || opts.oldest, 'oldest');
  const latest = slackTimestamp(args.latest || opts.latest, 'latest');
  if (cursor) params.cursor = cursor;
  if (oldest) params.oldest = oldest;
  if (latest) params.latest = latest;
  if (args.inclusive != null || opts.inclusive != null) params.inclusive = (args.inclusive ?? opts.inclusive) === true;
  return buildSlackApiUrl('conversations.history', params, opts);
}

function buildFileInfoUrl(args = {}, opts = {}) {
  const file = slackOpaqueId(args.file || args.fileId || opts.file || opts.fileId, 'file');
  return buildSlackApiUrl('files.info', { file }, opts);
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
    throw new Error(`Slack content exceeds ${limit} byte limit`);
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
      if (total > limit) throw new Error(`Slack content exceeds ${limit} byte limit`);
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return { text, sizeBytes: total };
  }

  if (typeof response.arrayBuffer === 'function') {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > limit) throw new Error(`Slack content exceeds ${limit} byte limit`);
    return { text: buffer.toString('utf8'), sizeBytes: buffer.length };
  }

  const text = typeof response.text === 'function' ? await response.text() : '';
  const size = Buffer.byteLength(text, 'utf8');
  if (size > limit) throw new Error(`Slack content exceeds ${limit} byte limit`);
  return { text, sizeBytes: size };
}

function slackScopes(opts = {}) {
  if (Array.isArray(opts.scopes)) return opts.scopes.filter(Boolean).map((scope) => compactLabel(scope, '', 96));
  const raw = envValue(['SLACK_SCOPES'], opts.env);
  if (!raw) return DEFAULT_SCOPES;
  return raw.split(/[,\s]+/).map((scope) => compactLabel(scope, '', 96)).filter(Boolean);
}

function slackTenant(opts = {}) {
  return compactLabel(opts.teamId || opts.enterpriseId || envValue([
    'SLACK_TEAM_ID',
    'SLACK_ENTERPRISE_ID',
  ], opts.env), '', 120);
}

function slackConnectorHealth(opts = {}, ok = true, detail = 'configured') {
  return connectorHealthCheck({
    id: 'Slack',
    tenantId: slackTenant(opts),
    scopes: slackScopes(opts),
  }, ok, detail);
}

async function slackApiCall(method, args = {}, opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Slack access token is required');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');
  const url = method === 'conversations.history'
    ? buildConversationHistoryUrl(args, opts)
    : method === 'files.info'
      ? buildFileInfoUrl(args, opts)
      : buildSlackApiUrl(method, args, opts);

  const response = await fetchWithTimeout(fetchImpl, url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  }, opts);
  if (!response || !response.ok) {
    const status = response && response.status ? response.status : 'unknown';
    throw new Error(`Slack ${method} failed with HTTP ${status}`);
  }
  const body = typeof response.json === 'function'
    ? await response.json()
    : JSON.parse((await readBoundedText(response, { ...opts, maxBytes: Math.min(maxBytes(opts), 64 * 1024) })).text || '{}');
  if (!body || body.ok !== true) {
    const error = compactLabel(body && body.error, 'unknown_error', 80);
    throw new Error(`Slack ${method} failed: ${error}`);
  }
  return body;
}

function normalizeSlackText(value) {
  return String(value || '')
    .replace(/<@[A-Z0-9]+>/gi, '[slack_user]')
    .replace(/<#[A-Z0-9]+(?:\|[^>]+)?>/gi, '[slack_channel]')
    .replace(/<!(?:here|channel|everyone)(?:\|[^>]+)?>/gi, '[slack_broadcast]')
    .replace(/\r\n/g, '\n')
    .trim();
}

function blockText(block) {
  if (!block || typeof block !== 'object') return '';
  const texts = [];
  function walk(value) {
    if (!value || typeof value !== 'object') return;
    if (typeof value.text === 'string') texts.push(value.text);
    if (Array.isArray(value.elements)) value.elements.forEach(walk);
    if (Array.isArray(value.blocks)) value.blocks.forEach(walk);
  }
  walk(block);
  return texts.join(' ');
}

function messagesToText(messages = []) {
  return (Array.isArray(messages) ? messages : [])
    .map((message) => {
      const direct = typeof message.text === 'string' ? message.text : '';
      const fromBlocks = !direct && Array.isArray(message.blocks)
        ? message.blocks.map(blockText).filter(Boolean).join(' ')
        : '';
      return normalizeSlackText(direct || fromBlocks);
    })
    .filter(Boolean)
    .join('\n\n');
}

async function fetchConversationHistory(args = {}, opts = {}) {
  const body = await slackApiCall('conversations.history', args, opts);
  const messages = Array.isArray(body.messages) ? body.messages : [];
  const text = messagesToText(messages);
  const sizeBytes = Buffer.byteLength(text || '', 'utf8');
  const limit = maxBytes(opts);
  if (sizeBytes > limit) throw new Error(`Slack conversation content exceeds ${limit} byte limit`);
  return {
    content: [{ type: 'text', text: text || '[No Slack messages returned]' }],
    structuredContent: {
      connector: 'slack',
      operation: 'conversations.history',
      contentType: 'text/plain',
      sizeBytes,
      messageCount: messages.length,
      hasMore: body.has_more === true,
    },
  };
}

function isAllowedSlackFileUrl(value) {
  try {
    const url = new URL(String(value || ''));
    const host = url.hostname.toLowerCase();
    return url.protocol === 'https:' && SLACK_FILE_HOSTS.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
  } catch {
    return false;
  }
}

async function fetchSlackFileContent(args = {}, opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Slack access token is required');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');
  const info = await slackApiCall('files.info', args, { ...opts, token, fetchImpl });
  const file = info.file && typeof info.file === 'object' ? info.file : {};
  const privateUrl = compactLabel(file.url_private_download || file.url_private, '', 2048);
  if (!isAllowedSlackFileUrl(privateUrl)) {
    throw new Error('Slack file private URL host is not allowed');
  }

  const response = await fetchWithTimeout(fetchImpl, privateUrl, {
    redirect: 'error',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'text/plain, application/json, application/xml, text/*;q=0.9, */*;q=0.1',
    },
  }, opts);
  if (!response || !response.ok) {
    const status = response && response.status ? response.status : 'unknown';
    throw new Error(`Slack file content fetch failed with HTTP ${status}`);
  }

  const contentType = responseContentType(response);
  if (!isTextContentType(contentType, opts)) {
    throw new Error(`Slack file content type is not text-readable: ${contentType}`);
  }

  const body = await readBoundedText(response, opts);
  return {
    content: [{ type: 'text', text: body.text }],
    structuredContent: {
      connector: 'slack',
      operation: 'files.info',
      contentType,
      sizeBytes: body.sizeBytes,
      mimetype: compactLabel(file.mimetype || contentType, 'unknown', 80),
      transferMode: 'url_private',
    },
  };
}

async function sanitizeConversationHistory(args = {}, opts = {}) {
  const raw = await fetchConversationHistory(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'slack',
    tool: 'conversations.history',
  }, opts.guardOptions || {});
}

async function sanitizeSlackFileContent(args = {}, opts = {}) {
  const raw = await fetchSlackFileContent(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'slack',
    tool: 'files.info',
  }, opts.guardOptions || {});
}

function createSlackConversationHistoryTool(opts = {}) {
  return async function slackConversationHistoryTool(args) {
    const sanitized = await sanitizeConversationHistory(args, opts);
    return sanitized.result;
  };
}

function createSlackFileContentTool(opts = {}) {
  return async function slackFileContentTool(args) {
    const sanitized = await sanitizeSlackFileContent(args, opts);
    return sanitized.result;
  };
}

module.exports = {
  buildConversationHistoryUrl,
  buildFileInfoUrl,
  createSlackConversationHistoryTool,
  createSlackFileContentTool,
  fetchConversationHistory,
  fetchSlackFileContent,
  isAllowedSlackFileUrl,
  messagesToText,
  sanitizeConversationHistory,
  sanitizeSlackFileContent,
  slackConnectorHealth,
  slackScopes,
};
