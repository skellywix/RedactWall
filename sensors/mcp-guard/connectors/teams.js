'use strict';
/**
 * Microsoft Teams connector for MCP runtimes.
 *
 * Fetches bounded Teams channel or chat messages through Microsoft Graph, then
 * routes the result through the MCP connector SDK before any model receives it.
 */
const { fetchWithTimeout } = require('../guard');
const { connectorHealthCheck, htmlToText, sanitizeToolResult } = require('../sdk');

const DEFAULT_GRAPH_ROOT = 'https://graph.microsoft.com/v1.0';
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_TOP = 20;
const MAX_TOP = 50;
const DEFAULT_SCOPES = ['ChannelMessage.Read.Group', 'ChatMessage.Read.Chat'];

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
    'TEAMS_GRAPH_ACCESS_TOKEN',
    'M365_GRAPH_ACCESS_TOKEN',
    'MICROSOFT_GRAPH_ACCESS_TOKEN',
  ], opts.env), '', 10000);
}

function normalizeGraphRoot(value = DEFAULT_GRAPH_ROOT) {
  const url = new URL(value || DEFAULT_GRAPH_ROOT);
  if (url.protocol !== 'https:') {
    throw new Error('Microsoft Teams Graph root must use https');
  }
  return url.toString().replace(/\/+$/, '');
}

function graphPathSegment(value, label) {
  const text = String(value == null ? '' : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) throw new Error(`Microsoft Teams ${label} is required`);
  if (text.length > 512) throw new Error(`Microsoft Teams ${label} is too long`);
  if (/[\\/]/.test(text)) throw new Error(`Microsoft Teams ${label} must be an opaque id`);
  return encodeURIComponent(text);
}

function topLimit(value) {
  const n = Number(value == null ? DEFAULT_TOP : value);
  if (!Number.isFinite(n)) return DEFAULT_TOP;
  return Math.max(1, Math.min(MAX_TOP, Math.floor(n)));
}

function graphUrl(pathParts = [], params = {}, opts = {}) {
  const root = normalizeGraphRoot(opts.graphRoot || DEFAULT_GRAPH_ROOT);
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return `${root}/${pathParts.join('/')}${qs ? `?${qs}` : ''}`;
}

function buildTeamsChannelMessagesUrl(args = {}, opts = {}) {
  const teamId = graphPathSegment(args.teamId || opts.teamId, 'teamId');
  const channelId = graphPathSegment(args.channelId || opts.channelId, 'channelId');
  return graphUrl(['teams', teamId, 'channels', channelId, 'messages'], {
    $top: topLimit(args.top ?? args.limit ?? opts.top ?? opts.limit),
  }, opts);
}

function cleanOrderBy(value) {
  const text = compactLabel(value, '', 80);
  if (!text) return '';
  if (!/^(?:lastModifiedDateTime|createdDateTime) desc$/i.test(text)) {
    throw new Error('Microsoft Teams orderby is not supported');
  }
  return text;
}

function cleanFilter(value) {
  const text = compactLabel(value, '', 240);
  if (!text) return '';
  if (!/^(?:lastModifiedDateTime|createdDateTime) (?:gt|lt) \d{4}-\d{2}-\d{2}T[\d:.]+Z(?: and (?:lastModifiedDateTime|createdDateTime) (?:gt|lt) \d{4}-\d{2}-\d{2}T[\d:.]+Z)?$/i.test(text)) {
    throw new Error('Microsoft Teams filter is not supported');
  }
  return text;
}

function buildTeamsChatMessagesUrl(args = {}, opts = {}) {
  const chatId = graphPathSegment(args.chatId || opts.chatId, 'chatId');
  const params = {
    $top: topLimit(args.top ?? args.limit ?? opts.top ?? opts.limit),
  };
  const orderby = cleanOrderBy(args.orderby || opts.orderby);
  const filter = cleanFilter(args.filter || opts.filter);
  if (orderby) params.$orderby = orderby;
  if (filter) params.$filter = filter;
  return graphUrl(['chats', chatId, 'messages'], params, opts);
}

function maxBytes(opts = {}) {
  const n = Number(opts.maxBytes ?? DEFAULT_MAX_BYTES);
  if (!Number.isFinite(n)) return DEFAULT_MAX_BYTES;
  return Math.max(1, Math.min(5 * 1024 * 1024, Math.floor(n)));
}

function graphScopes(opts = {}) {
  if (Array.isArray(opts.scopes)) return opts.scopes.filter(Boolean).map((scope) => compactLabel(scope, '', 96));
  const raw = envValue(['TEAMS_GRAPH_SCOPES'], opts.env);
  if (!raw) return DEFAULT_SCOPES;
  return raw.split(/[,\s]+/).map((scope) => compactLabel(scope, '', 96)).filter(Boolean);
}

function teamsTenant(opts = {}) {
  return compactLabel(opts.tenantId || envValue([
    'TEAMS_TENANT_ID',
    'M365_TENANT_ID',
    'AZURE_TENANT_ID',
  ], opts.env), '', 120);
}

function teamsConnectorHealth(opts = {}, ok = true, detail = 'configured') {
  return connectorHealthCheck({
    id: 'Microsoft Teams',
    tenantId: teamsTenant(opts),
    scopes: graphScopes(opts),
  }, ok, detail);
}

async function graphApiCall(url, method, opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Microsoft Teams access token is required');
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
    throw new Error(`Microsoft Teams ${method} failed with HTTP ${status}`);
  }
  const body = typeof response.json === 'function' ? await response.json() : JSON.parse(await response.text() || '{}');
  if (body && body.error) {
    const code = compactLabel(body.error.code || 'graph_error', 'graph_error', 80);
    throw new Error(`Microsoft Teams ${method} failed: ${code}`);
  }
  return body || {};
}

function messagesToText(messages = []) {
  return (Array.isArray(messages) ? messages : [])
    .map((message) => {
      const body = message && message.body && typeof message.body === 'object' ? message.body : {};
      const content = typeof body.content === 'string' ? body.content : '';
      return body.contentType === 'html' ? htmlToText(content) : compactLabel(content, '', 10000);
    })
    .filter(Boolean)
    .join('\n\n');
}

function resultForMessages(messages, body, operation, opts = {}) {
  const text = messagesToText(messages);
  const sizeBytes = Buffer.byteLength(text || '', 'utf8');
  const limit = maxBytes(opts);
  if (sizeBytes > limit) throw new Error(`Microsoft Teams message content exceeds ${limit} byte limit`);
  return {
    content: [{ type: 'text', text: text || '[No Microsoft Teams messages returned]' }],
    structuredContent: {
      connector: 'teams',
      operation,
      contentType: 'text/plain',
      sizeBytes,
      messageCount: messages.length,
      hasMore: Boolean(body && body['@odata.nextLink']),
    },
  };
}

async function fetchTeamsChannelMessages(args = {}, opts = {}) {
  const body = await graphApiCall(buildTeamsChannelMessagesUrl(args, opts), 'channels.messages', opts);
  const messages = Array.isArray(body.value) ? body.value : [];
  return resultForMessages(messages, body, 'channels.messages', opts);
}

async function fetchTeamsChatMessages(args = {}, opts = {}) {
  const body = await graphApiCall(buildTeamsChatMessagesUrl(args, opts), 'chats.messages', opts);
  const messages = Array.isArray(body.value) ? body.value : [];
  return resultForMessages(messages, body, 'chats.messages', opts);
}

async function sanitizeTeamsChannelMessages(args = {}, opts = {}) {
  const raw = await fetchTeamsChannelMessages(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'teams',
    tool: 'channels.messages',
  }, opts.guardOptions || {});
}

async function sanitizeTeamsChatMessages(args = {}, opts = {}) {
  const raw = await fetchTeamsChatMessages(args, opts);
  return sanitizeToolResult(raw, {
    agent: opts.agent,
    connector: 'teams',
    tool: 'chats.messages',
  }, opts.guardOptions || {});
}

function createTeamsChannelMessagesTool(opts = {}) {
  return async function teamsChannelMessagesTool(args) {
    const sanitized = await sanitizeTeamsChannelMessages(args, opts);
    return sanitized.result;
  };
}

function createTeamsChatMessagesTool(opts = {}) {
  return async function teamsChatMessagesTool(args) {
    const sanitized = await sanitizeTeamsChatMessages(args, opts);
    return sanitized.result;
  };
}

module.exports = {
  buildTeamsChannelMessagesUrl,
  buildTeamsChatMessagesUrl,
  createTeamsChannelMessagesTool,
  createTeamsChatMessagesTool,
  fetchTeamsChannelMessages,
  fetchTeamsChatMessages,
  graphScopes,
  htmlToText,
  messagesToText,
  sanitizeTeamsChannelMessages,
  sanitizeTeamsChatMessages,
  teamsConnectorHealth,
};
