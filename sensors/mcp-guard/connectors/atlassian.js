'use strict';
/**
 * Atlassian Jira and Confluence connector for MCP runtimes.
 *
 * Fetches bounded Jira issue or Confluence page content, then routes the
 * result through the MCP connector SDK before any model receives it.
 */
const { fetchWithTimeout } = require('../guard');
const { connectorHealthCheck, executeConnectorTool, htmlToText } = require('../sdk');
const { cancelResponseBody, readBoundedJson } = require('../../shared/bounded-response');

const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_SCOPES = ['read:jira-work', 'read:page:confluence'];
const DEFAULT_JIRA_FIELDS = ['summary', 'description', 'comment'];
const CONFLUENCE_BODY_FORMATS = new Set(['storage', 'atlas_doc_format', 'view']);

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
  return compactLabel(opts.accessToken || opts.apiToken || opts.token || envValue([
    'ATLASSIAN_ACCESS_TOKEN',
    'ATLASSIAN_API_TOKEN',
    'JIRA_API_TOKEN',
    'CONFLUENCE_API_TOKEN',
  ], opts.env), '', 10000);
}

function atlassianEmail(opts = {}) {
  return compactLabel(opts.email || envValue(['ATLASSIAN_EMAIL', 'JIRA_EMAIL', 'CONFLUENCE_EMAIL'], opts.env), '', 320);
}

function normalizeAtlassianSiteUrl(value, env = process.env) {
  const raw = value || envValue(['ATLASSIAN_SITE_URL', 'JIRA_BASE_URL', 'CONFLUENCE_BASE_URL'], env);
  if (!raw) throw new Error('Atlassian site URL is required');
  const url = new URL(raw);
  if (url.protocol !== 'https:') throw new Error('Atlassian site URL must use https');
  url.pathname = url.pathname.replace(/\/+$/, '');
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/+$/, '');
}

function opaqueId(value, label, max = 256) {
  const text = String(value == null ? '' : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) throw new Error(`Atlassian ${label} is required`);
  if (text.length > max) throw new Error(`Atlassian ${label} is too long`);
  if (/[\\/]/.test(text)) throw new Error(`Atlassian ${label} must be an opaque id`);
  return encodeURIComponent(text);
}

function confluencePageId(value) {
  const text = String(value == null ? '' : value).trim();
  if (!/^\d{1,32}$/.test(text)) throw new Error('Atlassian Confluence page id must be numeric');
  return text;
}

function cleanFields(value) {
  const raw = Array.isArray(value) ? value : String(value || '').split(/[,\s]+/);
  const fields = raw
    .map((field) => compactLabel(field, '', 48))
    .filter((field) => /^[A-Za-z0-9_.-]+$/.test(field))
    .slice(0, 12);
  return fields.length ? fields : DEFAULT_JIRA_FIELDS;
}

function buildJiraIssueUrl(args = {}, opts = {}) {
  // Site is derived ONLY from operator config/env, never from model-controlled
  // args: a caller-supplied siteUrl would send the Atlassian credential to an
  // attacker-chosen host (credential exfiltration / SSRF).
  const site = normalizeAtlassianSiteUrl(opts.siteUrl || opts.atlassianSiteUrl, opts.env);
  const issueIdOrKey = opaqueId(args.issueIdOrKey || args.issueKey || opts.issueIdOrKey || opts.issueKey, 'issueIdOrKey');
  const search = new URLSearchParams();
  search.set('fields', cleanFields(args.fields || opts.fields).join(','));
  search.set('updateHistory', 'false');
  return `${site}/rest/api/3/issue/${issueIdOrKey}?${search.toString()}`;
}

function bodyFormat(value) {
  const format = compactLabel(value, 'storage', 40).toLowerCase();
  if (!CONFLUENCE_BODY_FORMATS.has(format)) throw new Error('Atlassian Confluence body format is not supported');
  return format;
}

function buildConfluencePageUrl(args = {}, opts = {}) {
  // Site is derived ONLY from operator config/env, never from model-controlled
  // args (see buildJiraIssueUrl — prevents credential exfiltration / SSRF).
  const site = normalizeAtlassianSiteUrl(opts.siteUrl || opts.atlassianSiteUrl, opts.env);
  const pageId = confluencePageId(args.pageId || args.id || opts.pageId || opts.id);
  const search = new URLSearchParams();
  search.set('body-format', bodyFormat(args.bodyFormat || opts.bodyFormat));
  return `${site}/wiki/api/v2/pages/${pageId}?${search.toString()}`;
}

function maxBytes(opts = {}) {
  const n = Number(opts.maxBytes ?? DEFAULT_MAX_BYTES);
  if (!Number.isFinite(n)) return DEFAULT_MAX_BYTES;
  return Math.max(1, Math.min(5 * 1024 * 1024, Math.floor(n)));
}

function authHeaders(opts = {}) {
  const token = accessToken(opts);
  if (!token) throw new Error('Atlassian access token is required');
  const email = atlassianEmail(opts);
  if (email) {
    return {
      Authorization: `Basic ${Buffer.from(`${email}:${token}`).toString('base64')}`,
      Accept: 'application/json',
    };
  }
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
  };
}

async function fetchJson(url, method, opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');
  const response = await fetchWithTimeout(fetchImpl, url, {
    headers: authHeaders(opts),
  }, opts);
  if (!response || !response.ok) {
    const status = response && response.status ? response.status : 'unknown';
    if (response) await cancelResponseBody(response);
    throw new Error(`Atlassian ${method} failed with HTTP ${status}`);
  }
  const body = await readBoundedJson(response, {
    maxBytes: maxBytes(opts),
    timeoutMs: opts.responseTimeoutMs || opts.timeoutMs,
    label: `Atlassian ${method} response`,
  });
  return body.json || {};
}

function adfToText(value) {
  const out = [];
  function walk(node) {
    if (node == null) return;
    if (typeof node === 'string') {
      out.push(node);
      return;
    }
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (typeof node !== 'object') return;
    if (typeof node.text === 'string') out.push(node.text);
    if (node.type === 'hardBreak' || node.type === 'paragraph' || node.type === 'heading') out.push('\n');
    if (Array.isArray(node.content)) node.content.forEach(walk);
  }
  walk(value);
  return out.join(' ').replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\s+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

function plainField(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value.content || value.type === 'doc') return adfToText(value);
  if (typeof value.value === 'string') return value.value;
  if (typeof value.name === 'string') return value.name;
  if (typeof value.displayName === 'string') return value.displayName;
  return '';
}

function jiraIssueToText(issue = {}) {
  const fields = issue.fields && typeof issue.fields === 'object' ? issue.fields : {};
  const parts = [];
  const summary = plainField(fields.summary);
  const description = plainField(fields.description);
  if (summary) parts.push(`Summary: ${summary}`);
  if (description) parts.push(`Description: ${description}`);
  const comments = fields.comment && Array.isArray(fields.comment.comments) ? fields.comment.comments : [];
  comments.slice(0, 20).forEach((comment, index) => {
    const text = plainField(comment.body);
    if (text) parts.push(`Comment ${index + 1}: ${text}`);
  });
  return parts.filter(Boolean).join('\n\n').trim();
}

function confluencePageToText(page = {}) {
  const body = page.body && typeof page.body === 'object' ? page.body : {};
  const candidates = [body.storage, body.view, body.atlas_doc_format].filter(Boolean);
  const title = compactLabel(page.title, '', 240);
  const parts = title ? [`Title: ${title}`] : [];
  for (const candidate of candidates) {
    if (!candidate) continue;
    if (typeof candidate.value === 'string') {
      if (candidate.representation === 'atlas_doc_format') {
        try {
          parts.push(adfToText(JSON.parse(candidate.value)));
        } catch {
          parts.push(htmlToText(candidate.value));
        }
      } else {
        parts.push(htmlToText(candidate.value));
      }
      break;
    }
    if (typeof candidate === 'string') {
      parts.push(htmlToText(candidate));
      break;
    }
  }
  return parts.filter(Boolean).join('\n\n').trim();
}

function boundedConnectorText(text, label, opts = {}) {
  const safe = String(text || '').trim() || `[No ${label} content returned]`;
  const sizeBytes = Buffer.byteLength(safe, 'utf8');
  const limit = maxBytes(opts);
  if (sizeBytes > limit) throw new Error(`Atlassian ${label} content exceeds ${limit} byte limit`);
  return { text: safe, sizeBytes };
}

async function fetchJiraIssue(args = {}, opts = {}) {
  const body = await fetchJson(buildJiraIssueUrl(args, opts), 'jira.issue.get', opts);
  const text = boundedConnectorText(jiraIssueToText(body), 'Jira issue', opts);
  const commentCount = body.fields && body.fields.comment && Array.isArray(body.fields.comment.comments)
    ? body.fields.comment.comments.length
    : 0;
  return {
    content: [{ type: 'text', text: text.text }],
    structuredContent: {
      connector: 'atlassian',
      operation: 'jira.issue.get',
      contentType: 'text/plain',
      sizeBytes: text.sizeBytes,
      commentCount,
    },
  };
}

async function fetchConfluencePage(args = {}, opts = {}) {
  const body = await fetchJson(buildConfluencePageUrl(args, opts), 'confluence.page.get', opts);
  const text = boundedConnectorText(confluencePageToText(body), 'Confluence page', opts);
  return {
    content: [{ type: 'text', text: text.text }],
    structuredContent: {
      connector: 'atlassian',
      operation: 'confluence.page.get',
      contentType: 'text/plain',
      sizeBytes: text.sizeBytes,
      bodyFormat: bodyFormat(args.bodyFormat || opts.bodyFormat),
    },
  };
}

function atlassianScopes(opts = {}) {
  if (Array.isArray(opts.scopes)) return opts.scopes.filter(Boolean).map((scope) => compactLabel(scope, '', 96));
  const raw = envValue(['ATLASSIAN_SCOPES', 'JIRA_SCOPES', 'CONFLUENCE_SCOPES'], opts.env);
  if (!raw) return DEFAULT_SCOPES;
  return raw.split(/[,\s]+/).map((scope) => compactLabel(scope, '', 96)).filter(Boolean);
}

function atlassianTenant(opts = {}) {
  try {
    const site = opts.siteUrl || opts.atlassianSiteUrl || envValue(['ATLASSIAN_SITE_URL', 'JIRA_BASE_URL', 'CONFLUENCE_BASE_URL'], opts.env);
    if (!site) return '';
    return new URL(site).hostname;
  } catch {
    return '';
  }
}

function atlassianConnectorHealth(opts = {}, ok = true, detail = 'configured') {
  return connectorHealthCheck({
    id: 'Atlassian Jira Confluence',
    tenantId: atlassianTenant(opts),
    scopes: atlassianScopes(opts),
  }, ok, detail);
}

async function sanitizeJiraIssue(args = {}, opts = {}) {
  return executeConnectorTool((toolArgs) => fetchJiraIssue(toolArgs, opts), args, {
    agent: opts.agent,
    connector: 'atlassian',
    tool: 'jira.issue.get',
  }, opts.guardOptions || {});
}

async function sanitizeConfluencePage(args = {}, opts = {}) {
  return executeConnectorTool((toolArgs) => fetchConfluencePage(toolArgs, opts), args, {
    agent: opts.agent,
    connector: 'atlassian',
    tool: 'confluence.page.get',
  }, opts.guardOptions || {});
}

function createJiraIssueTool(opts = {}) {
  return async function jiraIssueTool(args) {
    const sanitized = await sanitizeJiraIssue(args, opts);
    return sanitized.result;
  };
}

function createConfluencePageTool(opts = {}) {
  return async function confluencePageTool(args) {
    const sanitized = await sanitizeConfluencePage(args, opts);
    return sanitized.result;
  };
}

module.exports = {
  atlassianConnectorHealth,
  atlassianScopes,
  buildConfluencePageUrl,
  buildJiraIssueUrl,
  confluencePageToText,
  createConfluencePageTool,
  createJiraIssueTool,
  fetchConfluencePage,
  fetchJiraIssue,
  htmlToText,
  jiraIssueToText,
  sanitizeConfluencePage,
  sanitizeJiraIssue,
};
