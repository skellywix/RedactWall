'use strict';
require('../../server/env').loadEnv();
/**
 * PromptSentinel MCP guard (reference implementation).
 *
 * Sits between an MCP server and the model. When an AI agent pulls a document or
 * record through a tool call (SharePoint, Drive, a database), the guard scans
 * the tool RESPONSE and redacts sensitive content BEFORE the model ever sees it,
 * while logging the event to the control plane. This solves the "agent pulling
 * PII from a data source" problem.
 *
 * Wrap any tool handler with guardToolResult(). Same shared engine, same server.
 */
const D = require('../../detection-engine/detect');
const VERSION = require('../../package.json').version;

const SERVER = process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || '';
const POLICY_REFRESH_MS = 15 * 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;
const DEFAULT_DETECTION_POLICY = { ignore: [], disabledDetectors: [] };
let detectionPolicy = normalizeDetectionPolicy(DEFAULT_DETECTION_POLICY);
let lastPolicyRefresh = 0;

function configuredKey(opts = {}) {
  const value = Object.prototype.hasOwnProperty.call(opts, 'key') ? opts.key : KEY;
  return typeof value === 'string' ? value.trim() : '';
}

function lowerDetectorList(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim());
}

function normalizeDetectionPolicy(policy = {}) {
  return {
    ignore: lowerDetectorList(policy.ignore),
    disabledDetectors: lowerDetectorList(policy.disabledDetectors),
  };
}

function detectionOptions(policy = detectionPolicy) {
  return normalizeDetectionPolicy(policy);
}

function requestTimeoutMs(opts = {}) {
  const n = Number(opts.timeoutMs ?? process.env.SENTINEL_REQUEST_TIMEOUT_MS ?? DEFAULT_REQUEST_TIMEOUT_MS);
  if (!Number.isFinite(n)) return DEFAULT_REQUEST_TIMEOUT_MS;
  return Math.max(50, Math.min(120000, n));
}

async function fetchWithTimeout(fetchImpl, url, options, opts = {}) {
  const timeout = requestTimeoutMs(opts);
  if (!globalThis.AbortController) return fetchImpl(url, options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetchImpl(url, { ...(options || {}), signal: controller.signal });
  } catch (e) {
    if (e && e.name === 'AbortError') e.code = 'SENTINEL_TIMEOUT';
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchPolicy(opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return null;
  const server = opts.server || SERVER;
  const key = configuredKey(opts);
  if (!key) return null;
  try {
    const r = await fetchWithTimeout(fetchImpl, server + '/api/v1/policy', {
      headers: { 'x-api-key': key },
    }, opts);
    if (!r || !r.ok) return null;
    return r.json();
  } catch (e) {
    if (!opts.silent) console.error('  policy refresh failed:', e.message);
    return null;
  }
}

async function refreshPolicy(opts = {}) {
  const pol = await fetchPolicy(opts);
  if (pol) {
    detectionPolicy = normalizeDetectionPolicy(pol);
    lastPolicyRefresh = Date.now();
  }
  return detectionPolicy;
}

async function maybeRefreshPolicy(opts = {}) {
  if (opts.policy || opts.skipPolicyRefresh) return;
  if (Date.now() - lastPolicyRefresh < (opts.policyRefreshMs || POLICY_REFRESH_MS)) return;
  await refreshPolicy({ ...opts, silent: opts.silentPolicyRefresh !== false });
}

function publicFindings(analysis) {
  return (analysis.findings || []).map((f) => ({
    type: f.type,
    severity: f.severity,
    score: f.score,
    masked: D.maskValue(f.type, f.value),
  }));
}

function publicCategories(analysis) {
  return (analysis.categories || []).map((c) => ({ category: c.category, score: c.score }));
}

function sensorMetadata() {
  return { name: 'mcp_guard', version: VERSION, platform: 'node' };
}

function reportBody({ safeText, analysis, ctx }) {
  return {
    prompt: String(safeText || '').slice(0, 1000),
    user: ctx.agent || 'mcp-agent',
    destination: ctx.tool || 'mcp-tool',
    source: 'mcp_guard',
    channel: 'mcp_doc',
    sensor: sensorMetadata(),
    clientOutcome: 'redacted_sent',
    clientPreRedacted: true,
    clientFindings: publicFindings(analysis),
    clientCategories: publicCategories(analysis),
    clientEntityCounts: analysis.entityCounts || {},
    clientRiskScore: analysis.riskScore || 0,
    clientMaxSeverity: analysis.maxSeverity || 0,
    clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
    note: 'MCP guard redacted tool output before model delivery',
  };
}

async function logEvent(rec, opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return;
  const server = opts.server || SERVER;
  const key = configuredKey(opts);
  if (!key) return;
  try {
    await fetchWithTimeout(fetchImpl, server + '/api/v1/gate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': key },
      body: JSON.stringify(rec),
    }, opts);
  } catch (e) { /* logging best-effort */ }
}

/**
 * Inspect+redact a tool result string before returning it to the model.
 * @returns {Promise<{ text:string, redacted:boolean, findings:string[] }>}
 */
async function guardToolResult(text, ctx = {}, opts = {}) {
  await maybeRefreshPolicy(opts);
  const a = D.analyze(text || '', detectionOptions(opts.policy || detectionPolicy));
  const findings = [...new Set(a.findings.map(f => f.type).concat(a.categories.map(c => c.category)))];
  if (!a.findings.length && !a.categories.length) {
    return { text, redacted: false, findings: [] };
  }
  const safe = a.categories.length
    ? '[REDACTED: ' + findings.join(', ') + ']'
    : D.redact(text, a.findings); // structured PII replaced with [TYPE]
  await logEvent(reportBody({ safeText: safe, analysis: a, ctx }), opts);
  return { text: safe, redacted: true, findings };
}

/** Higher-order wrapper for an MCP tool handler. */
function wrapTool(handler, ctx = {}) {
  return async function (args) {
    const result = await handler(args);
    const asText = typeof result === 'string' ? result : JSON.stringify(result);
    const guarded = await guardToolResult(asText, ctx);
    return guarded.text;
  };
}

module.exports = {
  guardToolResult,
  wrapTool,
  reportBody,
  publicFindings,
  publicCategories,
  fetchPolicy,
  refreshPolicy,
  detectionOptions,
  requestTimeoutMs,
  fetchWithTimeout,
  sensorMetadata,
};

// ---- demo when run directly ------------------------------------------------
if (require.main === module) {
  (async () => {
    const fakeDoc = `Member record pulled from SharePoint:
Name: Sarah Jones
SSN: 524-71-9043
Card on file: 4111 1111 1111 1111
Notes: confidential — account under review, do not share externally.`;
    console.log('--- raw MCP tool result (what the model WOULD see) ---');
    console.log(fakeDoc);
    const g = await guardToolResult(fakeDoc, { agent: 'claude-desktop', tool: 'sharepoint.fetchDoc' });
    console.log('\n--- guarded result (what the model ACTUALLY sees) ---');
    console.log(g.text);
    console.log('\nredacted:', g.redacted, '| detected:', g.findings.join(', '));
  })();
}
