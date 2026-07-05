'use strict';
require('../../server/env').loadEnv();
/**
 * PromptWall MCP guard (reference implementation).
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
const DEFAULT_DETECTION_POLICY = {
  ignore: [],
  disabledDetectors: [],
  customDetectors: [],
  mcpAllowedTools: [],
  mcpBlockedTools: [],
  mcpApprovalRequiredTools: [],
};
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

function normalizeToolList(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const item of value) {
    const text = String(item || '').trim();
    if (!text || text.length > 160 || !/^[A-Za-z0-9.*:_/-]+$/.test(text)) continue;
    const key = text.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(text);
  }
  return out;
}

function normalizeDetectionPolicy(policy = {}) {
  return {
    ignore: lowerDetectorList(policy.ignore),
    disabledDetectors: lowerDetectorList(policy.disabledDetectors),
    customDetectors: Array.isArray(policy.customDetectors) ? policy.customDetectors : [],
    mcpAllowedTools: normalizeToolList(policy.mcpAllowedTools),
    mcpBlockedTools: normalizeToolList(policy.mcpBlockedTools),
    mcpApprovalRequiredTools: normalizeToolList(policy.mcpApprovalRequiredTools),
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
  sendHeartbeat(opts).catch(() => {});
}

// Presence heartbeat: registers this guard with the control plane and returns
// the companion view (is the browser extension / endpoint agent also active
// for this identity), so wrapped agents can surface coverage gaps.
async function sendHeartbeat(opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const server = opts.server || SERVER;
  const key = configuredKey(opts);
  if (!fetchImpl || !key) return null;
  try {
    const r = await fetchWithTimeout(fetchImpl, server + '/api/v1/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': key },
      body: JSON.stringify({ user: opts.agent || 'mcp-agent', source: 'mcp_guard', sensor: sensorMetadata() }),
    }, opts);
    return await r.json().catch(() => null);
  } catch (e) {
    return null;
  }
}

function publicFindings(analysis) {
  return (analysis.findings || []).map((f) => ({
    type: f.type,
    severity: f.severity,
    score: f.score,
    masked: D.maskValue(f.type, f.value),
    ...(f.vendor ? { vendor: f.vendor, vendorLabel: f.vendorLabel } : {}),
  }));
}

function publicCategories(analysis) {
  return (analysis.categories || []).map((c) => ({ category: c.category, score: c.score }));
}

function sensorMetadata() {
  return { name: 'mcp_guard', version: VERSION, platform: 'node' };
}

function safeToolName(value) {
  const text = String(value || 'mcp-tool').replace(/[\r\n\t]/g, ' ').trim();
  return (text || 'mcp-tool').slice(0, 160);
}

function wildcardRegex(pattern) {
  const escaped = String(pattern)
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

function toolPatternMatches(tool, pattern) {
  const target = safeToolName(tool).toLowerCase();
  const rule = safeToolName(pattern).toLowerCase();
  if (rule === '*') return true;
  if (rule.includes('*')) return wildcardRegex(rule).test(target);
  return target === rule;
}

function toolMatchesAny(tool, patterns = []) {
  return patterns.some((pattern) => toolPatternMatches(tool, pattern));
}

function mcpToolDecision(ctx = {}, policy = detectionPolicy) {
  const tool = safeToolName(ctx.tool || ctx.destination || 'mcp-tool');
  const normalized = normalizeDetectionPolicy(policy || DEFAULT_DETECTION_POLICY);
  if (toolMatchesAny(tool, normalized.mcpBlockedTools)) {
    return { allowed: false, status: 'blocked', tool, reason: 'MCP tool blocked by policy' };
  }
  if (toolMatchesAny(tool, normalized.mcpApprovalRequiredTools)) {
    return { allowed: false, status: 'approval_required', tool, reason: 'MCP tool requires approval before execution' };
  }
  if (normalized.mcpAllowedTools.length && !toolMatchesAny(tool, normalized.mcpAllowedTools)) {
    return { allowed: false, status: 'not_allowed', tool, reason: 'MCP tool is outside the allowed registry' };
  }
  return { allowed: true, status: 'allowed', tool, reason: 'MCP tool allowed by policy' };
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

function reportToolPolicyBody({ decision, ctx }) {
  const context = ctx && typeof ctx === 'object' ? ctx : {};
  const tool = safeToolName(decision && decision.tool || context.tool || 'mcp-tool');
  return {
    prompt: `[MCP tool blocked] ${tool}`,
    user: context.agent || 'mcp-agent',
    destination: tool,
    source: 'mcp_guard',
    channel: 'mcp_tool',
    sensor: sensorMetadata(),
    clientOutcome: 'action_blocked',
    note: decision.reason || 'MCP tool policy blocked execution',
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

async function logToolPolicyBlock(decision, ctx = {}, opts = {}) {
  await logEvent(reportToolPolicyBody({ decision, ctx }), opts);
}

async function guardToolRequest(ctx = {}, opts = {}) {
  await maybeRefreshPolicy(opts);
  const decision = mcpToolDecision(ctx, opts.policy || detectionPolicy);
  if (!decision.allowed) await logToolPolicyBlock(decision, ctx, opts);
  return decision;
}

/**
 * Inspect+redact a tool result string before returning it to the model.
 * @returns {Promise<{ text:string, redacted:boolean, findings:string[] }>}
 */
async function guardToolResult(text, ctx = {}, opts = {}) {
  await maybeRefreshPolicy(opts);
  const toolDecision = mcpToolDecision(ctx, opts.policy || detectionPolicy);
  if (!toolDecision.allowed) {
    await logToolPolicyBlock(toolDecision, ctx, opts);
    return {
      text: `[BLOCKED: ${toolDecision.reason}]`,
      redacted: true,
      blocked: true,
      findings: ['MCP_TOOL_POLICY'],
    };
  }
  const a = D.analyze(text || '', detectionOptions(opts.policy || detectionPolicy));
  const findings = [...new Set(a.findings.map(f => f.type).concat(a.categories.map(c => c.category)))];
  if (!a.findings.length && !a.categories.length) {
    return { text, redacted: false, findings: [] };
  }
  const safe = a.categories.length
    ? '[REDACTED: ' + findings.join(', ') + ']'
    : D.redact(text, a.findings); // structured PII replaced with [TYPE]
  // Telemetry to the control plane is always a label-only summary — never the
  // fetched document prose, even with structured PII masked. The model still
  // receives the full redacted `safe` text below.
  const telemetryText = '[REDACTED: ' + findings.join(', ') + ']';
  await logEvent(reportBody({ safeText: telemetryText, analysis: a, ctx }), opts);
  return { text: safe, redacted: true, findings };
}

/** Higher-order wrapper for an MCP tool handler. */
function wrapTool(handler, ctx = {}, opts = {}) {
  return async function (args) {
    const decision = await guardToolRequest(ctx, opts);
    if (!decision.allowed) return `[BLOCKED: ${decision.reason}]`;
    const result = await handler(args);
    const asText = typeof result === 'string' ? result : JSON.stringify(result);
    const guarded = await guardToolResult(asText, ctx, opts);
    return guarded.text;
  };
}

async function demo(deps = {}) {
  const io = deps.console || console;
  const guard = deps.guardToolResult || guardToolResult;
  const canary = ['PS', 'CANARY', 'MCPDEMO123456'].join('-');
  const fakeDoc = `Member record pulled from SharePoint:
Name: Sarah Jones
Canary: ${canary}
Notes: confidential - account under review, do not share externally.`;
  io.log('--- raw MCP tool result (what the model WOULD see) ---');
  io.log(fakeDoc);
  const g = await guard(fakeDoc, { agent: 'claude-desktop', tool: 'sharepoint.fetchDoc' });
  io.log('\n--- guarded result (what the model ACTUALLY sees) ---');
  io.log(g.text);
  io.log('\nredacted:', g.redacted, '| detected:', g.findings.join(', '));
  return g;
}

module.exports = {
  guardToolResult,
  guardToolRequest,
  wrapTool,
  demo,
  reportBody,
  reportToolPolicyBody,
  publicFindings,
  publicCategories,
  mcpToolDecision,
  fetchPolicy,
  refreshPolicy,
  detectionOptions,
  requestTimeoutMs,
  fetchWithTimeout,
  sensorMetadata,
  sendHeartbeat,
};

// ---- demo when run directly ------------------------------------------------
if (require.main === module) demo();
