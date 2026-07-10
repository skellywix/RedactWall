'use strict';
require('../../server/env').loadEnv();
/**
 * RedactWall MCP guard (reference implementation).
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
const { secureServerUrl } = require('../shared/server-url');
const { mandatoryAlwaysBlock } = require('../shared/decision');
const { cancelResponseBody, readBoundedJson } = require('../shared/bounded-response');
const { carriesEncodedSensitiveText, carriesNumericContent } = require('../shared/opaque-content');
const signedPolicy = require('../shared/signed-policy');

const bool = (v) => ['1', 'true', 'yes', 'on'].includes(String(v || '').toLowerCase());
// Cleartext to a remote plane would leak the ingest key; loopback stays fine.
const RAW_SERVER = process.env.REDACTWALL_URL || 'http://localhost:4000';
const PRODUCTION = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
const SERVER_CHECKED = secureServerUrl(RAW_SERVER, !PRODUCTION && bool(process.env.REDACTWALL_ALLOW_INSECURE_SERVER));
if (!SERVER_CHECKED) {
  console.error('[mcp-guard] refusing insecure control-plane URL: use https:// for a remote plane (the insecure override is development-only).');
  process.exit(1);
}
const SERVER = SERVER_CHECKED;
const KEY = process.env.INGEST_API_KEY || '';
const POLICY_REFRESH_MS = 5 * 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;
const DEFAULT_CONTROL_PLANE_RESPONSE_BYTES = 512 * 1024;
const NODE_TEST_CONTEXT = String(process.env.NODE_TEST_CONTEXT || '');
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
let lastPolicyAttempt = 0;
let policyTrusted = false;
let policyExpiresAt = 0;

function configuredKey(opts = {}) {
  const value = Object.prototype.hasOwnProperty.call(opts, 'key') ? opts.key : KEY;
  return typeof value === 'string' ? value.trim() : '';
}

function configuredServer(opts = {}) {
  const raw = opts.server || SERVER;
  const production = String(opts.nodeEnv ?? process.env.NODE_ENV ?? '').trim().toLowerCase() === 'production';
  const allowInsecure = !production
    && (opts.allowInsecureServer === true || bool(process.env.REDACTWALL_ALLOW_INSECURE_SERVER));
  return secureServerUrl(raw, allowInsecure) || '';
}

function controlPlaneResponseBytes(opts = {}) {
  const n = Number(opts.maxResponseBytes ?? opts.maxControlPlaneResponseBytes ?? DEFAULT_CONTROL_PLANE_RESPONSE_BYTES);
  if (!Number.isFinite(n)) return DEFAULT_CONTROL_PLANE_RESPONSE_BYTES;
  return Math.max(1024, Math.min(8 * 1024 * 1024, Math.floor(n)));
}

async function readControlPlaneJson(response, opts, label) {
  const parsed = await readBoundedJson(response, {
    maxBytes: controlPlaneResponseBytes(opts),
    timeoutMs: requestTimeoutMs(opts),
    label,
  });
  return parsed.json;
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
  const alwaysBlock = mandatoryAlwaysBlock(policy.alwaysBlock);
  const hardStops = new Set(alwaysBlock);
  return {
    ignore: lowerDetectorList(policy.ignore).filter((type) => !hardStops.has(type)),
    disabledDetectors: lowerDetectorList(policy.disabledDetectors).filter((type) => !hardStops.has(type)),
    customDetectors: Array.isArray(policy.customDetectors) ? policy.customDetectors : [],
    exactMatch: policy.exactMatch && typeof policy.exactMatch === 'object' && !Array.isArray(policy.exactMatch)
      ? policy.exactMatch : undefined,
    opaqueEncodedContent: true,
    alwaysBlock,
    mcpAllowedTools: normalizeToolList(policy.mcpAllowedTools),
    mcpBlockedTools: normalizeToolList(policy.mcpBlockedTools),
    mcpApprovalRequiredTools: normalizeToolList(policy.mcpApprovalRequiredTools),
  };
}

function detectionOptions(policy = detectionPolicy) {
  return normalizeDetectionPolicy(policy);
}

function requestTimeoutMs(opts = {}) {
  const n = Number(opts.timeoutMs ?? process.env.REDACTWALL_REQUEST_TIMEOUT_MS ?? DEFAULT_REQUEST_TIMEOUT_MS);
  if (!Number.isFinite(n)) return DEFAULT_REQUEST_TIMEOUT_MS;
  return Math.max(50, Math.min(120000, n));
}

async function fetchWithTimeout(fetchImpl, url, options, opts = {}) {
  const timeout = requestTimeoutMs(opts);
  const requestOptions = { ...(options || {}), redirect: 'error' };
  if (!globalThis.AbortController) return fetchImpl(url, requestOptions);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetchImpl(url, { ...requestOptions, signal: controller.signal });
  } catch (e) {
    if (e && e.name === 'AbortError') e.code = 'REDACTWALL_TIMEOUT';
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchPolicy(opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const trustOptions = { ...opts, sensorId: opts.sensorId || 'mcp-guard' };
  const cached = () => {
    const result = signedPolicy.readCachedSignedPolicy(trustOptions);
    if (result.ok) policyExpiresAt = Date.parse(result.bundle.expiresAt);
    return result.ok ? result.policy : null;
  };
  if (!fetchImpl) return cached();
  const server = configuredServer(opts);
  const key = configuredKey(opts);
  if (!server || !key) return cached();
  try {
    const r = await fetchWithTimeout(fetchImpl, server + '/api/v1/policy/bundle', {
      headers: { 'x-api-key': key },
    }, opts);
    if (!r || !r.ok) {
      if (r) await cancelResponseBody(r);
      return cached();
    }
    const bundle = await readControlPlaneJson(r, opts, 'MCP policy response');
    const accepted = signedPolicy.acceptSignedPolicyBundle(bundle, trustOptions);
    if (accepted.ok) policyExpiresAt = Date.parse(accepted.bundle.expiresAt);
    return accepted.ok ? accepted.policy : cached();
  } catch (e) {
    if (!opts.silent) console.error('  policy refresh failed:', e.message);
    return cached();
  }
}

async function refreshPolicy(opts = {}) {
  const pol = await fetchPolicy(opts);
  lastPolicyAttempt = Date.now();
  if (pol) {
    detectionPolicy = normalizeDetectionPolicy(pol);
    lastPolicyRefresh = lastPolicyAttempt;
    policyTrusted = policyExpiresAt > Date.now();
  } else {
    policyTrusted = false;
    policyExpiresAt = 0;
  }
  return detectionPolicy;
}

async function maybeRefreshPolicy(opts = {}) {
  if (testPolicyOverride(opts) || opts.skipPolicyRefresh) return;
  if (Date.now() - lastPolicyAttempt < (opts.policyRefreshMs || POLICY_REFRESH_MS)) return;
  await refreshPolicy({ ...opts, silent: opts.silentPolicyRefresh !== false });
  sendHeartbeat(opts).catch(() => {});
}

function testPolicyOverride(opts = {}) {
  // Node supplies NODE_TEST_CONTEXT only to `node --test` workers. Capture it
  // at module load so an ordinary runtime caller cannot turn an inline object
  // into trusted policy by setting an option (or by mutating process.env later).
  if (!NODE_TEST_CONTEXT) return null;
  if (!Object.prototype.hasOwnProperty.call(opts, 'policy')) return null;
  return normalizeDetectionPolicy(opts.policy || {});
}

function selectedPolicy(opts = {}) {
  const explicit = testPolicyOverride(opts);
  return {
    trusted: !!explicit || (policyTrusted && policyExpiresAt > Date.now()),
    policy: explicit || detectionPolicy,
  };
}

function unavailablePolicyDecision(ctx = {}) {
  return {
    allowed: false,
    status: 'policy_unavailable',
    tool: safeToolName(ctx.tool || ctx.destination || 'mcp-tool'),
    reason: 'No trusted signed MCP policy is available',
  };
}

// Presence heartbeat: registers this guard with the control plane and returns
// the companion view (is the browser extension / endpoint agent also active
// for this identity), so wrapped agents can surface coverage gaps.
async function sendHeartbeat(opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const server = configuredServer(opts);
  const key = configuredKey(opts);
  if (!fetchImpl || !server || !key) return null;
  try {
    const r = await fetchWithTimeout(fetchImpl, server + '/api/v1/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': key },
      body: JSON.stringify({ user: opts.agent || 'mcp-agent', source: 'mcp_guard', sensor: sensorMetadata() }),
    }, opts);
    return await readControlPlaneJson(r, opts, 'MCP heartbeat response').catch(() => null);
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

const MAX_RESULT_DEPTH = 64;
const BINARY_RESULT_TYPE = /^(?:(?:input|output)_)?(?:image|audio|video|file|binary|blob|base64)(?:_(?:url|data))?$/i;
const BINARY_RESULT_KEY = /^(?:blob|base64|b64_?json|content_?base64|bytes|binary)$/i;
const BINARY_DATA_URL = /^data:[^,]*;base64,/i;
const NON_TEXT_MIME = /^(?:image|audio|video)\/|^application\/(?:octet-stream|pdf|zip|gzip)$/i;
const UNSCANNABLE_RESULT_TEXT = '[BLOCKED: MCP tool result contains binary content RedactWall cannot inspect]';
const UNINSPECTABLE_RESULT_TEXT = '[BLOCKED: MCP tool result could not be safely inspected]';

function carriesKnownBinaryResult(value, depth = 0) {
  if (depth > MAX_RESULT_DEPTH) return true;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return true;
  if (typeof ArrayBuffer !== 'undefined' && (value instanceof ArrayBuffer || ArrayBuffer.isView(value))) return true;
  if (typeof value === 'string') {
    const text = value.trim();
    if (BINARY_DATA_URL.test(text)) return true;
    if (text.startsWith('{') || text.startsWith('[')) {
      try {
        const parsed = JSON.parse(text);
        if (carriesNumericContent(parsed, { rootIsContent: Array.isArray(parsed) })) return true;
        return carriesKnownBinaryResult(parsed, depth + 1);
      } catch (_) { return false; }
    }
    return false;
  }
  if (value == null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some((item) => carriesKnownBinaryResult(item, depth + 1));
  if (typeof value.type === 'string' && BINARY_RESULT_TYPE.test(value.type)) return true;
  const mime = value.mimeType || value.mime_type || value.mime;
  if (typeof mime === 'string' && NON_TEXT_MIME.test(mime.trim())) return true;
  for (const key of Object.keys(value)) {
    if (BINARY_RESULT_KEY.test(key) && value[key] != null) return true;
    if (carriesKnownBinaryResult(value[key], depth + 1)) return true;
  }
  return false;
}

function carriesUnscannableToolResult(value, policy = detectionPolicy) {
  if (carriesKnownBinaryResult(value)) return true;
  if (carriesNumericContent(value, { rootIsContent: true })) return true;
  const detectorOptions = detectionOptions(policy);
  return carriesEncodedSensitiveText(value, (text, options) => D.analyze(text, { ...detectorOptions, ...options }));
}

function unscannableResultRecord(ctx = {}) {
  return {
    prompt: '[MCP tool result blocked] unscannable binary content',
    user: ctx.agent || 'mcp-agent',
    destination: safeToolName(ctx.tool || 'mcp-tool'),
    source: 'mcp_guard',
    channel: 'mcp_doc',
    sensor: sensorMetadata(),
    clientOutcome: 'action_blocked',
    note: 'MCP guard blocked unscannable binary tool output before model delivery',
  };
}

async function blockUnscannableToolResult(ctx = {}, opts = {}) {
  await logEvent(unscannableResultRecord(ctx), opts);
  return {
    text: UNSCANNABLE_RESULT_TEXT,
    redacted: true,
    blocked: true,
    findings: ['UNSCANNABLE_BINARY'],
  };
}

function uninspectableResultRecord(ctx = {}) {
  return {
    prompt: '[MCP tool result blocked] inspection failed',
    user: ctx.agent || 'mcp-agent',
    destination: safeToolName(ctx.tool || 'mcp-tool'),
    source: 'mcp_guard',
    channel: 'mcp_doc',
    sensor: sensorMetadata(),
    clientOutcome: 'action_blocked',
    note: 'MCP guard blocked a tool result that could not be safely inspected',
  };
}

async function blockUninspectableToolResult(ctx = {}, opts = {}) {
  await logEvent(uninspectableResultRecord(ctx), opts);
  return {
    text: UNINSPECTABLE_RESULT_TEXT,
    redacted: true,
    blocked: true,
    findings: ['UNINSPECTABLE_RESULT'],
  };
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

function reportToolArgumentBlock({ analysis, ctx, reason, findings = [] }) {
  const context = ctx && typeof ctx === 'object' ? ctx : {};
  const types = findings.length
    ? findings
    : [...new Set((analysis && analysis.findings || []).map((finding) => finding.type)
      .concat((analysis && analysis.categories || []).map((category) => category.category)))];
  return {
    prompt: `[MCP tool arguments blocked] ${types.join(', ') || 'uninspectable content'}`,
    user: context.agent || 'mcp-agent',
    destination: safeToolName(context.tool || 'mcp-tool'),
    source: 'mcp_guard',
    channel: 'mcp_tool',
    sensor: sensorMetadata(),
    clientOutcome: 'action_blocked',
    ...(analysis ? {
      clientPreRedacted: true,
      clientFindings: publicFindings(analysis),
      clientCategories: publicCategories(analysis),
      clientEntityCounts: analysis.entityCounts || {},
      clientRiskScore: analysis.riskScore || 0,
      clientMaxSeverity: analysis.maxSeverity || 0,
      clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
    } : {}),
    note: reason,
  };
}

async function logEvent(rec, opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return;
  const server = configuredServer(opts);
  const key = configuredKey(opts);
  if (!server || !key) return;
  try {
    const response = await fetchWithTimeout(fetchImpl, server + '/api/v1/gate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': key },
      body: JSON.stringify(rec),
    }, opts);
    if (response && response.body && typeof response.body.cancel === 'function') await response.body.cancel();
  } catch (e) { /* logging best-effort */ }
}

async function logToolPolicyBlock(decision, ctx = {}, opts = {}) {
  await logEvent(reportToolPolicyBody({ decision, ctx }), opts);
}

async function guardToolRequest(ctx = {}, opts = {}) {
  await maybeRefreshPolicy(opts);
  const selected = selectedPolicy(opts);
  const decision = selected.trusted
    ? mcpToolDecision(ctx, selected.policy)
    : unavailablePolicyDecision(ctx);
  if (!decision.allowed) await logToolPolicyBlock(decision, ctx, opts);
  return decision;
}

async function guardToolArguments(text, ctx = {}, opts = {}, inspection = {}) {
  await maybeRefreshPolicy(opts);
  const selected = selectedPolicy(opts);
  const toolDecision = selected.trusted
    ? mcpToolDecision(ctx, selected.policy)
    : unavailablePolicyDecision(ctx);
  if (!toolDecision.allowed) {
    await logToolPolicyBlock(toolDecision, ctx, opts);
    return toolDecision;
  }
  if (inspection.unscannable === true || carriesUnscannableToolResult(text, selected.policy)) {
    const decision = {
      allowed: false,
      status: 'unscannable_arguments',
      tool: toolDecision.tool,
      reason: 'MCP tool arguments contain content RedactWall cannot inspect',
      findings: ['UNSCANNABLE_ARGUMENTS'],
    };
    await logEvent(reportToolArgumentBlock({ ctx, reason: decision.reason, findings: decision.findings }), opts);
    return decision;
  }
  const analysis = D.analyze(text || '', detectionOptions(selected.policy));
  const findings = [...new Set(analysis.findings.map((finding) => finding.type)
    .concat(analysis.categories.map((category) => category.category)))];
  if (!findings.length) return { ...toolDecision, findings: [] };
  const decision = {
    allowed: false,
    status: 'sensitive_arguments',
    tool: toolDecision.tool,
    reason: 'MCP tool arguments contain sensitive content',
    findings,
  };
  await logEvent(reportToolArgumentBlock({ analysis, ctx, reason: decision.reason, findings }), opts);
  return decision;
}

function redactEveryFinding(text, findings = []) {
  let safe = D.redact(text, findings);
  const replaced = new Set();
  for (const finding of findings) {
    const value = typeof finding.value === 'string' ? finding.value : '';
    const key = `${finding.type}\u0000${value}`;
    if (!value || replaced.has(key)) continue;
    replaced.add(key);
    safe = safe.split(value).join(`[${finding.type}]`);
  }
  return safe;
}

/**
 * Inspect+redact a tool result string before returning it to the model.
 * @returns {Promise<{ text:string, redacted:boolean, findings:string[] }>}
 */
async function guardToolResult(text, ctx = {}, opts = {}) {
  await maybeRefreshPolicy(opts);
  const selected = selectedPolicy(opts);
  const toolDecision = selected.trusted
    ? mcpToolDecision(ctx, selected.policy)
    : unavailablePolicyDecision(ctx);
  if (!toolDecision.allowed) {
    await logToolPolicyBlock(toolDecision, ctx, opts);
    return {
      text: `[BLOCKED: ${toolDecision.reason}]`,
      redacted: true,
      blocked: true,
      findings: ['MCP_TOOL_POLICY'],
    };
  }
  if (carriesUnscannableToolResult(text, selected.policy)) {
    return blockUnscannableToolResult(ctx, opts);
  }
  const a = D.analyze(text || '', detectionOptions(selected.policy));
  const findings = [...new Set(a.findings.map(f => f.type).concat(a.categories.map(c => c.category)))];
  if (!a.findings.length && !a.categories.length) {
    return { text, redacted: false, findings: [] };
  }
  const safe = a.categories.length
    ? '[REDACTED: ' + findings.join(', ') + ']'
    : redactEveryFinding(text, a.findings); // every repeated occurrence becomes [TYPE]
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
    // Load lazily to avoid the guard <-> SDK module cycle during startup. The
    // SDK snapshots and scans arguments before it invokes the handler, then
    // sanitizes the exact result snapshot. Keeping the legacy wrapper on that
    // one boundary prevents a blocked request from causing connector effects.
    const { executeConnectorTool } = require('./sdk');
    const guarded = await executeConnectorTool(handler, args, ctx, opts);
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
  guardToolArguments,
  wrapTool,
  demo,
  reportBody,
  reportToolPolicyBody,
  reportToolArgumentBlock,
  publicFindings,
  publicCategories,
  mcpToolDecision,
  fetchPolicy,
  refreshPolicy,
  policyTrustState: () => ({ trusted: policyTrusted && policyExpiresAt > Date.now(), lastPolicyRefresh, expiresAt: policyExpiresAt }),
  _resetPolicyTrustForTest: () => {
    detectionPolicy = normalizeDetectionPolicy(DEFAULT_DETECTION_POLICY);
    lastPolicyRefresh = 0;
    lastPolicyAttempt = 0;
    policyTrusted = false;
    policyExpiresAt = 0;
  },
  detectionOptions,
  normalizeDetectionPolicy,
  configuredKey,
  logEvent,
  requestTimeoutMs,
  fetchWithTimeout,
  sensorMetadata,
  sendHeartbeat,
  carriesUnscannableToolResult,
  blockUnscannableToolResult,
  blockUninspectableToolResult,
};

// ---- demo when run directly ------------------------------------------------
if (require.main === module) demo();
