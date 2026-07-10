'use strict';
require('../../server/env').loadEnv();
/**
 * RedactWall agent hooks (Claude Code).
 *
 * A local hook shim invoked by Claude Code for UserPromptSubmit and PreToolUse
 * events. It scans the prompt / shell command / MCP tool call ON THE BOX with
 * the shared detection engine and applies org policy — blocking secrets, PII,
 * and prompt-injection before they reach the model or the shell. Nothing is
 * sent anywhere to decide; the control plane only receives a label-only,
 * post-decision telemetry record (best effort). Every supported hook event
 * fails closed until a pinned, signed policy is available.
 *
 *   echo '<claude-code-event-json>' | node sensors/agent-hooks/hook.js
 *
 * Install into ~/.claude/settings.json with scripts/install-agent-hooks.js.
 */
const os = require('os');
const D = require('../../detection-engine/detect');
const guard = require('../mcp-guard/guard');
const { decide } = require('../shared/decision');
const VERSION = require('../../package.json').version;

const MAX_CHARS = 200000;

// Conservative policy template used by installers/tests. Runtime enforcement
// never treats this unsigned object as organization authority.
const DEFAULT_POLICY = {
  enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25,
  alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT',
    'US_ITIN', 'US_NPI', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID',
    'UK_NINO', 'UK_NHS_NUMBER', 'CANADA_SIN', 'AUSTRALIA_TFN', 'INDIA_AADHAAR',
    'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN', 'EXACT_MATCH'],
  ignore: [], disabledDetectors: [], customDetectors: [],
  mcpAllowedTools: [], mcpBlockedTools: [], mcpApprovalRequiredTools: [],
};

function parseArgs(argv) {
  const opts = { json: false, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--quiet') opts.quiet = true;
    else if (a === '--env') opts.envPath = argv[++i];
    else if (a === '--user') opts.user = argv[++i];
  }
  return opts;
}

async function readStdin(stream = process.stdin) {
  if (!stream || stream.isTTY) return '';
  let data = '';
  stream.setEncoding('utf8');
  for await (const chunk of stream) data += chunk;
  return data;
}

async function loadPolicy(opts = {}, deps = {}) {
  if (Object.prototype.hasOwnProperty.call(deps, 'trustedPolicy')) return deps.trustedPolicy;
  return guard.fetchPolicy({
    ...opts,
    silent: true,
    sensorId: 'agent-hooks',
    ...(deps.cacheFile ? { policyCachePath: deps.cacheFile } : {}),
    ...(deps.policyPublicKey ? { policyPublicKey: deps.policyPublicKey } : {}),
  }).catch(() => null);
}

// ---- event dispatch --------------------------------------------------------
function mapMcpTool(name) {
  // Claude Code names MCP tools mcp__<server>__<tool>; the policy lists use
  // <server>.<tool> wildcards.
  const m = /^mcp__([^_]+(?:_[^_]+)*?)__(.+)$/.exec(String(name || ''));
  return m ? `${m[1]}.${m[2]}` : String(name || '');
}

function extractEvent(event) {
  const name = event && event.hook_event_name;
  if (name === 'UserPromptSubmit') {
    return { channel: 'agent_prompt', text: String(event.prompt || ''), tool: null };
  }
  if (name === 'PreToolUse') {
    const tool = event.tool_name || '';
    const input = event.tool_input || {};
    if (tool === 'Bash') {
      return { channel: 'agent_shell', text: `${input.command || ''}\n${input.description || ''}`, tool: null };
    }
    if (/^mcp__/.test(tool)) {
      return { channel: 'agent_mcp', text: safeStringify(input), tool: mapMcpTool(tool) };
    }
  }
  return null; // not a hook we act on
}

function safeStringify(v) {
  try { return JSON.stringify(v || {}); } catch (_) { return ''; }
}

function labelReason(analysis, prefix) {
  const types = [...new Set((analysis.findings || []).map((f) => f.type)
    .concat((analysis.categories || []).map((c) => c.category)))];
  return `${prefix}: ${types.join(', ') || 'sensitive content'}`.slice(0, 400);
}

// ---- Claude Code protocol output -------------------------------------------
function emitDecision(kind, action, reason, io) {
  // Version-stable: exit code 2 + stderr reason is honored across Claude Code
  // versions; the JSON is the richer, current form.
  if (action === 'allow') return 0;
  const deny = action === 'block' || action === 'redact';
  if (kind === 'UserPromptSubmit') {
    io.out(JSON.stringify({ decision: deny ? 'block' : 'approve', reason }));
  } else {
    io.out(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: deny ? 'deny' : 'ask',
        permissionDecisionReason: reason,
      },
    }));
  }
  io.err(reason);
  return deny ? 2 : 0;
}

// ---- telemetry (best effort, label-only, after the decision) ---------------
function buildRecord(kind, extracted, analysis, action, opts) {
  const outcome = action === 'block' || action === 'redact' ? 'action_blocked' : 'paste_flagged';
  const base = {
    prompt: `[agent ${extracted.channel.replace('agent_', '')} ${outcome === 'action_blocked' ? 'blocked' : 'flagged'} locally] `
      + (analysis.opaqueEncoded === true ? 'OPAQUE_ENCODED_CONTENT'
        : [...new Set((analysis.findings || []).map((f) => f.type).concat((analysis.categories || []).map((c) => c.category)))].join(', ')),
    user: opts.user || process.env.REDACTWALL_AGENT_USER || process.env.PROMPTWALL_AGENT_USER || os.userInfo().username,
    destination: extracted.tool ? `claude-code:${extracted.tool}` : 'claude-code',
    source: 'agent_hooks',
    channel: extracted.channel,
    sensor: { name: 'agent_hooks', version: VERSION, platform: 'node' },
    clientOutcome: outcome,
    note: 'agent hook enforced locally before model/tool execution',
  };
  if (analysis.opaqueEncoded === true) return base;
  return {
    ...base,
    clientPreRedacted: true,
    clientFindings: guard.publicFindings(analysis),
    clientCategories: guard.publicCategories(analysis),
    clientEntityCounts: analysis.entityCounts || {},
    clientRiskScore: analysis.riskScore || 0,
    clientMaxSeverity: analysis.maxSeverity || 0,
    clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
  };
}

async function run(event, opts = {}, deps = {}) {
  const io = deps.io || { out: (s) => process.stdout.write(s + '\n'), err: (s) => process.stderr.write(s + '\n') };
  const extracted = extractEvent(event);
  if (!extracted) return { code: 0, action: 'allow' };

  const trustedPolicy = await loadPolicy(opts, deps);
  if (!trustedPolicy) {
    const reason = 'RedactWall blocked: no trusted signed policy is available';
    const code = emitDecision(event.hook_event_name, 'block', reason, io);
    return { code, action: 'block', reason };
  }
  const policy = trustedPolicy;

  // MCP tool-call policy (reuse the guard's wildcard matcher — do not reimplement).
  if (extracted.tool) {
    const toolDecision = guard.mcpToolDecision({ tool: extracted.tool }, policy);
    if (!toolDecision.allowed) {
      const reason = `RedactWall blocked MCP tool ${extracted.tool}: ${toolDecision.reason}`;
      const action = toolDecision.status === 'approval_required' ? 'warn' : 'block';
      const code = emitDecision(event.hook_event_name, action, reason, io);
      await report(buildToolRecord(extracted, toolDecision, opts), opts, deps);
      return { code, action, reason };
    }
  }

  const text = String(extracted.text || '');
  if (text.length > MAX_CHARS) {
    const analysis = { findings: [], categories: [], entityCounts: {}, riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none' };
    const reason = `RedactWall blocked: input exceeds the ${MAX_CHARS}-character local scan limit`;
    const code = emitDecision(event.hook_event_name, 'block', reason, io);
    await report(buildRecord(event.hook_event_name, extracted, analysis, 'block', opts), opts, deps);
    return { code, action: 'block', reason };
  }
  const analysis = D.analyze(text, guard.detectionOptions(policy));
  const { action } = decide(analysis, policy);
  if (action === 'allow') return { code: 0, action };

  const reason = labelReason(analysis, 'RedactWall blocked');
  const code = emitDecision(event.hook_event_name, action, reason, io);
  await report(buildRecord(event.hook_event_name, extracted, analysis, action, opts), opts, deps);
  return { code, action, reason };
}

function buildToolRecord(extracted, toolDecision, opts) {
  return {
    prompt: `[agent mcp blocked locally] ${extracted.tool}`,
    user: opts.user || process.env.REDACTWALL_AGENT_USER || process.env.PROMPTWALL_AGENT_USER || os.userInfo().username,
    destination: `claude-code:${extracted.tool}`,
    source: 'agent_hooks',
    channel: 'agent_mcp',
    sensor: { name: 'agent_hooks', version: VERSION, platform: 'node' },
    clientOutcome: 'action_blocked',
    note: toolDecision.reason || 'MCP tool blocked by policy',
  };
}

async function report(record, opts, deps = {}) {
  if (deps.report) return deps.report(record, opts);
  try { await guard.logEvent(record, opts); } catch (_) { /* best effort */ }
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const opts = parseArgs(argv);
  const io = deps.io || { out: (s) => process.stdout.write(s + '\n'), err: (s) => process.stderr.write(s + '\n') };
  const exit = deps.exit || ((code) => { process.exitCode = code; });
  try {
    const raw = deps.stdin !== undefined ? deps.stdin : await readStdin(deps.stdinStream);
    let event;
    try {
      event = JSON.parse(raw);
    } catch (_) {
      io.err('RedactWall blocked: malformed hook input');
      return exit(2);
    }
    const result = await run(event, opts, { ...deps, io });
    return exit(result.code);
  } catch (_) {
    io.err('RedactWall blocked: hook inspection failed');
    return exit(2);
  }
}

if (require.main === module) main();

module.exports = { main, run, extractEvent, mapMcpTool, buildRecord, loadPolicy, DEFAULT_POLICY };
