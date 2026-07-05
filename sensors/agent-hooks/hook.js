'use strict';
require('../../server/env').loadEnv();
/**
 * PromptWall agent hooks (Claude Code).
 *
 * A local hook shim invoked by Claude Code for UserPromptSubmit and PreToolUse
 * events. It scans the prompt / shell command / MCP tool call ON THE BOX with
 * the shared detection engine and applies org policy — blocking secrets, PII,
 * and prompt-injection before they reach the model or the shell. Nothing is
 * sent anywhere to decide; the control plane only receives a label-only,
 * post-decision telemetry record (best effort). Fails OPEN on any internal
 * error so it never breaks the agent; exits 2 only to deliberately block.
 *
 *   echo '<claude-code-event-json>' | node sensors/agent-hooks/hook.js
 *
 * Install into ~/.claude/settings.json with scripts/install-agent-hooks.js.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const D = require('../../detection-engine/detect');
const guard = require('../mcp-guard/guard');
const { decide } = require('../shared/decision');
const VERSION = require('../../package.json').version;

const MAX_CHARS = 200000;
const POLICY_REFRESH_MS = 15 * 60 * 1000;
const CACHE_DIR = path.join(os.homedir(), '.promptwall');
const CACHE_FILE = path.join(CACHE_DIR, 'agent-hooks-policy.json');

// Conservative built-in policy when no cache and the control plane is
// unreachable — mirrors sensors/browser-extension/background.js DEFAULTS so a
// fresh install still hard-blocks the obvious secrets/PII.
const DEFAULT_POLICY = {
  enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25,
  alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'US_ITIN', 'US_NPI',
    'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID',
    'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'],
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

// ---- policy: cached to disk, refreshed lazily; enforcement is fully local ----
function readCachedPolicy(now = Date.now(), deps = {}) {
  const read = deps.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  try {
    const cached = JSON.parse(read(deps.cacheFile || CACHE_FILE));
    return { policy: cached.policy, fresh: now - (cached.fetchedAt || 0) < POLICY_REFRESH_MS };
  } catch (_) { return { policy: null, fresh: false }; }
}

function writeCachedPolicy(policy, now = Date.now(), deps = {}) {
  const write = deps.writeFile || ((p, d) => {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, d, { mode: 0o600 });
  });
  try { write(deps.cacheFile || CACHE_FILE, JSON.stringify({ policy, fetchedAt: now })); } catch (_) { /* best effort */ }
}

async function loadPolicy(opts = {}, deps = {}) {
  const now = deps.now || Date.now();
  const cached = readCachedPolicy(now, deps);
  if (cached.policy && cached.fresh) return cached.policy;
  const fetched = await guard.fetchPolicy({ ...opts, silent: true }).catch(() => null);
  if (fetched) { writeCachedPolicy(fetched, now, deps); return fetched; }
  return cached.policy || DEFAULT_POLICY;
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
  return {
    prompt: `[agent ${extracted.channel.replace('agent_', '')} ${outcome === 'action_blocked' ? 'blocked' : 'flagged'} locally] `
      + [...new Set((analysis.findings || []).map((f) => f.type).concat((analysis.categories || []).map((c) => c.category)))].join(', '),
    user: opts.user || process.env.PROMPTWALL_AGENT_USER || os.userInfo().username,
    destination: extracted.tool ? `claude-code:${extracted.tool}` : 'claude-code',
    source: 'agent_hooks',
    channel: extracted.channel,
    sensor: { name: 'agent_hooks', version: VERSION, platform: 'node' },
    clientOutcome: outcome,
    clientPreRedacted: true,
    clientFindings: guard.publicFindings(analysis),
    clientCategories: guard.publicCategories(analysis),
    clientEntityCounts: analysis.entityCounts || {},
    clientRiskScore: analysis.riskScore || 0,
    clientMaxSeverity: analysis.maxSeverity || 0,
    clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
    note: 'agent hook enforced locally before model/tool execution',
  };
}

async function run(event, opts = {}, deps = {}) {
  const io = deps.io || { out: (s) => process.stdout.write(s + '\n'), err: (s) => process.stderr.write(s + '\n') };
  const extracted = extractEvent(event);
  if (!extracted) return { code: 0, action: 'allow' };

  const policy = await loadPolicy(opts, deps);

  // MCP tool-call policy (reuse the guard's wildcard matcher — do not reimplement).
  if (extracted.tool) {
    const toolDecision = guard.mcpToolDecision({ tool: extracted.tool }, policy);
    if (!toolDecision.allowed) {
      const reason = `PromptWall blocked MCP tool ${extracted.tool}: ${toolDecision.reason}`;
      const action = toolDecision.status === 'approval_required' ? 'warn' : 'block';
      const code = emitDecision(event.hook_event_name, action, reason, io);
      await report(buildToolRecord(extracted, toolDecision, opts), opts, deps);
      return { code, action, reason };
    }
  }

  const text = String(extracted.text || '').slice(0, MAX_CHARS);
  const analysis = D.analyze(text, {
    ignore: policy.ignore, disabledDetectors: policy.disabledDetectors, customDetectors: policy.customDetectors,
  });
  const { action } = decide(analysis, policy);
  if (action === 'allow') return { code: 0, action };

  const reason = labelReason(analysis, 'PromptWall blocked');
  const code = emitDecision(event.hook_event_name, action, reason, io);
  await report(buildRecord(event.hook_event_name, extracted, analysis, action, opts), opts, deps);
  return { code, action, reason };
}

function buildToolRecord(extracted, toolDecision, opts) {
  return {
    prompt: `[agent mcp blocked locally] ${extracted.tool}`,
    user: opts.user || process.env.PROMPTWALL_AGENT_USER || os.userInfo().username,
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
    try { event = JSON.parse(raw); } catch (_) { return exit(0); } // malformed → fail open
    const result = await run(event, opts, { ...deps, io });
    return exit(result.code);
  } catch (_) {
    // Never break the agent on an internal error.
    return exit(0);
  }
}

if (require.main === module) main();

module.exports = { main, run, extractEvent, mapMcpTool, buildRecord, loadPolicy, DEFAULT_POLICY };
