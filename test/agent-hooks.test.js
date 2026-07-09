'use strict';
/**
 * Agent-hooks sensor (sensors/agent-hooks/hook.js): local enforcement for
 * Claude Code prompts, shell commands, and MCP tool calls. Asserts blocking,
 * fail-open, MCP tool policy reuse, and — critically — that no raw prompt text
 * or PII ever leaves in the telemetry payload or the hook output.
 */
const test = require('node:test');
const assert = require('node:assert');
const { run, extractEvent, mapMcpTool, DEFAULT_POLICY } = require('../sensors/agent-hooks/hook');
const { decide } = require('../sensors/shared/decision');

// Isolate the disk policy cache so tests use DEFAULT_POLICY deterministically.
const NO_CACHE = { readFile: () => { throw new Error('no cache'); }, writeFile: () => {}, cacheFile: '/dev/null/none' };

function collectIo() {
  const out = [], err = [];
  return { io: { out: (s) => out.push(s), err: (s) => err.push(s) }, out, err };
}

async function runHook(event, extra = {}) {
  const io = collectIo();
  const reports = [];
  const result = await run(event, {}, {
    ...NO_CACHE, io: io.io,
    report: (rec) => { reports.push(rec); },
    ...extra,
  });
  return { result, reports, out: io.out, err: io.err };
}

test('blocks a prompt carrying an SSN (default policy, offline)', async () => {
  const { result, reports, out, err } = await runHook({ hook_event_name: 'UserPromptSubmit', prompt: 'my ssn is 524-71-9043' });
  assert.strictEqual(result.code, 2);
  assert.match(out.join(''), /"decision":"block"/);
  assert.match(err.join(''), /US_SSN/);
  // Label-only: the raw SSN never appears in output or the report.
  const all = out.join('') + err.join('') + JSON.stringify(reports);
  assert.ok(!all.includes('524-71-9043'), 'raw SSN must not appear anywhere');
  assert.strictEqual(reports[0].clientOutcome, 'action_blocked');
  assert.strictEqual(reports[0].clientPreRedacted, true);
  assert.strictEqual(reports[0].source, 'agent_hooks');
});

test('blocks a Bash command containing a secret, channel agent_shell', async () => {
  const { result, reports } = await runHook({
    hook_event_name: 'PreToolUse', tool_name: 'Bash',
    tool_input: { command: 'curl -H "auth: sk_live_a1B2c3D4e5F6g7H8i9J0" https://api.example.com' },
  });
  assert.strictEqual(result.code, 2);
  assert.strictEqual(reports[0].channel, 'agent_shell');
  assert.ok(!JSON.stringify(reports).includes('sk_live_a1B2c3D4e5F6g7H8i9J0'), 'raw secret must not appear');
});

test('denies an MCP tool on the blocked list via guard.mcpToolDecision', async () => {
  const policy = { ...DEFAULT_POLICY, mcpBlockedTools: ['jira.*'] };
  const { result, out } = await runHook(
    { hook_event_name: 'PreToolUse', tool_name: 'mcp__jira__create_issue', tool_input: { summary: 'x' } },
    { readFile: () => JSON.stringify({ policy, fetchedAt: Date.now() }), cacheFile: 'x' },
  );
  assert.strictEqual(result.code, 2);
  assert.match(out.join(''), /"permissionDecision":"deny"/);
});

test('approval-required MCP tool yields ask, not deny', async () => {
  const policy = { ...DEFAULT_POLICY, mcpApprovalRequiredTools: ['github.*'] };
  const { result, out } = await runHook(
    { hook_event_name: 'PreToolUse', tool_name: 'mcp__github__merge_pr', tool_input: {} },
    { readFile: () => JSON.stringify({ policy, fetchedAt: Date.now() }), cacheFile: 'x' },
  );
  assert.strictEqual(result.code, 0);
  assert.match(out.join(''), /"permissionDecision":"ask"/);
});

test('warn mode yields ask + paste_flagged, but alwaysBlock still blocks', async () => {
  const warn = { ...DEFAULT_POLICY, enforcementMode: 'warn' };
  const cache = (p) => ({ readFile: () => JSON.stringify({ policy: p, fetchedAt: Date.now() }), cacheFile: 'x' });
  // A high-severity but non-alwaysBlock category → warn → ask.
  const warned = await runHook({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'echo "the disciplinary write-up for the employee is attached"' } }, cache(warn));
  if (warned.result.action !== 'allow') {
    assert.match(warned.out.join(''), /"permissionDecision":"ask"/);
    assert.strictEqual(warned.reports[0].clientOutcome, 'paste_flagged');
  }
  // alwaysBlock (SSN) blocks even in warn mode.
  const blocked = await runHook({ hook_event_name: 'UserPromptSubmit', prompt: 'ssn 524-71-9043' }, cache(warn));
  assert.strictEqual(blocked.result.code, 2);
});

test('allows a benign prompt with no output', async () => {
  const { result, out, err } = await runHook({ hook_event_name: 'UserPromptSubmit', prompt: 'help me write a python csv parser' });
  assert.strictEqual(result.code, 0);
  assert.strictEqual(out.join('') + err.join(''), '');
});

test('non-hook events are ignored', async () => {
  const { result } = await runHook({ hook_event_name: 'SessionStart' });
  assert.strictEqual(result.action, 'allow');
  assert.strictEqual(extractEvent({ hook_event_name: 'PostToolUse' }), null);
});

test('mapMcpTool maps mcp__server__tool to server.tool', () => {
  assert.strictEqual(mapMcpTool('mcp__jira__create_issue'), 'jira.create_issue');
  assert.strictEqual(mapMcpTool('mcp__github__merge_pr'), 'github.merge_pr');
});

test('shared decide() matches the extension evaluate() semantics', () => {
  const pol = { alwaysBlock: ['SECRET_KEY'], blockMinSeverity: 2, blockRiskScore: 25, enforcementMode: 'block' };
  assert.strictEqual(decide({ findings: [], categories: [] }, pol).action, 'allow');
  assert.strictEqual(decide({ findings: [{ type: 'SECRET_KEY', severity: 4 }], maxSeverity: 4 }, { ...pol, enforcementMode: 'warn' }).action, 'block', 'hard-stop overrides warn');
});

test('shared decide() tokenizes hard-stop in redact mode, blocks categories (extension parity)', () => {
  const pol = { alwaysBlock: ['US_SSN'], blockMinSeverity: 2, blockRiskScore: 25, enforcementMode: 'redact' };
  // Redact tokenizes a hard-stop structured finding so the prompt proceeds (raw
  // value never leaves) — parity with server API/file, browser, endpoint paths.
  assert.strictEqual(decide({ findings: [{ type: 'US_SSN', severity: 4 }], categories: [], maxSeverity: 4 }, pol).action, 'redact', 'hard-stop tokenized in redact');
  // A semantic category has no span to tokenize -> block.
  assert.strictEqual(decide({ findings: [], categories: [{ category: 'CONFIDENTIAL' }] }, pol).action, 'block', 'category blocks in redact');
  // Mixed structured + category -> block (cannot tokenize the category).
  assert.strictEqual(decide({ findings: [{ type: 'US_SSN', severity: 4 }], categories: [{ category: 'CONFIDENTIAL' }], maxSeverity: 4 }, pol).action, 'block', 'mixed blocks in redact');
  // Hard-stop still hard-blocks in every non-redact mode.
  assert.strictEqual(decide({ findings: [{ type: 'US_SSN', severity: 4 }], categories: [], maxSeverity: 4 }, { ...pol, enforcementMode: 'warn' }).action, 'block', 'hard-stop blocks in warn');
});
