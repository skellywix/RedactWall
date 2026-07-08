'use strict';
/**
 * Installer + packager for the agent-hooks sensor. Asserts idempotent merge,
 * uninstall of only RedactWall-owned entries, and that the ingest key is never
 * written into settings.json.
 */
const test = require('node:test');
const assert = require('node:assert');
const { mergeHooks, removeHooks, ownsEntry, desiredConfig } = require('../scripts/install-agent-hooks');
const { validateRuntimeFiles, packageAgentHooks } = require('../scripts/package-agent-hooks');
const fs = require('fs');
const os = require('os');
const path = require('path');

test('merge is idempotent and adds both hook events', () => {
  const once = mergeHooks({});
  const twice = mergeHooks(once);
  assert.ok(Array.isArray(once.hooks.UserPromptSubmit));
  assert.ok(Array.isArray(once.hooks.PreToolUse));
  assert.strictEqual(twice.hooks.UserPromptSubmit.length, 1, 'no duplicate entries on re-run');
  assert.strictEqual(twice.hooks.PreToolUse.length, 1);
  assert.strictEqual(twice.hooks.PreToolUse[0].matcher, 'Bash|mcp__.*');
});

test('merge preserves foreign hook entries', () => {
  const foreign = { hooks: { PreToolUse: [{ matcher: 'Write', hooks: [{ type: 'command', command: 'other-tool' }] }] } };
  const merged = mergeHooks(foreign);
  assert.ok(merged.hooks.PreToolUse.some((e) => e.hooks[0].command === 'other-tool'), 'foreign entry kept');
  assert.ok(merged.hooks.PreToolUse.some(ownsEntry), 'our entry added');
});

test('ownership survives Windows-style backslash paths (cross-platform)', () => {
  // A hookPath built by path.join on Windows uses backslashes, so the command
  // written into settings.json is 'node "…\\agent-hooks\\hook.js" --quiet'.
  // ownsEntry must still recognize it, or merge duplicates and uninstall no-ops.
  // Passing the path explicitly makes this fail on any OS if the bug returns.
  const winPath = 'C:\\Users\\Jane\\redactwall\\sensors\\agent-hooks\\hook.js';
  const once = mergeHooks({}, winPath);
  assert.ok(once.hooks.PreToolUse.some(ownsEntry), 'own entry recognized with backslash path');
  const twice = mergeHooks(once, winPath);
  assert.strictEqual(twice.hooks.PreToolUse.length, 1, 'idempotent with backslash path');
  assert.strictEqual(twice.hooks.UserPromptSubmit.length, 1);
});

test('uninstall removes only RedactWall-owned entries', () => {
  const foreign = { hooks: { PreToolUse: [{ matcher: 'Write', hooks: [{ type: 'command', command: 'other-tool' }] }] } };
  const merged = mergeHooks(foreign);
  const removed = removeHooks(merged);
  assert.ok(!removed.hooks || !(removed.hooks.PreToolUse || []).some(ownsEntry), 'our entry gone');
  assert.ok(removed.hooks.PreToolUse.some((e) => e.hooks[0].command === 'other-tool'), 'foreign entry kept');
});

test('the hooks JSON never contains the ingest key', () => {
  const cfg = JSON.stringify(desiredConfig());
  assert.ok(!/x-api-key|INGEST_API_KEY/.test(cfg));
});

test('package rejects an installer that writes the ingest key', () => {
  const bad = [
    { path: 'package.json', body: Buffer.from('{}') },
    { path: 'server/env.js', body: Buffer.from('') },
    { path: 'detection-engine/detect.js', body: Buffer.from('') },
    { path: 'sensors/shared/decision.js', body: Buffer.from('') },
    { path: 'sensors/mcp-guard/guard.js', body: Buffer.from('') },
    { path: 'sensors/agent-hooks/hook.js', body: Buffer.from('hook_event_name decide(') },
    { path: 'scripts/install-agent-hooks.js', body: Buffer.from('settings.hooks["x-api-key"] = key;') },
    { path: 'scripts/check-agent-hooks-install.js', body: Buffer.from('') },
  ];
  assert.throws(() => validateRuntimeFiles(bad), /never write the ingest key/);
});

test('package builds a prompt-free zip with a manifest', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph-agent-hooks-'));
  try {
    const result = packageAgentHooks({ outDir, now: new Date('2026-07-05T00:00:00Z') });
    assert.ok(fs.existsSync(result.zipPath));
    assert.strictEqual(result.packageManifest.checks.installerNeverWritesKey, true);
    assert.ok(result.packageManifest.files.some((f) => f.path === 'sensors/agent-hooks/hook.js'));
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});
