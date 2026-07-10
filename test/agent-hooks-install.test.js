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
const { spawnSync } = require('node:child_process');
const AdmZip = require('adm-zip');
const installCheck = require('../scripts/check-agent-hooks-install');

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

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
    { path: 'server/file-mutation-lock.js', body: Buffer.from('') },
    { path: 'server/private-path.js', body: Buffer.from('') },
    { path: 'detection-engine/detect.js', body: Buffer.from('') },
    { path: 'sensors/shared/decision.js', body: Buffer.from('') },
    { path: 'sensors/shared/bounded-response.js', body: Buffer.from('') },
    { path: 'sensors/shared/opaque-content.js', body: Buffer.from('') },
    { path: 'sensors/shared/signed-policy.js', body: Buffer.from('') },
    { path: 'sensors/shared/server-url.js', body: Buffer.from('') },
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
    assert.strictEqual(result.packageManifest.checks.boundedResponseReaderIncluded, true);
    assert.ok(result.packageManifest.files.some((f) => f.path === 'sensors/agent-hooks/hook.js'));
    assert.ok(result.packageManifest.files.some((f) => f.path === 'sensors/shared/bounded-response.js'));
    assert.ok(result.packageManifest.files.some((f) => f.path === 'sensors/shared/server-url.js'));
    assert.ok(result.packageManifest.files.some((f) => f.path === 'server/private-path.js'));
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test('packaged agent-hooks install check starts from a clean unpack', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph-agent-hooks-out-'));
  const unpackDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph-agent-hooks-unpack-'));
  try {
    const result = packageAgentHooks({ outDir, now: new Date('2026-07-05T00:00:00Z') });
    new AdmZip(result.zipPath).extractAllTo(unpackDir, true);
    const smoke = spawnSync(process.execPath, ['-e', "require('./scripts/check-agent-hooks-install')"], {
      cwd: unpackDir,
      encoding: 'utf8',
    });
    assert.strictEqual(smoke.status, 0, `${smoke.stdout}\n${smoke.stderr}`);
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
    fs.rmSync(unpackDir, { recursive: true, force: true });
  }
});

test('agent-hooks heartbeat refuses remote cleartext and disables redirects', async () => {
  const report = { checks: [{ id: 'agent_hooks_runtime', ok: true, detail: 'present' }] };
  await assert.rejects(() => installCheck.emitHeartbeat(report, {
    serverUrl: 'https://redactwall.example',
    ingestKey: 'unit-ingest-key',
    fetchImpl: 42,
  }), /fetch is not available/);
  let called = false;
  await assert.rejects(() => installCheck.emitHeartbeat(report, {
    serverUrl: 'http://redactwall.example',
    ingestKey: 'unit-ingest-key',
    fetchImpl: async () => { called = true; },
  }), /must use HTTPS or loopback HTTP/);
  assert.strictEqual(called, false);

  let request;
  await installCheck.emitHeartbeat(report, {
    serverUrl: 'https://redactwall.example/control/',
    ingestKey: 'unit-ingest-key',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return jsonResponse(200, { id: 'hb_hooks' });
    },
  });
  assert.strictEqual(request.url, 'https://redactwall.example/control/api/v1/heartbeat');
  assert.strictEqual(request.options.redirect, 'error');
});

test('agent-hooks heartbeat rejects an oversized streamed response', async () => {
  await assert.rejects(() => installCheck.emitHeartbeat({ checks: [] }, {
    serverUrl: 'https://redactwall.example',
    ingestKey: 'unit-ingest-key',
    maxResponseBytes: 8,
    fetchImpl: async () => jsonResponse(200, { id: 'response-is-too-large' }),
  }), /exceeds 8 byte limit/);
});
