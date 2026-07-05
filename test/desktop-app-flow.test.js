'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const desktopAppFlow = require('../sensors/endpoint-agent/collectors/desktop-app-flow');
const aiToolInventory = require('../sensors/endpoint-agent/collectors/ai-tool-inventory');
const agent = require('../sensors/endpoint-agent/agent');

function tempDir(t, prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('app flow settings require an explicit opt-in and derive the guarded base dir', () => {
  assert.strictEqual(desktopAppFlow.appFlowSettings({}, '/tmp/watch').enabled, false);
  const enabled = desktopAppFlow.appFlowSettings({ ENDPOINT_AGENT_APP_FLOW: '1' }, '/tmp/watch');
  assert.strictEqual(enabled.enabled, true);
  assert.strictEqual(enabled.baseDir, path.join('/tmp/watch', 'AI Apps'));
  const custom = desktopAppFlow.appFlowSettings({ REDACTWALL_ENDPOINT_AGENT_APP_FLOW_DIR: '/srv/guarded' }, '');
  assert.strictEqual(custom.enabled, true);
  assert.strictEqual(custom.baseDir, path.resolve('/srv/guarded'));
});

test('guarded folders are provisioned only for detected desktop AI apps', (t) => {
  const base = tempDir(t, 'ps-app-flow-');
  const profiles = desktopAppFlow.desktopAppFlowProfiles({
    settings: { enabled: true, baseDir: base },
    detected: ['chatgpt_desktop', 'copilot'],
  });
  assert.deepStrictEqual(profiles.map((p) => p.id), ['app_flow_chatgpt_desktop', 'app_flow_copilot']);
  assert.deepStrictEqual(profiles.map((p) => p.destination), ['ChatGPT Desktop', 'Microsoft Copilot']);
  for (const profile of profiles) {
    assert.ok(fs.statSync(profile.dir).isDirectory(), 'guarded folder is created');
    assert.ok(profile.dir.startsWith(base));
  }
});

test('app flow profiles stay empty when disabled and skip unknown or non-desktop tools', () => {
  assert.deepStrictEqual(desktopAppFlow.desktopAppFlowProfiles({
    settings: { enabled: false, baseDir: '/tmp/x' },
    detected: ['chatgpt_desktop'],
  }), []);
  const profiles = desktopAppFlow.desktopAppFlowProfiles({
    settings: { enabled: true, baseDir: '/tmp/x' },
    detected: ['gemini_cli', 'codex_cli', 'not_a_tool'],
    ensureDirs: false,
  });
  assert.deepStrictEqual(profiles, []);
});

test('detection falls back to the sanitized AI tool inventory', (t) => {
  const binDir = tempDir(t, 'ps-app-flow-bin-');
  fs.writeFileSync(path.join(binDir, 'Cursor.exe'), 'stub');
  const profiles = desktopAppFlow.desktopAppFlowProfiles({
    settings: { enabled: true, baseDir: tempDir(t, 'ps-app-flow-base-') },
    env: { PATH: binDir },
    platform: 'win32',
    processNames: [],
  });
  assert.deepStrictEqual(profiles.map((p) => p.id), ['app_flow_cursor']);
});

test('public app flow checks expose tool ids and counts but never local paths', (t) => {
  const base = tempDir(t, 'ps-app-flow-checks-');
  const profiles = desktopAppFlow.desktopAppFlowProfiles({
    settings: { enabled: true, baseDir: base },
    detected: ['claude_desktop'],
  });
  const checks = desktopAppFlow.publicAppFlowChecks(profiles, (dir) => fs.existsSync(dir));
  assert.deepStrictEqual(checks.map((c) => c.id), ['endpoint_app_flow', 'endpoint_app_flow_claude_desktop']);
  assert.strictEqual(checks[0].detail, 'guarded apps:1');
  assert.strictEqual(checks[1].ok, true);
  assert.ok(!JSON.stringify(checks).includes(base), 'checks never leak local paths');
  const missing = desktopAppFlow.publicAppFlowChecks(profiles, () => false);
  assert.strictEqual(missing[1].ok, false);
  assert.strictEqual(missing[1].detail, 'guarded folder missing');
  assert.deepStrictEqual(desktopAppFlow.publicAppFlowChecks([], () => true)[0].detail, 'disabled');
});

test('copilot ships as a known desktop AI tool signature', () => {
  const copilot = aiToolInventory.KNOWN_AI_TOOLS.find((tool) => tool.id === 'copilot');
  assert.ok(copilot, 'copilot signature present');
  assert.strictEqual(copilot.label, 'Microsoft Copilot');
});

test('endpoint agent start watches guarded app folders alongside file-flow profiles', async (t) => {
  const guarded = tempDir(t, 'ps-app-flow-watch-');
  const scans = [];
  const watched = [];
  fs.writeFileSync(path.join(guarded, 'seeded.txt'), 'staged for upload');
  const started = agent.start({
    console: { log: () => {} },
    watchDir: '/tmp/primary-watch',
    server: 'https://redactwall.example',
    key: 'ingest-key-configured',
    refreshPolicy: async () => {},
    scanFile: (filename, opts) => scans.push({ filename, opts }),
    readdirSync: (dir) => (dir === guarded ? fs.readdirSync(dir) : []),
    setInterval: () => ({ unref: () => {} }),
    setTimeout: (fn) => { fn(); return null; },
    watch: (dir) => { watched.push(dir); return { close() {} }; },
    fileFlowProfiles: [],
    appFlowProfiles: [{ id: 'app_flow_claude_desktop', dir: guarded, destination: 'Claude Desktop' }],
  });
  await started.initialRefresh;
  assert.ok(watched.includes(guarded), 'guarded app folder is watched');
  const scanned = scans.find((item) => item.filename === 'seeded.txt');
  assert.ok(scanned, 'staged file is scanned');
  assert.strictEqual(scanned.opts.destination, 'Claude Desktop');
  assert.strictEqual(scanned.opts.watchDir, guarded);
});
