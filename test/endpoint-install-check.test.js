'use strict';
/** Endpoint install validation should be useful and secret-free. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  buildHeartbeatBody,
  buildInstallReport,
  defaultEndpointEnvPath,
  emitHeartbeat,
  main,
  ocrExtractionCheck,
  parseArgs,
  printHuman,
  readEndpointConfig,
} = require('../scripts/check-endpoint-install');

const root = path.join(__dirname, '..');

function tempDir(t, prefix = 'ps-endpoint-check-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('endpoint install check validates runtime wiring without exposing secrets', async (t) => {
  const dir = tempDir(t);
  const watchDir = path.join(dir, 'watch');
  const handoffDir = path.join(dir, 'handoff');
  const lendingFlowDir = path.join(dir, 'lending-flow');
  fs.mkdirSync(watchDir, { recursive: true });
  fs.mkdirSync(handoffDir, { recursive: true });
  fs.mkdirSync(lendingFlowDir, { recursive: true });
  const envPath = path.join(dir, 'endpoint-agent.env');
  const ingestKey = 'pilot-ingest-key-000000000000000000000000000002';
  const handoffSecret = 'native-handoff-secret-000000000000000002';
  const profiles = JSON.stringify([
    { id: 'lending', dir: lendingFlowDir, destination: 'Copilot Desktop' },
  ]);
  fs.writeFileSync(envPath, [
    'REDACTWALL_URL=https://redactwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    `ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${handoffDir}`,
    `ENDPOINT_AGENT_HANDOFF_SECRET=${handoffSecret}`,
    `ENDPOINT_AGENT_FILE_FLOW_PROFILES=${profiles}`,
    'REDACTWALL_TENANT_ID=cu-acme',
  ].join('\n') + '\n');

  const report = buildInstallReport({
    envPath,
    repoRoot: root,
    requireDesktopCollector: true,
    env: {},
  });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.every((item) => item.ok), JSON.stringify(report.checks));
  assert.ok(report.checks.some((item) => item.id === 'desktop_collector_runtime'));
  assert.ok(report.checks.some((item) => item.id === 'clipboard_guard_runtime'));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_ocr_runtime'));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_ocr_config' && item.ok && item.detail === 'disabled'));
  assert.ok(report.checks.some((item) => item.id === 'ai_tool_inventory_runtime'));
  assert.ok(report.checks.some((item) => item.id === 'ai_tool_inventory' && item.ok));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_file_flow_profiles' && item.ok && item.detail === 'configured:1'));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_file_flow_profile_lending' && item.ok));
  assert.ok(!JSON.stringify(report).includes(ingestKey));
  assert.ok(!JSON.stringify(report).includes(handoffSecret));
  assert.ok(!JSON.stringify(report).includes(lendingFlowDir));

  const heartbeat = buildHeartbeatBody(report, {
    envPath,
    env: {},
    user: 'tech@example.test',
    destination: 'endpoint-install',
  });
  assert.strictEqual(heartbeat.user, 'tech@example.test');
  assert.strictEqual(heartbeat.orgId, 'cu-acme');
  assert.strictEqual(heartbeat.source, 'endpoint_agent');
  assert.strictEqual(heartbeat.destination, 'endpoint-install');
  assert.strictEqual(heartbeat.sensor.name, 'endpoint_agent');
  assert.ok(heartbeat.checks.some((item) => item.id === 'ingest_key' && item.ok));
  assert.ok(!JSON.stringify(heartbeat).includes(ingestKey));
  assert.ok(!JSON.stringify(heartbeat).includes(handoffSecret));

  const requests = [];
  const response = await emitHeartbeat(report, {
    envPath,
    env: {},
    user: 'tech@example.test',
    fetchImpl: async (url, opts = {}) => {
      requests.push({ url, opts });
      assert.strictEqual(url, 'https://redactwall.customer.example/api/v1/heartbeat');
      assert.strictEqual(opts.headers['x-api-key'], ingestKey);
      assert.ok(!opts.body.includes(ingestKey));
      assert.ok(!opts.body.includes(handoffSecret));
      const body = JSON.parse(opts.body);
      assert.strictEqual(body.source, 'endpoint_agent');
      assert.ok(body.checks.every((item) => item.ok));
      assert.ok(!opts.body.includes(lendingFlowDir));
      return {
        ok: true,
        status: 200,
        json: async () => ({ id: 'q_heartbeat', decision: 'recorded', status: 'sensor_heartbeat', failedChecks: [] }),
      };
    },
  });
  assert.strictEqual(requests.length, 1);
  assert.strictEqual(response.id, 'q_heartbeat');
});

test('endpoint install check reports unapproved endpoint AI tools without failing install status', (t) => {
  const dir = tempDir(t, 'ps-endpoint-check-ai-tools-');
  const watchDir = path.join(dir, 'watch');
  fs.mkdirSync(watchDir, { recursive: true });
  const envPath = path.join(dir, 'endpoint-agent.env');
  fs.writeFileSync(envPath, [
    'REDACTWALL_URL=https://redactwall.customer.example',
    'INGEST_API_KEY=pilot-ingest-key-000000000000000000000000000004',
    `ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    'ENDPOINT_AGENT_APPROVED_AI_TOOLS=cursor,claude_code',
  ].join('\n') + '\n');

  const report = buildInstallReport({
    envPath,
    repoRoot: root,
    env: {},
    processNames: ['Cursor.exe', 'C:\\Users\\analyst\\AppData\\Local\\Programs\\Claude\\Claude.exe --profile rawargument'],
  });

  assert.strictEqual(report.status, 'ok');
  assert.deepStrictEqual(report.failedChecks, []);
  assert.deepStrictEqual(report.endpointAiToolAttention, ['claude_desktop']);
  assert.ok(report.checks.some((item) => item.id === 'ai_tool_cursor' && item.ok));
  assert.ok(report.checks.some((item) => item.id === 'ai_tool_claude_desktop' && !item.ok && item.detail === 'unapproved detected'));
  assert.ok(!JSON.stringify(report).includes('Programs\\Claude'));
  assert.ok(!JSON.stringify(report).includes('rawargument'));
  assert.ok(!JSON.stringify(report).includes('pilot-ingest-key'));
});

test('endpoint install check reports attention for missing desktop collector prerequisites', (t) => {
  const dir = tempDir(t, 'ps-endpoint-check-attention-');
  const envPath = path.join(dir, 'endpoint-agent.env');
  fs.writeFileSync(envPath, [
    'REDACTWALL_URL=https://redactwall.customer.example',
    'INGEST_API_KEY=too-short',
    `ENDPOINT_AGENT_WATCH_DIR=${path.join(dir, 'missing-watch')}`,
  ].join('\n') + '\n');

  const report = buildInstallReport({
    envPath,
    repoRoot: root,
    requireDesktopCollector: true,
    env: {},
  });
  assert.strictEqual(report.status, 'attention');
  assert.ok(report.checks.some((item) => item.id === 'ingest_key' && !item.ok));
  assert.ok(report.checks.some((item) => item.id === 'watch_dir' && !item.ok));
  assert.ok(report.checks.some((item) => item.id === 'handoff_secret' && !item.ok));
  assert.ok(!JSON.stringify(report).includes('too-short'));
});

test('endpoint install check reports attention for unusable explicit OCR command', (t) => {
  const dir = tempDir(t, 'ps-endpoint-check-ocr-');
  const watchDir = path.join(dir, 'watch');
  fs.mkdirSync(watchDir, { recursive: true });
  const envPath = path.join(dir, 'endpoint-agent.env');
  fs.writeFileSync(envPath, [
    'REDACTWALL_URL=https://redactwall.customer.example',
    'INGEST_API_KEY=pilot-ingest-key-000000000000000000000000000003',
    `ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    `ENDPOINT_AGENT_OCR_COMMAND=${path.join(dir, 'missing-ocr.exe')}`,
  ].join('\n') + '\n');

  const report = buildInstallReport({
    envPath,
    repoRoot: root,
    env: {},
  });

  assert.strictEqual(report.status, 'attention');
  assert.ok(report.checks.some((item) => item.id === 'endpoint_ocr_runtime' && item.ok));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_ocr_config' && !item.ok));
  assert.ok(!JSON.stringify(report).includes('pilot-ingest-key'));
});

test('endpoint install check reports missing file-flow profile directories without leaking paths', (t) => {
  const dir = tempDir(t, 'ps-endpoint-check-file-flow-');
  const watchDir = path.join(dir, 'watch');
  const missingFlowDir = path.join(dir, 'member-524-71-9043-flow');
  fs.mkdirSync(watchDir, { recursive: true });
  const envPath = path.join(dir, 'endpoint-agent.env');
  fs.writeFileSync(envPath, [
    'REDACTWALL_URL=https://redactwall.customer.example',
    'INGEST_API_KEY=pilot-ingest-key-000000000000000000000000000005',
    `ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    `ENDPOINT_AGENT_FILE_FLOW_PROFILES=${JSON.stringify([{ id: 'member-flow', dir: missingFlowDir, destination: 'Desktop AI' }])}`,
  ].join('\n') + '\n');

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'attention');
  assert.ok(report.failedChecks.includes('endpoint_file_flow_profile_member_flow'));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_file_flow_profiles' && item.detail === 'configured:1'));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_file_flow_profile_member_flow' && !item.ok && item.detail === 'missing directory'));
  assert.ok(!JSON.stringify(report).includes(missingFlowDir));
  assert.ok(!JSON.stringify(report).includes('524-71-9043'));
});

test('endpoint install check accepts env aliases, default paths, and shell OCR commands', (t) => {
  const dir = tempDir(t, 'ps-endpoint-check-aliases-');
  const watchDir = path.join(dir, 'watch');
  fs.mkdirSync(watchDir, { recursive: true });
  const envPath = path.join(dir, 'endpoint-agent.env');
  const aliasKey = 'alias-ingest-key-0000000000000000000000000001';
  fs.writeFileSync(envPath, [
    'REDACTWALL_URL=https://redactwall.alias.example/path',
    `REDACTWALL_INGEST_API_KEY=${aliasKey}`,
    `REDACTWALL_ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    'REDACTWALL_ENDPOINT_AGENT_OCR_COMMAND=tesseract',
    'REDACTWALL_TENANT_ID=cu-alias',
  ].join('\n') + '\n');

  const config = readEndpointConfig(envPath, {}).config;
  assert.strictEqual(config.INGEST_API_KEY, aliasKey);
  assert.strictEqual(defaultEndpointEnvPath({ LOCALAPPDATA: 'C:\\Temp' }, 'win32'), 'C:\\Temp\\RedactWall\\endpoint-agent.env');
  assert.match(defaultEndpointEnvPath({ HOME: '/tmp/home' }, 'linux').replace(/\\/g, '/'), /\/tmp\/home\/.config\/redactwall\/endpoint-agent\.env$/);

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.some((item) => item.id === 'server_url' && item.detail === 'https://redactwall.alias.example'));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_ocr_config' && item.ok && item.detail === 'configured'));
  assert.ok(!JSON.stringify(report).includes(aliasKey));

  const invalidEnvPath = path.join(dir, 'invalid-endpoint-agent.env');
  fs.writeFileSync(invalidEnvPath, [
    'REDACTWALL_URL=https://bad host%%%/prompt',
    `REDACTWALL_INGEST_API_KEY=${aliasKey}`,
    `REDACTWALL_ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
  ].join('\n') + '\n');
  const invalidUrlReport = buildInstallReport({
    envPath: invalidEnvPath,
    repoRoot: root,
    env: {},
  });
  assert.ok(invalidUrlReport.checks.some((item) => item.id === 'server_url' && !item.ok && item.detail === 'missing or invalid'));
});

test('endpoint heartbeat and human output cover failure branches without leaking secrets', async () => {
  const report = { status: 'ok', checks: [{ id: 'ingest_key', ok: true, detail: 'configured' }] };
  await assert.rejects(() => emitHeartbeat(report, { config: { INGEST_API_KEY: 'key-0000000000000001' } }), /REDACTWALL_URL/);
  await assert.rejects(() => emitHeartbeat(report, { config: { REDACTWALL_URL: 'https://redactwall.example' } }), /INGEST_API_KEY/);
  const originalFetch = globalThis.fetch;
  delete globalThis.fetch;
  try {
    await assert.rejects(() => emitHeartbeat(report, {
      config: {
        REDACTWALL_URL: 'https://redactwall.example',
        INGEST_API_KEY: 'key-0000000000000001',
      },
    }), /fetch is not available/);
  } finally {
    globalThis.fetch = originalFetch;
  }
  await assert.rejects(() => emitHeartbeat(report, {
    config: {
      REDACTWALL_URL: 'https://redactwall.example',
      INGEST_API_KEY: 'key-0000000000000001',
    },
    fetchImpl: async () => ({
      ok: false,
      status: 503,
      json: async () => ({ error: 'maintenance' }),
    }),
  }), /HTTP 503: maintenance/);

  const logs = [];
  printHuman({ ...report, heartbeat: { ok: false, detail: 'offline' } }, { log: (line) => logs.push(line) });
  assert.match(logs.join('\n'), /RedactWall endpoint install: ok/);
  assert.match(logs.join('\n'), /\[attention\] heartbeat - offline/);
});

test('endpoint install check args cover validation and heartbeat options', () => {
  const parsed = parseArgs([
    '--env', 'custom.env',
    '--repo-root', 'dist/package',
    '--json',
    '--emit-heartbeat',
    '--require-desktop-collector',
    '--user', 'tech@example.test',
    '--org-id', 'cu-acme',
    '--destination', 'install-check',
  ], { LOCALAPPDATA: 'C:\\Temp' });
  assert.match(parsed.envPath, /custom\.env$/);
  assert.match(parsed.repoRoot, /dist[\\/]package$/);
  assert.strictEqual(parsed.json, true);
  assert.strictEqual(parsed.emitHeartbeat, true);
  assert.strictEqual(parsed.requireDesktopCollector, true);
  assert.strictEqual(parsed.user, 'tech@example.test');
  assert.strictEqual(parsed.orgId, 'cu-acme');
  assert.strictEqual(parsed.destination, 'install-check');
  assert.strictEqual(parseArgs(['--help'], {}).help, true);
  assert.throws(() => parseArgs(['--bad'], {}), /Unknown option: --bad/);
});

test('endpoint install check CLI main reports json, help, heartbeat errors, and parse errors', async () => {
  const logs = [];
  const errors = [];
  const exitCodes = [];
  const io = {
    log: (line) => logs.push(String(line)),
    error: (line) => errors.push(String(line)),
  };
  const okReport = { status: 'ok', checks: [{ id: 'server_url', ok: true, detail: 'ok' }] };
  const report = await main(['--json', '--emit-heartbeat'], {
    console: io,
    env: {},
    listProcessNames: async () => ['Cursor.exe'],
    buildInstallReport: (opts) => {
      assert.deepStrictEqual(opts.processNames, ['Cursor.exe']);
      return { ...okReport };
    },
    emitHeartbeat: async () => ({ id: 'q_endpoint_cli' }),
    setExitCode: (code) => exitCodes.push(code),
  });
  assert.strictEqual(report.heartbeat.detail, 'q_endpoint_cli');
  assert.match(logs.join('\n'), /"heartbeat"/);
  assert.deepStrictEqual(exitCodes, []);

  logs.length = 0;
  const attention = await main(['--emit-heartbeat'], {
    console: io,
    env: {},
    listProcessNames: async () => [],
    buildInstallReport: () => ({ ...okReport }),
    emitHeartbeat: async () => { throw new Error('offline'); },
    setExitCode: (code) => exitCodes.push(code),
  });
  assert.strictEqual(attention.status, 'attention');
  assert.strictEqual(attention.heartbeat.ok, false);
  assert.ok(exitCodes.includes(1));
  assert.match(logs.join('\n'), /\[attention\] heartbeat - offline/);

  logs.length = 0;
  assert.strictEqual(await main(['--help'], { console: io, env: {}, setExitCode: (code) => exitCodes.push(code) }), null);
  assert.match(logs.join('\n'), /Usage: node scripts\/check-endpoint-install\.js/);

  assert.strictEqual(await main(['--bad'], { console: io, env: {}, setExitCode: (code) => exitCodes.push(code) }), null);
  assert.ok(errors.some((line) => /Unknown option: --bad/.test(line)));
});

test('endpoint install check verifies OCR extraction against the bundled fixture', async (t) => {
  const dir = tempDir(t, 'ps-endpoint-ocr-check-');
  const envPath = path.join(dir, 'endpoint-agent.env');
  fs.writeFileSync(envPath, 'ENDPOINT_AGENT_OCR_COMMAND=/opt/ocr/tesseract\n');

  const extracted = await ocrExtractionCheck({
    envPath,
    env: {},
    extractImageFile: async (name, filePath) => {
      assert.strictEqual(name, 'ocr-sample.png');
      assert.ok(fs.existsSync(filePath), 'fixture image ships with the agent');
      return { extractionOk: true, text: 'REDACTWALL OCR 7391' };
    },
  });
  assert.deepStrictEqual(extracted, { id: 'endpoint_ocr_extract', ok: true, detail: 'extracted fixture text' });

  const broken = await ocrExtractionCheck({
    envPath,
    env: {},
    extractImageFile: async () => ({ extractionOk: false, error: 'extract_failed' }),
  });
  assert.strictEqual(broken.ok, false);
  assert.strictEqual(broken.detail, 'extract_failed');

  const noText = await ocrExtractionCheck({
    envPath,
    env: {},
    extractImageFile: async () => ({ extractionOk: true, text: '' }),
  });
  assert.strictEqual(noText.ok, false);
  assert.strictEqual(noText.detail, 'no text extracted from fixture');

  const noEngine = await ocrExtractionCheck({
    envPath: path.join(dir, 'missing.env'),
    env: {},
    discoverOcrCommand: () => '',
    wasmOcrAvailable: () => false,
  });
  assert.strictEqual(noEngine.ok, true);
  assert.match(noEngine.detail, /no OCR engine/);

  const wasmExtract = await ocrExtractionCheck({
    envPath: path.join(dir, 'missing.env'),
    env: {},
    discoverOcrCommand: () => '',
    wasmOcrAvailable: () => true,
    extractImageFile: async (name, filePath, engineOpts) => {
      assert.strictEqual(engineOpts.discover, false);
      assert.ok(fs.existsSync(filePath), 'fixture image ships with the agent');
      return { extractionOk: true, text: 'REDACTWALL OCR 73491', ocrEngine: 'wasm' };
    },
  });
  assert.strictEqual(wasmExtract.ok, true);
  assert.strictEqual(wasmExtract.detail, 'extracted fixture text (wasm)');
});

test('endpoint install check auto-discovers OCR and surfaces guarded app folders', async (t) => {
  const dir = tempDir(t, 'ps-endpoint-appflow-check-');
  const watchDir = path.join(dir, 'watch');
  fs.mkdirSync(path.join(watchDir, 'AI Apps', 'Microsoft Copilot'), { recursive: true });
  const envPath = path.join(dir, 'endpoint-agent.env');
  const key = 'appflow-ingest-key-000000000000000000000001';
  fs.writeFileSync(envPath, [
    'REDACTWALL_URL=https://redactwall.appflow.example',
    `INGEST_API_KEY=${key}`,
    `ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    'ENDPOINT_AGENT_APP_FLOW=1',
  ].join('\n') + '\n');

  const binDir = path.join(dir, 'bin');
  fs.mkdirSync(binDir);
  fs.writeFileSync(path.join(binDir, 'Copilot.exe'), 'stub');

  const report = buildInstallReport({
    envPath,
    repoRoot: root,
    env: { PATH: binDir },
    platform: 'win32',
    extraChecks: [await ocrExtractionCheck({
      envPath,
      env: {},
      extractImageFile: async () => ({ extractionOk: true, text: 'REDACTWALL OCR 7391' }),
      discoverOcrCommand: () => '/discovered/tesseract',
    })],
  });

  assert.ok(report.checks.some((item) => item.id === 'desktop_app_flow_runtime' && item.ok));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_app_flow' && item.detail === 'guarded apps:1'));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_app_flow_copilot' && item.ok && item.detail === 'guarded folder ready'));
  assert.ok(report.checks.some((item) => item.id === 'endpoint_ocr_extract' && item.ok));
  assert.ok(!JSON.stringify(report.checks).includes(watchDir), 'app flow checks never leak paths');
  assert.ok(!JSON.stringify(report).includes(key));
});
