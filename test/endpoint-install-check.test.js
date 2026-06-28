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
  emitHeartbeat,
  parseArgs,
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
  fs.mkdirSync(watchDir, { recursive: true });
  fs.mkdirSync(handoffDir, { recursive: true });
  const envPath = path.join(dir, 'endpoint-agent.env');
  const ingestKey = 'pilot-ingest-key-000000000000000000000000000002';
  const handoffSecret = 'native-handoff-secret-000000000000000002';
  fs.writeFileSync(envPath, [
    'PROMPTWALL_URL=https://promptwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    `ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    `ENDPOINT_AGENT_HANDOFF_DIR=${handoffDir}`,
    `ENDPOINT_AGENT_HANDOFF_SECRET=${handoffSecret}`,
    'SENTINEL_TENANT_ID=cu-acme',
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
  assert.ok(!JSON.stringify(report).includes(ingestKey));
  assert.ok(!JSON.stringify(report).includes(handoffSecret));

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
      assert.strictEqual(url, 'https://promptwall.customer.example/api/v1/heartbeat');
      assert.strictEqual(opts.headers['x-api-key'], ingestKey);
      assert.ok(!opts.body.includes(ingestKey));
      assert.ok(!opts.body.includes(handoffSecret));
      const body = JSON.parse(opts.body);
      assert.strictEqual(body.source, 'endpoint_agent');
      assert.ok(body.checks.every((item) => item.ok));
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
    'PROMPTWALL_URL=https://promptwall.customer.example',
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
    'PROMPTWALL_URL=https://promptwall.customer.example',
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
    'PROMPTWALL_URL=https://promptwall.customer.example',
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
});
