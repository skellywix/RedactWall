'use strict';
/** MCP guard install validation should be useful and secret-free. */
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
} = require('../scripts/check-mcp-guard-install');

const root = path.join(__dirname, '..');

function tempDir(t, prefix = 'ps-mcp-check-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('MCP install check validates runtime wiring without exposing secrets', async (t) => {
  const dir = tempDir(t);
  const envPath = path.join(dir, 'mcp-guard.env');
  const ingestKey = 'mcp-ingest-key-000000000000000000000000000001';
  fs.writeFileSync(envPath, [
    'SENTINEL_URL=https://promptwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    'SENTINEL_TENANT_ID=cu-acme',
  ].join('\n') + '\n');

  const report = buildInstallReport({
    envPath,
    repoRoot: root,
    env: {},
  });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.every((item) => item.ok), JSON.stringify(report.checks));
  assert.ok(report.checks.some((item) => item.id === 'mcp_guard_runtime'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_connector_sdk'));
  assert.ok(report.checks.some((item) => item.id === 'shared_detection_engine'));
  assert.ok(!JSON.stringify(report).includes(ingestKey));

  const heartbeat = buildHeartbeatBody(report, {
    envPath,
    env: {},
    user: 'mcp-tech@example.test',
  });
  assert.strictEqual(heartbeat.user, 'mcp-tech@example.test');
  assert.strictEqual(heartbeat.orgId, 'cu-acme');
  assert.strictEqual(heartbeat.source, 'mcp_guard');
  assert.strictEqual(heartbeat.destination, 'mcp-install');
  assert.strictEqual(heartbeat.sensor.name, 'mcp_guard');
  assert.ok(heartbeat.checks.some((item) => item.id === 'ingest_key' && item.ok));
  assert.ok(!JSON.stringify(heartbeat).includes(ingestKey));

  const requests = [];
  const response = await emitHeartbeat(report, {
    envPath,
    env: {},
    user: 'mcp-tech@example.test',
    fetchImpl: async (url, opts = {}) => {
      requests.push({ url, opts });
      assert.strictEqual(url, 'https://promptwall.customer.example/api/v1/heartbeat');
      assert.strictEqual(opts.headers['x-api-key'], ingestKey);
      assert.ok(!opts.body.includes(ingestKey));
      const body = JSON.parse(opts.body);
      assert.strictEqual(body.source, 'mcp_guard');
      assert.ok(body.checks.every((item) => item.ok));
      return {
        ok: true,
        status: 200,
        json: async () => ({ id: 'q_mcp_heartbeat', decision: 'recorded', status: 'sensor_heartbeat', failedChecks: [] }),
      };
    },
  });
  assert.strictEqual(requests.length, 1);
  assert.strictEqual(response.id, 'q_mcp_heartbeat');
});

test('MCP install check reports attention for bad config', (t) => {
  const dir = tempDir(t, 'ps-mcp-check-attention-');
  const envPath = path.join(dir, 'mcp-guard.env');
  fs.writeFileSync(envPath, [
    'SENTINEL_URL=not a url',
    'INGEST_API_KEY=short-key',
  ].join('\n') + '\n');

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'attention');
  assert.ok(report.checks.some((item) => item.id === 'server_url' && !item.ok));
  assert.ok(report.checks.some((item) => item.id === 'ingest_key' && !item.ok));
  assert.ok(!JSON.stringify(report).includes('short-key'));
});

test('MCP install check accepts runtime environment without a default env file', () => {
  const ingestKey = 'runtime-mcp-key-000000000000000000000000001';
  const report = buildInstallReport({
    repoRoot: root,
    env: {
      SENTINEL_URL: 'https://promptwall.runtime.example',
      INGEST_API_KEY: ingestKey,
      SENTINEL_TENANT_ID: 'cu-runtime',
    },
  });

  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.some((item) => item.id === 'mcp_env_file' && item.ok && item.detail === 'runtime env only'));
  assert.ok(!JSON.stringify(report).includes(ingestKey));
});

test('MCP install check args cover validation and heartbeat options', () => {
  const parsed = parseArgs([
    '--env', 'custom.env',
    '--repo-root', 'dist/mcp',
    '--json',
    '--emit-heartbeat',
    '--user', 'mcp-tech@example.test',
    '--org-id', 'cu-acme',
    '--destination', 'mcp-prod',
  ], {});
  assert.match(parsed.envPath, /custom\.env$/);
  assert.match(parsed.repoRoot, /dist[\\/]mcp$/);
  assert.strictEqual(parsed.json, true);
  assert.strictEqual(parsed.emitHeartbeat, true);
  assert.strictEqual(parsed.user, 'mcp-tech@example.test');
  assert.strictEqual(parsed.orgId, 'cu-acme');
  assert.strictEqual(parsed.destination, 'mcp-prod');
});
