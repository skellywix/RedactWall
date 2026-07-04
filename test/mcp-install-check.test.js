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
  defaultMcpEnvPath,
  emitHeartbeat,
  atlassianSettings,
  databaseReadonlySettings,
  googleDriveSettings,
  main,
  microsoft365Settings,
  mcpSettings,
  parseArgs,
  printHuman,
  readMcpConfig,
  slackSettings,
  teamsSettings,
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
    'PROMPTWALL_URL=https://promptwall.customer.example',
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
  assert.ok(report.checks.some((item) => item.id === 'mcp_microsoft365_connector'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_google_drive_connector'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_slack_connector'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_teams_connector'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_atlassian_connector'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_database_readonly_connector'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_connector_registry' && item.ok && /shipped:6\/6/.test(item.detail)));
  assert.ok(report.checks.some((item) => item.id === 'mcp_connector_profile_microsoft365' && item.ok && /stage:shipped/.test(item.detail)));
  assert.ok(report.checks.some((item) => item.id === 'mcp_connector_profile_google_drive' && item.ok && /stage:shipped/.test(item.detail)));
  assert.ok(report.checks.some((item) => item.id === 'mcp_connector_profile_slack' && item.ok && /stage:shipped/.test(item.detail)));
  assert.ok(report.checks.some((item) => item.id === 'mcp_connector_profile_teams' && item.ok && /stage:shipped/.test(item.detail)));
  assert.ok(report.checks.some((item) => item.id === 'mcp_connector_profile_jira_confluence' && item.ok && /stage:shipped/.test(item.detail)));
  assert.ok(report.checks.some((item) => item.id === 'mcp_connector_profile_database_readonly' && item.ok && /stage:shipped/.test(item.detail)));
  assert.ok(report.checks.some((item) => item.id === 'shared_detection_engine'));
  assert.strictEqual(report.connectorRegistry.summary.shippedRuntimePresent, 6);
  assert.strictEqual(report.connectorRegistry.summary.profileTemplates, 0);
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

test('MCP install check adds optional Microsoft 365 connector health without exposing tokens', async (t) => {
  const dir = tempDir(t, 'ps-mcp-m365-check-');
  const envPath = path.join(dir, 'mcp-guard.env');
  const ingestKey = 'mcp-ingest-key-000000000000000000000000000002';
  const graphToken = 'microsoft-graph-token-000000000000000000000001';
  fs.writeFileSync(envPath, [
    'PROMPTWALL_URL=https://promptwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    'SENTINEL_TENANT_ID=cu-acme',
    `M365_GRAPH_ACCESS_TOKEN=${graphToken}`,
    'M365_TENANT_ID=tenant-acme',
    'M365_GRAPH_SCOPES=Files.Read Sites.Selected',
  ].join('\n') + '\n');

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.some((item) => item.id === 'mcp_microsoft365_token' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_microsoft365_tenant' && item.ok));
  assert.ok(report.checks.some((item) => item.id === 'mcp_microsoft365_scopes' && item.ok && item.detail === 'scopes:2'));
  assert.ok(!JSON.stringify(report).includes(graphToken));

  const heartbeat = buildHeartbeatBody(report, { envPath, env: {}, user: 'mcp-tech@example.test' });
  assert.ok(heartbeat.checks.some((item) => item.id === 'mcp_microsoft365_scopes' && item.detail === 'scopes:2'));
  assert.ok(!JSON.stringify(heartbeat).includes(graphToken));
});

test('MCP install check adds optional Google Drive connector health without exposing tokens', async (t) => {
  const dir = tempDir(t, 'ps-mcp-gdrive-check-');
  const envPath = path.join(dir, 'mcp-guard.env');
  const ingestKey = 'mcp-ingest-key-000000000000000000000000000003';
  const googleToken = 'google-drive-token-000000000000000000000001';
  fs.writeFileSync(envPath, [
    'PROMPTWALL_URL=https://promptwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    'SENTINEL_TENANT_ID=cu-acme',
    `GOOGLE_DRIVE_ACCESS_TOKEN=${googleToken}`,
    'GOOGLE_WORKSPACE_DOMAIN=cu.example',
    'GOOGLE_DRIVE_SCOPES=https://www.googleapis.com/auth/drive.readonly',
  ].join('\n') + '\n');

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.some((item) => item.id === 'mcp_google_drive_token' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_google_drive_tenant' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_google_drive_scopes' && item.ok && item.detail === 'scopes:1'));
  assert.ok(report.connectorRegistry.profiles.some((item) => item.id === 'google_drive' && item.configured && item.runtimePresent));
  assert.ok(!JSON.stringify(report).includes(googleToken));

  const heartbeat = buildHeartbeatBody(report, { envPath, env: {}, user: 'mcp-tech@example.test' });
  assert.ok(heartbeat.checks.some((item) => item.id === 'mcp_google_drive_scopes' && item.detail === 'scopes:1'));
  assert.ok(!JSON.stringify(heartbeat).includes(googleToken));
});

test('MCP install check adds optional Slack connector health without exposing tokens', async (t) => {
  const dir = tempDir(t, 'ps-mcp-slack-check-');
  const envPath = path.join(dir, 'mcp-guard.env');
  const ingestKey = 'mcp-ingest-key-000000000000000000000000000004';
  const slackToken = 'fixture-slack-token-000000000000000000000001';
  fs.writeFileSync(envPath, [
    'PROMPTWALL_URL=https://promptwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    'SENTINEL_TENANT_ID=cu-acme',
    `SLACK_BOT_TOKEN=${slackToken}`,
    'SLACK_TEAM_ID=T123',
    'SLACK_SCOPES=channels:history groups:history files:read',
  ].join('\n') + '\n');

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.some((item) => item.id === 'mcp_slack_token' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_slack_tenant' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_slack_scopes' && item.ok && item.detail === 'scopes:3'));
  assert.ok(report.connectorRegistry.profiles.some((item) => item.id === 'slack' && item.configured && item.runtimePresent));
  assert.ok(!JSON.stringify(report).includes(slackToken));

  const heartbeat = buildHeartbeatBody(report, { envPath, env: {}, user: 'mcp-tech@example.test' });
  assert.ok(heartbeat.checks.some((item) => item.id === 'mcp_slack_scopes' && item.detail === 'scopes:3'));
  assert.ok(!JSON.stringify(heartbeat).includes(slackToken));
});

test('MCP install check adds optional Microsoft Teams connector health without exposing tokens', async (t) => {
  const dir = tempDir(t, 'ps-mcp-teams-check-');
  const envPath = path.join(dir, 'mcp-guard.env');
  const ingestKey = 'mcp-ingest-key-000000000000000000000000000005';
  const teamsToken = 'teams-graph-token-000000000000000000000001';
  fs.writeFileSync(envPath, [
    'PROMPTWALL_URL=https://promptwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    'SENTINEL_TENANT_ID=cu-acme',
    `TEAMS_GRAPH_ACCESS_TOKEN=${teamsToken}`,
    'TEAMS_TENANT_ID=tenant-acme',
    'TEAMS_GRAPH_SCOPES=ChannelMessage.Read.Group ChatMessage.Read.Chat',
  ].join('\n') + '\n');

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.some((item) => item.id === 'mcp_teams_token' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_teams_tenant' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_teams_scopes' && item.ok && item.detail === 'scopes:2'));
  assert.ok(report.connectorRegistry.profiles.some((item) => item.id === 'teams' && item.configured && item.runtimePresent));
  assert.ok(!JSON.stringify(report).includes(teamsToken));

  const heartbeat = buildHeartbeatBody(report, { envPath, env: {}, user: 'mcp-tech@example.test' });
  assert.ok(heartbeat.checks.some((item) => item.id === 'mcp_teams_scopes' && item.detail === 'scopes:2'));
  assert.ok(!JSON.stringify(heartbeat).includes(teamsToken));
});

test('MCP install check adds optional Atlassian connector health without exposing tokens', async (t) => {
  const dir = tempDir(t, 'ps-mcp-atlassian-check-');
  const envPath = path.join(dir, 'mcp-guard.env');
  const ingestKey = 'mcp-ingest-key-000000000000000000000000000006';
  const atlassianToken = 'atlassian-token-000000000000000000000001';
  fs.writeFileSync(envPath, [
    'PROMPTWALL_URL=https://promptwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    'SENTINEL_TENANT_ID=cu-acme',
    `ATLASSIAN_ACCESS_TOKEN=${atlassianToken}`,
    'ATLASSIAN_SITE_URL=https://acme.atlassian.net',
    'ATLASSIAN_SCOPES=read:jira-work read:page:confluence',
  ].join('\n') + '\n');

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.some((item) => item.id === 'mcp_atlassian_token' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_atlassian_tenant' && item.ok));
  assert.ok(report.checks.some((item) => item.id === 'mcp_atlassian_scopes' && item.ok && item.detail === 'scopes:2'));
  assert.ok(report.connectorRegistry.profiles.some((item) => item.id === 'jira_confluence' && item.configured && item.runtimePresent));
  assert.ok(!JSON.stringify(report).includes(atlassianToken));

  const heartbeat = buildHeartbeatBody(report, { envPath, env: {}, user: 'mcp-tech@example.test' });
  assert.ok(heartbeat.checks.some((item) => item.id === 'mcp_atlassian_scopes' && item.detail === 'scopes:2'));
  assert.ok(!JSON.stringify(heartbeat).includes(atlassianToken));
});

test('MCP install check adds optional database read-only connector health without exposing DSNs', async (t) => {
  const dir = tempDir(t, 'ps-mcp-db-check-');
  const envPath = path.join(dir, 'mcp-guard.env');
  const ingestKey = 'mcp-ingest-key-000000000000000000000000000007';
  const dsn = 'sqlite:///C:/private/member-data.db';
  fs.writeFileSync(envPath, [
    'PROMPTWALL_URL=https://promptwall.customer.example',
    `INGEST_API_KEY=${ingestKey}`,
    'SENTINEL_TENANT_ID=cu-acme',
    `MCP_DATABASE_DSN=${dsn}`,
    'MCP_DATABASE_LABEL=core-reporting',
    'MCP_DATABASE_SCOPES=readonly',
  ].join('\n') + '\n');

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'ok');
  assert.ok(report.checks.some((item) => item.id === 'mcp_database_readonly_dsn' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_database_readonly_label' && item.ok && item.detail === 'configured'));
  assert.ok(report.checks.some((item) => item.id === 'mcp_database_readonly_scopes' && item.ok && item.detail === 'scopes:1'));
  assert.ok(report.connectorRegistry.profiles.some((item) => item.id === 'database_readonly' && item.configured && item.runtimePresent));
  assert.ok(!JSON.stringify(report).includes(dsn));

  const heartbeat = buildHeartbeatBody(report, { envPath, env: {}, user: 'mcp-tech@example.test' });
  assert.ok(heartbeat.checks.some((item) => item.id === 'mcp_database_readonly_scopes' && item.detail === 'scopes:1'));
  assert.ok(!JSON.stringify(heartbeat).includes(dsn));
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

test('MCP install check accepts runtime environment without a default env file', (t) => {
  // A hermetic install root: runtime files present, but no default .env —
  // the repo checkout may have one from `npm run setup`.
  const installRoot = tempDir(t, 'ps-mcp-check-runtime-');
  for (const rel of [
    'sensors/mcp-guard/guard.js',
    'sensors/mcp-guard/sdk.js',
    'sensors/mcp-guard/connector-registry.js',
    'sensors/mcp-guard/connectors/microsoft365.js',
    'sensors/mcp-guard/connectors/google-drive.js',
    'sensors/mcp-guard/connectors/slack.js',
    'sensors/mcp-guard/connectors/teams.js',
    'sensors/mcp-guard/connectors/atlassian.js',
    'sensors/mcp-guard/connectors/database-readonly.js',
    'detection-engine/detect.js',
    'server/env.js',
    'package.json',
  ]) {
    const target = path.join(installRoot, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(root, rel), target);
  }

  const ingestKey = 'runtime-mcp-key-000000000000000000000000001';
  const report = buildInstallReport({
    repoRoot: installRoot,
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

test('MCP install check accepts env aliases and default install-root env paths', (t) => {
  const dir = tempDir(t, 'ps-mcp-check-aliases-');
  const envPath = path.join(dir, 'mcp.env');
  const aliasKey = 'mcp-alias-key-000000000000000000000000000001';
  fs.writeFileSync(envPath, [
    'PROMPTWALL_URL=https://promptwall.alias.example/path',
    `PROMPTWALL_INGEST_API_KEY=${aliasKey}`,
    'PROMPTWALL_TENANT_ID=cu-alias',
    'MICROSOFT_GRAPH_SCOPES=Files.Read, Sites.Selected',
  ].join('\n') + '\n');

  assert.strictEqual(defaultMcpEnvPath({}, dir), path.join(dir, '.env'));
  const config = readMcpConfig(envPath, {}, dir).config;
  assert.strictEqual(config.INGEST_API_KEY, aliasKey);
  assert.strictEqual(mcpSettings(config).serverUrl, 'https://promptwall.alias.example/path');
  assert.deepStrictEqual(microsoft365Settings(config).scopes, ['Files.Read', 'Sites.Selected']);
  assert.deepStrictEqual(googleDriveSettings(config).scopes, ['https://www.googleapis.com/auth/drive.readonly']);
  assert.deepStrictEqual(slackSettings(config).scopes, ['channels:history', 'groups:history', 'files:read']);
  assert.deepStrictEqual(teamsSettings(config).scopes, ['ChannelMessage.Read.Group', 'ChatMessage.Read.Chat']);
  assert.deepStrictEqual(atlassianSettings(config).scopes, ['read:jira-work', 'read:page:confluence']);
  assert.deepStrictEqual(databaseReadonlySettings(config).scopes, ['readonly']);

  const report = buildInstallReport({ envPath, repoRoot: root, env: {} });
  assert.strictEqual(report.status, 'attention');
  assert.ok(report.checks.some((item) => item.id === 'mcp_microsoft365_tenant' && !item.ok));
  assert.ok(!JSON.stringify(report).includes(aliasKey));
});

test('MCP heartbeat and human output cover failure branches without leaking secrets', async () => {
  const report = { status: 'ok', checks: [{ id: 'ingest_key', ok: true, detail: 'configured' }] };
  await assert.rejects(() => emitHeartbeat(report, { config: { INGEST_API_KEY: 'key-0000000000000001' } }), /PROMPTWALL_URL/);
  await assert.rejects(() => emitHeartbeat(report, { config: { PROMPTWALL_URL: 'https://promptwall.example' } }), /INGEST_API_KEY/);
  const originalFetch = globalThis.fetch;
  delete globalThis.fetch;
  try {
    await assert.rejects(() => emitHeartbeat(report, {
      config: {
        PROMPTWALL_URL: 'https://promptwall.example',
        INGEST_API_KEY: 'key-0000000000000001',
      },
    }), /fetch is not available/);
  } finally {
    globalThis.fetch = originalFetch;
  }
  await assert.rejects(() => emitHeartbeat(report, {
    config: {
      PROMPTWALL_URL: 'https://promptwall.example',
      INGEST_API_KEY: 'key-0000000000000001',
    },
    fetchImpl: async () => ({
      ok: false,
      status: 429,
      json: async () => ({ error: 'rate limited' }),
    }),
  }), /HTTP 429: rate limited/);

  const logs = [];
  printHuman({ ...report, heartbeat: { ok: true, detail: 'recorded' } }, { log: (line) => logs.push(line) });
  assert.match(logs.join('\n'), /PromptWall MCP guard install: ok/);
  assert.match(logs.join('\n'), /\[ok\] heartbeat - recorded/);
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
  assert.strictEqual(parseArgs(['--help'], {}).help, true);
  assert.throws(() => parseArgs(['--bad'], {}), /Unknown option: --bad/);
});

test('MCP install check CLI main reports json, help, heartbeat errors, and parse errors', async () => {
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
    buildInstallReport: () => ({ ...okReport }),
    emitHeartbeat: async () => ({ id: 'q_mcp_cli' }),
    setExitCode: (code) => exitCodes.push(code),
  });
  assert.strictEqual(report.heartbeat.detail, 'q_mcp_cli');
  assert.match(logs.join('\n'), /"heartbeat"/);
  assert.deepStrictEqual(exitCodes, []);

  logs.length = 0;
  const attention = await main(['--emit-heartbeat'], {
    console: io,
    env: {},
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
  assert.match(logs.join('\n'), /Usage: node scripts\/check-mcp-guard-install\.js/);

  assert.strictEqual(await main(['--bad'], { console: io, env: {}, setExitCode: (code) => exitCodes.push(code) }), null);
  assert.ok(errors.some((line) => /Unknown option: --bad/.test(line)));
});
