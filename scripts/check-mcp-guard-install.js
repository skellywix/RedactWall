'use strict';
/**
 * Validate an MCP guard install without printing secrets.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseEnv, withEnvAliases } = require('../server/env');
const {
  connectorRegistryChecks,
  connectorRegistryStatus,
} = require('../sensors/mcp-guard/connector-registry');

const ROOT = path.join(__dirname, '..');
const VERSION = require('../package.json').version;
const DEVELOPMENT_INGEST_KEY = ['dev', 'ingest', 'key'].join('-');

function configured(value) {
  return value != null && String(value).trim() !== '';
}

function defaultMcpEnvPath(env = process.env, repoRoot = ROOT) {
  if (configured(env.REDACTWALL_ENV_PATH)) return env.REDACTWALL_ENV_PATH;
  if (configured(env.PROMPTWALL_ENV_PATH)) return env.PROMPTWALL_ENV_PATH;
  if (configured(env.SENTINEL_ENV_PATH)) return env.SENTINEL_ENV_PATH;
  // The default env file belongs to the install root being checked, not to
  // wherever this checker script happens to live.
  return path.join(repoRoot, '.env');
}

function readMcpConfig(envPath, env = process.env, repoRoot = ROOT) {
  const resolved = path.resolve(envPath || defaultMcpEnvPath(env, repoRoot));
  const exists = fs.existsSync(resolved);
  const parsed = exists ? parseEnv(fs.readFileSync(resolved, 'utf8')) : { parsed: {}, errors: [] };
  return {
    path: resolved,
    exists,
    errors: parsed.errors || [],
    config: withEnvAliases({ ...env, ...parsed.parsed }),
  };
}

function safeOrigin(value) {
  try {
    const url = new URL(String(value || ''));
    return `${url.protocol}//${url.host}`;
  } catch {
    return 'invalid URL';
  }
}

function existsFile(root, relPath) {
  return fs.existsSync(path.join(root, relPath));
}

function check(id, ok, detail) {
  return {
    id,
    ok: ok === true,
    detail: String(detail || (ok ? 'ok' : 'attention')).slice(0, 160),
  };
}

function mcpSettings(config = {}) {
  return {
    serverUrl: config.REDACTWALL_URL || config.PROMPTWALL_URL || config.SENTINEL_URL || '',
    ingestKey: config.INGEST_API_KEY || config.REDACTWALL_INGEST_API_KEY || '',
    orgId: config.REDACTWALL_TENANT_ID || config.PROMPTWALL_TENANT_ID || config.SENTINEL_TENANT_ID || '',
  };
}

function splitScopes(value) {
  return String(value || '').split(/[,\s]+/).map((scope) => scope.trim()).filter(Boolean);
}

function microsoft365Settings(config = {}) {
  return {
    token: config.M365_GRAPH_ACCESS_TOKEN || config.MICROSOFT_GRAPH_ACCESS_TOKEN || '',
    tenantId: config.M365_TENANT_ID || config.AZURE_TENANT_ID || '',
    scopes: splitScopes(config.M365_GRAPH_SCOPES || config.MICROSOFT_GRAPH_SCOPES || 'Files.Read'),
  };
}

function googleDriveSettings(config = {}) {
  return {
    token: config.GOOGLE_DRIVE_ACCESS_TOKEN || config.GOOGLE_WORKSPACE_ACCESS_TOKEN || '',
    tenantId: config.GOOGLE_WORKSPACE_CUSTOMER_ID || config.GOOGLE_WORKSPACE_DOMAIN || '',
    scopes: splitScopes(config.GOOGLE_DRIVE_SCOPES || config.GOOGLE_WORKSPACE_SCOPES || 'https://www.googleapis.com/auth/drive.readonly'),
  };
}

function slackSettings(config = {}) {
  return {
    token: config.SLACK_BOT_TOKEN || config.SLACK_CONNECTOR_TOKEN || '',
    tenantId: config.SLACK_TEAM_ID || config.SLACK_ENTERPRISE_ID || '',
    scopes: splitScopes(config.SLACK_SCOPES || 'channels:history groups:history files:read'),
  };
}

function teamsSettings(config = {}) {
  return {
    token: config.TEAMS_GRAPH_ACCESS_TOKEN || config.M365_GRAPH_ACCESS_TOKEN || config.MICROSOFT_GRAPH_ACCESS_TOKEN || '',
    tenantId: config.TEAMS_TENANT_ID || config.M365_TENANT_ID || config.AZURE_TENANT_ID || '',
    scopes: splitScopes(config.TEAMS_GRAPH_SCOPES || 'ChannelMessage.Read.Group ChatMessage.Read.Chat'),
  };
}

function atlassianSettings(config = {}) {
  return {
    token: config.ATLASSIAN_ACCESS_TOKEN || config.ATLASSIAN_API_TOKEN || config.JIRA_API_TOKEN || config.CONFLUENCE_API_TOKEN || '',
    tenantId: config.ATLASSIAN_SITE_URL || config.JIRA_BASE_URL || config.CONFLUENCE_BASE_URL || '',
    scopes: splitScopes(config.ATLASSIAN_SCOPES || 'read:jira-work read:page:confluence'),
  };
}

function databaseReadonlySettings(config = {}) {
  return {
    token: config.MCP_DATABASE_DSN || config.DATABASE_READONLY_DSN || '',
    tenantId: config.MCP_DATABASE_LABEL || config.DATABASE_READONLY_LABEL || '',
    scopes: splitScopes(config.MCP_DATABASE_SCOPES || config.DATABASE_READONLY_SCOPES || 'readonly'),
  };
}

function microsoft365Configured(settings) {
  return configured(settings.token)
    || configured(settings.tenantId)
    || (settings.scopes.length && settings.scopes.join(' ') !== 'Files.Read');
}

function googleDriveConfigured(settings) {
  return configured(settings.token)
    || configured(settings.tenantId)
    || (settings.scopes.length && settings.scopes.join(' ') !== 'https://www.googleapis.com/auth/drive.readonly');
}

function slackConfigured(settings) {
  return configured(settings.token)
    || configured(settings.tenantId)
    || (settings.scopes.length && settings.scopes.join(' ') !== 'channels:history groups:history files:read');
}

function teamsConfigured(settings) {
  return configured(settings.token)
    || configured(settings.tenantId)
    || (settings.scopes.length && settings.scopes.join(' ') !== 'ChannelMessage.Read.Group ChatMessage.Read.Chat');
}

function atlassianConfigured(settings) {
  return configured(settings.token)
    || configured(settings.tenantId)
    || (settings.scopes.length && settings.scopes.join(' ') !== 'read:jira-work read:page:confluence');
}

function databaseReadonlyConfigured(settings) {
  return configured(settings.token)
    || configured(settings.tenantId)
    || (settings.scopes.length && settings.scopes.join(' ') !== 'readonly');
}

function nodeMajor() {
  return Number(String(process.versions.node || '').split('.')[0]);
}

function buildInstallReport(opts = {}) {
  const repoRoot = path.resolve(opts.repoRoot || ROOT);
  const env = opts.env || process.env;
  const configInfo = readMcpConfig(opts.envPath, env, repoRoot);
  const settings = mcpSettings(configInfo.config);
  const microsoft365 = microsoft365Settings(configInfo.config);
  const googleDrive = googleDriveSettings(configInfo.config);
  const slack = slackSettings(configInfo.config);
  const teams = teamsSettings(configInfo.config);
  const atlassian = atlassianSettings(configInfo.config);
  const databaseReadonly = databaseReadonlySettings(configInfo.config);
  const registry = connectorRegistryStatus({ repoRoot, envConfig: configInfo.config });
  const envExplicit = configured(opts.envPath)
    || configured(env.REDACTWALL_ENV_PATH)
    || configured(env.PROMPTWALL_ENV_PATH)
    || configured(env.SENTINEL_ENV_PATH);
  const serverUrlValid = configured(settings.serverUrl) && safeOrigin(settings.serverUrl) !== 'invalid URL';
  const keyLooksUsable = configured(settings.ingestKey)
    && settings.ingestKey.length >= 16
    && settings.ingestKey !== DEVELOPMENT_INGEST_KEY;
  const runtimeConfigOnly = !configInfo.exists && !envExplicit && (serverUrlValid || keyLooksUsable);
  const checks = [
    check('mcp_env_file', configInfo.exists || runtimeConfigOnly,
      configInfo.exists ? 'found' : (envExplicit ? 'missing mcp env file' : (runtimeConfigOnly ? 'runtime env only' : 'missing env file or runtime env'))),
    check('mcp_env_parse', configInfo.errors.length === 0, configInfo.errors.length ? `${configInfo.errors.length} parse errors` : 'parsed'),
    check('server_url', serverUrlValid, serverUrlValid ? safeOrigin(settings.serverUrl) : 'missing or invalid'),
    check('ingest_key', keyLooksUsable, keyLooksUsable ? 'configured' : 'missing, weak, or development key'),
    check('node_runtime', nodeMajor() >= 22, `node ${process.versions.node || 'unknown'}`),
    check('mcp_guard_runtime', existsFile(repoRoot, 'sensors/mcp-guard/guard.js'), 'guard runtime present'),
    check('mcp_connector_sdk', existsFile(repoRoot, 'sensors/mcp-guard/sdk.js'), 'connector SDK present'),
    check('mcp_microsoft365_connector', existsFile(repoRoot, 'sensors/mcp-guard/connectors/microsoft365.js'), 'Microsoft 365 connector present'),
    check('mcp_google_drive_connector', existsFile(repoRoot, 'sensors/mcp-guard/connectors/google-drive.js'), 'Google Drive connector present'),
    check('mcp_slack_connector', existsFile(repoRoot, 'sensors/mcp-guard/connectors/slack.js'), 'Slack connector present'),
    check('mcp_teams_connector', existsFile(repoRoot, 'sensors/mcp-guard/connectors/teams.js'), 'Microsoft Teams connector present'),
    check('mcp_atlassian_connector', existsFile(repoRoot, 'sensors/mcp-guard/connectors/atlassian.js'), 'Atlassian connector present'),
    check('mcp_database_readonly_connector', existsFile(repoRoot, 'sensors/mcp-guard/connectors/database-readonly.js'), 'Database read-only connector present'),
    ...connectorRegistryChecks(registry),
    check('shared_detection_engine', existsFile(repoRoot, 'detection-engine/detect.js'), 'shared engine present'),
    check('env_loader', existsFile(repoRoot, 'server/env.js'), 'env loader present'),
    check('package_manifest', existsFile(repoRoot, 'package.json'), 'package manifest present'),
  ];
  if (microsoft365Configured(microsoft365)) {
    checks.push(
      check('mcp_microsoft365_token', configured(microsoft365.token) && microsoft365.token.length >= 16,
        configured(microsoft365.token) && microsoft365.token.length >= 16 ? 'configured' : 'missing or weak access token'),
      check('mcp_microsoft365_tenant', configured(microsoft365.tenantId),
        configured(microsoft365.tenantId) ? 'configured' : 'missing tenant id'),
      check('mcp_microsoft365_scopes', microsoft365.scopes.length > 0, `scopes:${microsoft365.scopes.length}`)
    );
  }
  if (googleDriveConfigured(googleDrive)) {
    checks.push(
      check('mcp_google_drive_token', configured(googleDrive.token) && googleDrive.token.length >= 16,
        configured(googleDrive.token) && googleDrive.token.length >= 16 ? 'configured' : 'missing or weak access token'),
      check('mcp_google_drive_tenant', true,
        configured(googleDrive.tenantId) ? 'configured' : 'optional tenant id missing'),
      check('mcp_google_drive_scopes', googleDrive.scopes.length > 0, `scopes:${googleDrive.scopes.length}`)
    );
  }
  if (slackConfigured(slack)) {
    checks.push(
      check('mcp_slack_token', configured(slack.token) && slack.token.length >= 16,
        configured(slack.token) && slack.token.length >= 16 ? 'configured' : 'missing or weak access token'),
      check('mcp_slack_tenant', true,
        configured(slack.tenantId) ? 'configured' : 'optional team or enterprise id missing'),
      check('mcp_slack_scopes', slack.scopes.length > 0, `scopes:${slack.scopes.length}`)
    );
  }
  if (teamsConfigured(teams)) {
    checks.push(
      check('mcp_teams_token', configured(teams.token) && teams.token.length >= 16,
        configured(teams.token) && teams.token.length >= 16 ? 'configured' : 'missing or weak access token'),
      check('mcp_teams_tenant', true,
        configured(teams.tenantId) ? 'configured' : 'optional tenant id missing'),
      check('mcp_teams_scopes', teams.scopes.length > 0, `scopes:${teams.scopes.length}`)
    );
  }
  if (atlassianConfigured(atlassian)) {
    checks.push(
      check('mcp_atlassian_token', configured(atlassian.token) && atlassian.token.length >= 16,
        configured(atlassian.token) && atlassian.token.length >= 16 ? 'configured' : 'missing or weak access token'),
      check('mcp_atlassian_tenant', configured(atlassian.tenantId),
        configured(atlassian.tenantId) ? 'configured' : 'missing site url'),
      check('mcp_atlassian_scopes', atlassian.scopes.length > 0, `scopes:${atlassian.scopes.length}`)
    );
  }
  if (databaseReadonlyConfigured(databaseReadonly)) {
    checks.push(
      check('mcp_database_readonly_dsn', configured(databaseReadonly.token),
        configured(databaseReadonly.token) ? 'configured' : 'missing read-only DSN'),
      check('mcp_database_readonly_label', true,
        configured(databaseReadonly.tenantId) ? 'configured' : 'optional label missing'),
      check('mcp_database_readonly_scopes', databaseReadonly.scopes.length > 0, `scopes:${databaseReadonly.scopes.length}`)
    );
  }

  return {
    status: checks.every((item) => item.ok) ? 'ok' : 'attention',
    generatedAt: new Date().toISOString(),
    envPath: configInfo.path,
    repoRoot,
    connectorRegistry: registry,
    checks,
  };
}

function buildHeartbeatBody(report, opts = {}) {
  const envConfig = opts.config || readMcpConfig(opts.envPath, opts.env || process.env).config;
  const settings = mcpSettings(envConfig);
  return {
    user: opts.user || os.userInfo().username || 'mcp-technician',
    orgId: opts.orgId || settings.orgId || null,
    source: 'mcp_guard',
    destination: opts.destination || 'mcp-install',
    sensor: {
      name: 'mcp_guard',
      version: VERSION,
      platform: 'node',
    },
    checks: (report.checks || []).map((item) => ({
      id: item.id,
      ok: item.ok === true,
      detail: item.detail,
    })),
  };
}

async function emitHeartbeat(report, opts = {}) {
  const envConfig = opts.config || readMcpConfig(opts.envPath, opts.env || process.env).config;
  const settings = mcpSettings(envConfig);
  const serverUrl = opts.serverUrl || settings.serverUrl;
  const ingestKey = opts.ingestKey || settings.ingestKey;
  if (!configured(serverUrl)) throw new Error('REDACTWALL_URL is required to emit a heartbeat');
  if (!configured(ingestKey)) throw new Error('INGEST_API_KEY is required to emit a heartbeat');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');
  const response = await fetchImpl(String(serverUrl).replace(/\/+$/, '') + '/api/v1/heartbeat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': ingestKey },
    body: JSON.stringify(buildHeartbeatBody(report, { ...opts, config: envConfig })),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`heartbeat post failed with HTTP ${response.status}${body.error ? ': ' + body.error : ''}`);
  }
  return body;
}

function parseArgs(argv = process.argv.slice(2), env = process.env) {
  const opts = {
    envPath: undefined,
    repoRoot: ROOT,
    json: false,
    emitHeartbeat: false,
    user: '',
    orgId: '',
    destination: 'mcp-install',
    help: false,
  };
  const args = [...argv];
  while (args.length) {
    const arg = args.shift();
    if (arg === '--env') opts.envPath = path.resolve(args.shift() || '');
    else if (arg === '--repo-root') opts.repoRoot = path.resolve(args.shift() || '');
    else if (arg === '--json') opts.json = true;
    else if (arg === '--emit-heartbeat') opts.emitHeartbeat = true;
    else if (arg === '--user') opts.user = args.shift() || '';
    else if (arg === '--org-id') opts.orgId = args.shift() || '';
    else if (arg === '--destination') opts.destination = args.shift() || opts.destination;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown option: ${arg}`);
  }
  return opts;
}

function usage() {
  return [
    'Usage: node scripts/check-mcp-guard-install.js [options]',
    '',
    'Options:',
    '  --env <path>           MCP guard env file path',
    '  --repo-root <path>     RedactWall repo or extracted package root',
    '  --json                Print JSON output',
    '  --emit-heartbeat      POST sanitized checks to /api/v1/heartbeat',
    '  --user <id>           User to attach to heartbeat evidence',
    '  --org-id <id>         Tenant org id for managed sensors',
    '  --destination <label> Heartbeat destination label',
  ].join('\n');
}

function printHuman(report, io = console) {
  io.log(`RedactWall MCP guard install: ${report.status}`);
  for (const item of report.checks) {
    io.log(`[${item.ok ? 'ok' : 'attention'}] ${item.id} - ${item.detail}`);
  }
  if (report.heartbeat) {
    io.log(`[${report.heartbeat.ok ? 'ok' : 'attention'}] heartbeat - ${report.heartbeat.detail}`);
  }
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  const buildReport = deps.buildInstallReport || buildInstallReport;
  const sendHeartbeat = deps.emitHeartbeat || emitHeartbeat;
  try {
    const opts = parseArgs(argv, deps.env || process.env);
    if (opts.help) {
      io.log(usage());
      return null;
    }
    const report = buildReport(opts);
    if (opts.emitHeartbeat) {
      try {
        const response = await sendHeartbeat(report, opts);
        report.heartbeat = { ok: true, detail: response.id || 'recorded', response };
      } catch (err) {
        report.status = 'attention';
        report.heartbeat = { ok: false, detail: err.message || String(err) };
      }
    }
    if (opts.json) io.log(JSON.stringify(report, null, 2));
    else printHuman(report, io);
    if (report.status !== 'ok') setExitCode(1);
    return report;
  } catch (err) {
    io.error(err.message || err);
    setExitCode(1);
    return null;
  }
}

if (require.main === module) main();

module.exports = {
  buildHeartbeatBody,
  buildInstallReport,
  defaultMcpEnvPath,
  emitHeartbeat,
  main,
  microsoft365Settings,
  googleDriveSettings,
  slackSettings,
  teamsSettings,
  atlassianSettings,
  databaseReadonlySettings,
  mcpSettings,
  parseArgs,
  printHuman,
  readMcpConfig,
  usage,
};
