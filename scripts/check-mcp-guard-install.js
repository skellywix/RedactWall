'use strict';
/**
 * Validate an MCP guard install without printing secrets.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseEnv, withEnvAliases } = require('../server/env');

const ROOT = path.join(__dirname, '..');
const VERSION = require('../package.json').version;
const DEVELOPMENT_INGEST_KEY = ['dev', 'ingest', 'key'].join('-');

function configured(value) {
  return value != null && String(value).trim() !== '';
}

function defaultMcpEnvPath(env = process.env) {
  if (configured(env.SENTINEL_ENV_PATH)) return env.SENTINEL_ENV_PATH;
  if (configured(env.PROMPTWALL_ENV_PATH)) return env.PROMPTWALL_ENV_PATH;
  return path.join(__dirname, '..', '.env');
}

function readMcpConfig(envPath, env = process.env) {
  const resolved = path.resolve(envPath || defaultMcpEnvPath(env));
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
    serverUrl: config.SENTINEL_URL || config.PROMPTWALL_URL || '',
    ingestKey: config.INGEST_API_KEY || config.PROMPTWALL_INGEST_API_KEY || '',
    orgId: config.SENTINEL_TENANT_ID || config.PROMPTWALL_TENANT_ID || '',
  };
}

function nodeMajor() {
  return Number(String(process.versions.node || '').split('.')[0]);
}

function buildInstallReport(opts = {}) {
  const repoRoot = path.resolve(opts.repoRoot || ROOT);
  const env = opts.env || process.env;
  const configInfo = readMcpConfig(opts.envPath, env);
  const settings = mcpSettings(configInfo.config);
  const envExplicit = configured(opts.envPath)
    || configured(env.SENTINEL_ENV_PATH)
    || configured(env.PROMPTWALL_ENV_PATH);
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
    check('shared_detection_engine', existsFile(repoRoot, 'detection-engine/detect.js'), 'shared engine present'),
    check('env_loader', existsFile(repoRoot, 'server/env.js'), 'env loader present'),
    check('package_manifest', existsFile(repoRoot, 'package.json'), 'package manifest present'),
  ];

  return {
    status: checks.every((item) => item.ok) ? 'ok' : 'attention',
    generatedAt: new Date().toISOString(),
    envPath: configInfo.path,
    repoRoot,
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
  if (!configured(serverUrl)) throw new Error('SENTINEL_URL is required to emit a heartbeat');
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
    '  --repo-root <path>     PromptWall repo or extracted package root',
    '  --json                Print JSON output',
    '  --emit-heartbeat      POST sanitized checks to /api/v1/heartbeat',
    '  --user <id>           User to attach to heartbeat evidence',
    '  --org-id <id>         Tenant org id for managed sensors',
    '  --destination <label> Heartbeat destination label',
  ].join('\n');
}

function printHuman(report) {
  console.log(`PromptWall MCP guard install: ${report.status}`);
  for (const item of report.checks) {
    console.log(`[${item.ok ? 'ok' : 'attention'}] ${item.id} - ${item.detail}`);
  }
  if (report.heartbeat) {
    console.log(`[${report.heartbeat.ok ? 'ok' : 'attention'}] heartbeat - ${report.heartbeat.detail}`);
  }
}

async function main() {
  try {
    const opts = parseArgs();
    if (opts.help) {
      console.log(usage());
      return;
    }
    const report = buildInstallReport(opts);
    if (opts.emitHeartbeat) {
      try {
        const response = await emitHeartbeat(report, opts);
        report.heartbeat = { ok: true, detail: response.id || 'recorded', response };
      } catch (err) {
        report.status = 'attention';
        report.heartbeat = { ok: false, detail: err.message || String(err) };
      }
    }
    if (opts.json) console.log(JSON.stringify(report, null, 2));
    else printHuman(report);
    if (report.status !== 'ok') process.exitCode = 1;
  } catch (err) {
    console.error(err.message || err);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  buildHeartbeatBody,
  buildInstallReport,
  defaultMcpEnvPath,
  emitHeartbeat,
  mcpSettings,
  parseArgs,
  readMcpConfig,
};
