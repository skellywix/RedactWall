'use strict';
/**
 * Validate an endpoint-agent install without printing secrets.
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

function defaultEndpointEnvPath(env = process.env, platform = process.platform) {
  if (configured(env.SENTINEL_ENV_PATH)) return env.SENTINEL_ENV_PATH;
  if (configured(env.PROMPTWALL_ENV_PATH)) return env.PROMPTWALL_ENV_PATH;
  if (platform === 'win32' && configured(env.LOCALAPPDATA)) {
    return path.join(env.LOCALAPPDATA, 'PromptWall', 'endpoint-agent.env');
  }
  return path.join(env.HOME || os.homedir() || '.', '.config', 'promptwall', 'endpoint-agent.env');
}

function readEndpointConfig(envPath, env = process.env) {
  const resolved = path.resolve(envPath || defaultEndpointEnvPath(env));
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

function isDirectory(value) {
  try {
    return fs.statSync(value).isDirectory();
  } catch {
    return false;
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

function endpointSettings(config = {}) {
  return {
    serverUrl: config.SENTINEL_URL || config.PROMPTWALL_URL || '',
    ingestKey: config.INGEST_API_KEY || config.PROMPTWALL_INGEST_API_KEY || '',
    watchDir: config.ENDPOINT_AGENT_WATCH_DIR || config.PROMPTWALL_ENDPOINT_AGENT_WATCH_DIR || '',
    handoffDir: config.ENDPOINT_AGENT_HANDOFF_DIR || config.PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR || '',
    handoffSecret: config.ENDPOINT_AGENT_HANDOFF_SECRET || config.PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET || '',
    orgId: config.SENTINEL_TENANT_ID || config.PROMPTWALL_TENANT_ID || '',
  };
}

function buildInstallReport(opts = {}) {
  const repoRoot = path.resolve(opts.repoRoot || ROOT);
  const configInfo = readEndpointConfig(opts.envPath, opts.env || process.env);
  const settings = endpointSettings(configInfo.config);
  const requireDesktopCollector = opts.requireDesktopCollector === true;
  const checks = [];
  const serverUrlValid = configured(settings.serverUrl) && safeOrigin(settings.serverUrl) !== 'invalid URL';
  const keyLooksUsable = configured(settings.ingestKey)
    && settings.ingestKey.length >= 16
    && settings.ingestKey !== DEVELOPMENT_INGEST_KEY;
  const handoffEnabled = configured(settings.handoffSecret) || configured(settings.handoffDir);
  const handoffReady = configured(settings.handoffSecret) && settings.handoffSecret.length >= 32;
  const desktopCollectorExpected = requireDesktopCollector || handoffEnabled;

  checks.push(check('endpoint_env_file', configInfo.exists, configInfo.exists ? 'found' : 'missing endpoint-agent.env'));
  checks.push(check('endpoint_env_parse', configInfo.errors.length === 0, configInfo.errors.length ? `${configInfo.errors.length} parse errors` : 'parsed'));
  checks.push(check('server_url', serverUrlValid, serverUrlValid ? safeOrigin(settings.serverUrl) : 'missing or invalid'));
  checks.push(check('ingest_key', keyLooksUsable, keyLooksUsable ? 'configured' : 'missing, weak, or development key'));
  checks.push(check('watch_dir', configured(settings.watchDir) && isDirectory(settings.watchDir), configured(settings.watchDir) ? 'configured directory' : 'missing'));
  checks.push(check('endpoint_agent_runtime', existsFile(repoRoot, 'sensors/endpoint-agent/agent.js'), 'agent runtime present'));
  checks.push(check('endpoint_runner', existsFile(repoRoot, 'scripts/run-endpoint-agent.ps1'), 'runner present'));
  checks.push(check('clipboard_guard_runtime', existsFile(repoRoot, 'sensors/endpoint-agent/collectors/clipboard-guard.js'), 'clipboard guard present'));
  checks.push(check('handoff_secret', requireDesktopCollector ? handoffReady : (!handoffEnabled || handoffReady),
    handoffReady ? 'configured' : (requireDesktopCollector ? 'missing 32-plus character handoff secret' : 'desktop collector disabled')));
  checks.push(check('handoff_dir', desktopCollectorExpected ? configured(settings.handoffDir) && isDirectory(settings.handoffDir) : true,
    desktopCollectorExpected ? 'configured directory' : 'desktop collector disabled'));
  checks.push(check('desktop_collector_runtime', desktopCollectorExpected
    ? existsFile(repoRoot, 'sensors/endpoint-agent/collectors/protected-upload.js') && existsFile(repoRoot, 'scripts/run-desktop-collector.ps1')
    : true,
  desktopCollectorExpected ? 'desktop collector present' : 'desktop collector disabled'));

  const status = checks.every((item) => item.ok) ? 'ok' : 'attention';
  return {
    status,
    generatedAt: new Date().toISOString(),
    envPath: configInfo.path,
    repoRoot,
    checks,
  };
}

function buildHeartbeatBody(report, opts = {}) {
  const envConfig = opts.config || readEndpointConfig(opts.envPath, opts.env || process.env).config;
  const settings = endpointSettings(envConfig);
  return {
    user: opts.user || os.userInfo().username || 'technician',
    orgId: opts.orgId || settings.orgId || null,
    source: 'endpoint_agent',
    destination: opts.destination || 'endpoint-install',
    sensor: {
      name: 'endpoint_agent',
      version: VERSION,
      platform: process.platform,
    },
    checks: (report.checks || []).map((item) => ({
      id: item.id,
      ok: item.ok === true,
      detail: item.detail,
    })),
  };
}

async function emitHeartbeat(report, opts = {}) {
  const envConfig = opts.config || readEndpointConfig(opts.envPath, opts.env || process.env).config;
  const settings = endpointSettings(envConfig);
  const serverUrl = opts.serverUrl || settings.serverUrl;
  const ingestKey = opts.ingestKey || settings.ingestKey;
  if (!configured(serverUrl)) throw new Error('PROMPTWALL_URL or SENTINEL_URL is required to emit a heartbeat');
  if (!configured(ingestKey)) throw new Error('INGEST_API_KEY is required to emit a heartbeat');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('fetch is not available');
  const url = String(serverUrl).replace(/\/+$/, '') + '/api/v1/heartbeat';
  const response = await fetchImpl(url, {
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
    envPath: defaultEndpointEnvPath(env),
    repoRoot: ROOT,
    json: false,
    emitHeartbeat: false,
    requireDesktopCollector: false,
    user: '',
    orgId: '',
    destination: 'endpoint-install',
    help: false,
  };
  const args = [...argv];
  while (args.length) {
    const arg = args.shift();
    if (arg === '--env') opts.envPath = path.resolve(args.shift() || '');
    else if (arg === '--repo-root') opts.repoRoot = path.resolve(args.shift() || '');
    else if (arg === '--json') opts.json = true;
    else if (arg === '--emit-heartbeat') opts.emitHeartbeat = true;
    else if (arg === '--require-desktop-collector') opts.requireDesktopCollector = true;
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
    'Usage: node scripts/check-endpoint-install.js [options]',
    '',
    'Options:',
    '  --env <path>                    Endpoint env file path',
    '  --repo-root <path>              PromptWall repo or extracted package root',
    '  --json                         Print JSON output',
    '  --emit-heartbeat               POST sanitized checks to /api/v1/heartbeat',
    '  --require-desktop-collector    Fail if native handoff collector is not configured',
    '  --user <id>                    User to attach to heartbeat evidence',
    '  --org-id <id>                  Tenant org id for managed sensors',
    '  --destination <label>          Heartbeat destination label',
  ].join('\n');
}

function printHuman(report) {
  console.log(`PromptWall endpoint install: ${report.status}`);
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
  defaultEndpointEnvPath,
  emitHeartbeat,
  endpointSettings,
  parseArgs,
  readEndpointConfig,
};
