'use strict';
require('../server/env').loadEnv();
/**
 * Validate an agent-hooks install and (optionally) send a presence heartbeat so
 * the console shows the sensor in the fleet/coverage matrix. Reports only
 * install-health metadata; never reads prompt bodies.
 *
 *   node scripts/check-agent-hooks-install.js          # local file + settings checks
 *   node scripts/check-agent-hooks-install.js --json   # machine-readable report
 *   node scripts/check-agent-hooks-install.js --heartbeat
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { settingsPath, ownsEntry } = require('./install-agent-hooks');

const ROOT = path.join(__dirname, '..');
const VERSION = require(path.join(ROOT, 'package.json')).version;

function existsFile(relPath) {
  try { return fs.statSync(path.join(ROOT, relPath)).isFile(); } catch (_) { return false; }
}

function check(id, ok, detail) { return { id, ok: ok === true, detail }; }

function settingsInstalled(opts = {}) {
  const file = settingsPath(opts);
  try {
    const settings = JSON.parse(fs.readFileSync(file, 'utf8'));
    const hooks = (settings && settings.hooks) || {};
    const events = ['UserPromptSubmit', 'PreToolUse'];
    return events.every((e) => Array.isArray(hooks[e]) && hooks[e].some(ownsEntry));
  } catch (_) { return false; }
}

function buildInstallReport(opts = {}) {
  const key = opts.ingestKey || process.env.INGEST_API_KEY || '';
  const server = opts.serverUrl || process.env.REDACTWALL_URL || process.env.PROMPTWALL_URL || process.env.SENTINEL_URL || '';
  return {
    checks: [
      check('agent_hooks_runtime', existsFile('sensors/agent-hooks/hook.js'), 'hook runtime present'),
      check('agent_hooks_decision', existsFile('sensors/shared/decision.js'), 'shared decision helper present'),
      check('shared_detection_engine', existsFile('detection-engine/detect.js'), 'shared engine present'),
      check('agent_hooks_settings', settingsInstalled(opts), 'Claude Code settings contain the hooks'),
      check('ingest_key_configured', !!key, 'INGEST_API_KEY is set'),
      check('server_url_configured', !!server, 'control-plane URL is set'),
    ],
  };
}

function buildHeartbeatBody(report, opts = {}) {
  return {
    user: opts.user || process.env.REDACTWALL_AGENT_USER || os.userInfo().username || 'agent-technician',
    source: 'agent_hooks',
    destination: 'agent-hooks-install',
    sensor: { name: 'agent_hooks', version: VERSION, platform: 'node' },
    checks: (report.checks || []).map((c) => ({ id: c.id, ok: c.ok === true, detail: c.detail })),
  };
}

async function emitHeartbeat(report, opts = {}) {
  const server = opts.serverUrl || process.env.REDACTWALL_URL || process.env.PROMPTWALL_URL || process.env.SENTINEL_URL;
  const key = opts.ingestKey || process.env.INGEST_API_KEY;
  if (!server) throw new Error('REDACTWALL_URL is required to emit a heartbeat');
  if (!key) throw new Error('INGEST_API_KEY is required to emit a heartbeat');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const r = await fetchImpl(String(server).replace(/\/+$/, '') + '/api/v1/heartbeat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': key },
    body: JSON.stringify(buildHeartbeatBody(report, opts)),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`heartbeat post failed HTTP ${r.status}${body.error ? ': ' + body.error : ''}`);
  return body;
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const setExitCode = deps.setExitCode || ((c) => { process.exitCode = c; });
  const report = (deps.buildInstallReport || buildInstallReport)({});
  const failed = report.checks.filter((c) => !c.ok);
  if (argv.includes('--json')) io.log(JSON.stringify(report, null, 2));
  else {
    for (const c of report.checks) io.log(`${c.ok ? '✓' : '✗'} ${c.id} — ${c.detail}`);
  }
  if (argv.includes('--heartbeat')) {
    return (deps.emitHeartbeat || emitHeartbeat)(report, {})
      .then((res) => { io.log('heartbeat sent'); return res; })
      .catch((e) => { io.error(e.message); setExitCode(1); });
  }
  if (failed.length) setExitCode(1);
  return report;
}

if (require.main === module) main();

module.exports = { main, buildInstallReport, buildHeartbeatBody, emitHeartbeat, settingsInstalled };
