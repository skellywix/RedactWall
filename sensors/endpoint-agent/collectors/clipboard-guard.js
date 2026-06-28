'use strict';
/**
 * One-shot endpoint clipboard guard.
 *
 * Reads the current clipboard locally, analyzes it with the shared detector, and
 * reports only masked findings to the control plane. It never sends clipboard
 * text or writes clipboard text to disk.
 */
const { execFile } = require('child_process');
const { promisify } = require('util');
const writer = require('../write-handoff');
const D = require('../../../detection-engine/detect');

const execFileAsync = promisify(execFile);
const DEFAULT_DESTINATION = 'Clipboard';
const DEFAULT_MAX_CHARS = 200000;
let endpointAgent;

function loadAgent() {
  if (!endpointAgent) endpointAgent = require('../agent');
  return endpointAgent;
}

function usage() {
  return [
    'Usage: node sensors/endpoint-agent/collectors/clipboard-guard.js [options]',
    '',
    'Options:',
    '  --clear-on-block             Clear the clipboard when sensitive content is detected',
    '  --destination <name>          Destination label for audit context, default Clipboard',
    '  --user <id>                   Optional managed user identity',
    '  --env <path>                  Endpoint agent env file to load',
    '  --max-chars <n>               Maximum clipboard characters to inspect, default 200000',
    '  --json                        Print JSON result',
    '  --quiet                       Suppress non-error text output',
  ].join('\n');
}

function boundedNumber(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

function parseArgs(argv = process.argv.slice(2)) {
  const args = [...argv];
  const parsed = { maxChars: DEFAULT_MAX_CHARS };
  while (args.length) {
    const arg = args.shift();
    if (arg === '--help' || arg === '-h') return { ...parsed, help: true };
    const takeValue = (key) => {
      const value = args.shift();
      if (!value) throw new Error(`${arg} requires a value`);
      parsed[key] = value;
    };
    if (arg === '--clear-on-block') parsed.clearOnBlock = true;
    else if (arg === '--destination') takeValue('destination');
    else if (arg === '--user') takeValue('user');
    else if (arg === '--env') takeValue('envPath');
    else if (arg === '--max-chars') takeValue('maxChars');
    else if (arg === '--json') parsed.json = true;
    else if (arg === '--quiet') parsed.quiet = true;
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else throw new Error(`Unexpected argument: ${arg}`);
  }
  parsed.maxChars = boundedNumber(parsed.maxChars, DEFAULT_MAX_CHARS, 1024, 1000000);
  return parsed;
}

function publicError(err) {
  const message = String((err && err.message) || err || 'clipboard guard failed');
  if (/requires a value|Unknown option|Unexpected argument|endpoint env/i.test(message)) return message;
  if (/not supported/i.test(message)) return 'clipboard guard is only supported on Windows';
  if (/EACCES|EPERM|permission|access/i.test(message)) return 'clipboard cannot be accessed';
  return 'clipboard guard failed';
}

async function readClipboard(opts = {}) {
  if (opts.readClipboard) return opts.readClipboard();
  if (process.platform !== 'win32') throw new Error('clipboard guard is not supported on this platform');
  const result = await execFileAsync('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-Command',
    'Get-Clipboard -Raw',
  ], { windowsHide: true, timeout: 5000, maxBuffer: 2 * 1024 * 1024 });
  return result.stdout || '';
}

async function clearClipboard(opts = {}) {
  if (opts.clearClipboard) return opts.clearClipboard();
  if (process.platform !== 'win32') throw new Error('clipboard guard is not supported on this platform');
  await execFileAsync('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-Command',
    "Set-Clipboard -Value ''",
  ], { windowsHide: true, timeout: 5000, maxBuffer: 1024 });
}

function sensitivityLabels(analysis = {}) {
  return [...new Set(
    (analysis.findings || []).map((f) => f.type)
      .concat((analysis.categories || []).map((c) => c.category))
      .filter(Boolean)
  )];
}

function safePrompt(status, analysis) {
  const labels = sensitivityLabels(analysis);
  const labelText = labels.length ? labels.join(', ') : 'sensitive content';
  return `[clipboard ${status} locally] ${labelText}`.slice(0, 1000);
}

function clipboardRecord(analysis, outcome, opts = {}) {
  const agent = loadAgent();
  const status = outcome === 'action_blocked' ? 'blocked' : 'flagged';
  return {
    prompt: safePrompt(status, analysis),
    user: opts.user,
    destination: String(opts.destination || DEFAULT_DESTINATION).trim() || DEFAULT_DESTINATION,
    source: 'endpoint_agent',
    channel: 'clipboard',
    sensor: agent.sensorMetadata(),
    clientOutcome: outcome,
    note: outcome === 'action_blocked'
      ? 'endpoint clipboard cleared locally after sensitive content detection'
      : 'endpoint clipboard inspected locally; sensitive content detected',
    clientPreRedacted: true,
    clientFindings: agent.publicFindings(analysis),
    clientCategories: agent.publicCategories(analysis),
    clientEntityCounts: analysis.entityCounts || {},
    clientRiskScore: analysis.riskScore || 0,
    clientMaxSeverity: analysis.maxSeverity || 0,
    clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
  };
}

async function policyForClipboard(opts = {}) {
  const agent = loadAgent();
  if (opts.policy) return agent.sensorPolicy(opts.policy);
  const fetched = await agent.fetchPolicy({ ...opts, silent: true });
  return agent.sensorPolicy(fetched || {});
}

function analyzeClipboard(text, policy, opts = {}) {
  const sample = String(text || '').slice(0, boundedNumber(opts.maxChars, DEFAULT_MAX_CHARS, 1024, 1000000));
  return D.analyze(sample, {
    ignore: policy.ignore,
    disabledDetectors: policy.disabledDetectors,
    customDetectors: policy.customDetectors,
  });
}

function publicResult(status, analysis, extra = {}) {
  return {
    status,
    sensitive: !!sensitivityLabels(analysis).length,
    labels: sensitivityLabels(analysis),
    riskScore: (analysis && analysis.riskScore) || 0,
    cleared: !!extra.cleared,
    recorded: !!extra.recorded,
    ...(extra.id ? { id: extra.id } : {}),
    ...(extra.error ? { error: extra.error } : {}),
  };
}

async function reportClipboard(record, opts = {}) {
  if (opts.report) return opts.report(record, opts);
  return loadAgent().postJson('/api/v1/gate', record, opts);
}

async function collectClipboard(opts = {}) {
  writer.loadEndpointEnv(opts.envPath);
  const raw = await readClipboard(opts);
  if (!String(raw || '').trim()) {
    return { status: 'empty', sensitive: false, cleared: false, recorded: false };
  }

  const policy = await policyForClipboard(opts);
  const analysis = analyzeClipboard(raw, policy, opts);
  if (!sensitivityLabels(analysis).length) {
    return publicResult('clean', analysis);
  }

  let clearFailed = false;
  if (opts.clearOnBlock) {
    try {
      await clearClipboard(opts);
    } catch {
      clearFailed = true;
    }
  }

  const outcome = opts.clearOnBlock && !clearFailed ? 'action_blocked' : 'paste_flagged';
  const record = clipboardRecord(analysis, outcome, opts);
  const res = await reportClipboard(record, opts);
  const status = clearFailed ? 'clear_failed' : opts.clearOnBlock ? 'blocked' : 'flagged';
  if (!res) {
    return publicResult(status, analysis, {
      cleared: opts.clearOnBlock && !clearFailed,
      recorded: false,
      error: clearFailed ? 'clipboard cannot be cleared; control plane recording unavailable' : 'control plane recording unavailable',
    });
  }
  return publicResult(status, analysis, {
    cleared: opts.clearOnBlock && !clearFailed,
    recorded: true,
    id: res.id,
    ...(clearFailed ? { error: 'clipboard cannot be cleared' } : {}),
  });
}

function printHuman(result) {
  if (result.status === 'clean' || result.status === 'empty') {
    console.log(`PromptWall clipboard guard ${result.status}`);
    return;
  }
  const parts = [`PromptWall clipboard guard ${result.status}`];
  if (result.labels && result.labels.length) parts.push(result.labels.join(', '));
  if (result.cleared) parts.push('clipboard cleared');
  if (!result.recorded) parts.push('not recorded');
  console.log(parts.join(': '));
}

function exitCodeForResult(result) {
  if (!result) return 1;
  if (result.status === 'blocked' || result.status === 'failed' || result.status === 'clear_failed') return 1;
  return 0;
}

async function main() {
  try {
    const opts = parseArgs();
    if (opts.help) {
      console.log(usage());
      return;
    }
    const result = await collectClipboard(opts);
    if (opts.json) console.log(JSON.stringify(result, null, 2));
    else if (!opts.quiet) printHuman(result);
    process.exitCode = exitCodeForResult(result);
  } catch (err) {
    const error = publicError(err);
    if (!process.argv.includes('--quiet')) console.error(error);
    if (process.argv.includes('--json')) console.log(JSON.stringify({ status: 'failed', error }, null, 2));
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  DEFAULT_DESTINATION,
  DEFAULT_MAX_CHARS,
  analyzeClipboard,
  clipboardRecord,
  collectClipboard,
  exitCodeForResult,
  parseArgs,
  publicError,
  sensitivityLabels,
  usage,
};
