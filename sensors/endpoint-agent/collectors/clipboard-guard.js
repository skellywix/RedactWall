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
  if ((opts.platform || process.platform) !== 'win32') throw new Error('clipboard guard is not supported on this platform');
  const run = opts.execFileAsync || execFileAsync;
  const result = await run('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-Command',
    'Get-Clipboard -Raw',
  ], { windowsHide: true, timeout: 5000, maxBuffer: 2 * 1024 * 1024 });
  return result.stdout || '';
}

function isClipboardTooLargeError(error) {
  return !!error && (error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
    || /maxBuffer|stdout.*too large|stdout.*exceeded/i.test(String(error.message || '')));
}

async function readClipboardResult(opts = {}) {
  try {
    return { status: 'ok', text: await readClipboard(opts) };
  } catch (error) {
    if (isClipboardTooLargeError(error)) return { status: 'too_large', text: '' };
    throw error;
  }
}

// Sanitized origin-app provenance: the FOREGROUND process' executable name only
// (basename, lowercased, [a-z0-9_] id) — never a window title, path, argument,
// or any clipboard content. This lets the examiner pack say "NPI copied from
// the core-banking client into ChatGPT" without leaking anything.
const ORIGIN_APP_ID_RE = /^[a-z][a-z0-9_]{0,39}$/;
function normalizeOriginApp(value) {
  // basename first so a stray path never leaks its structure into the id.
  const leaf = String(value || '').trim().replace(/\\/g, '/').split('/').pop() || '';
  const base = leaf.toLowerCase().replace(/\.exe$/, '').replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '');
  return ORIGIN_APP_ID_RE.test(base) ? base : null;
}

async function foregroundApp(opts = {}) {
  if (opts.foregroundApp) return normalizeOriginApp(await opts.foregroundApp());
  if ((opts.platform || process.platform) !== 'win32') return null;
  const run = opts.execFileAsync || execFileAsync;
  // Returns ONLY the foreground process name (e.g. "chrome"). No title/path.
  const script = 'Add-Type @"\nusing System;using System.Runtime.InteropServices;'
    + 'public class W{[DllImport("user32.dll")]public static extern IntPtr GetForegroundWindow();'
    + '[DllImport("user32.dll")]public static extern int GetWindowThreadProcessId(IntPtr h,out int p);}"@;'
    + '$p=0;[void][W]::GetWindowThreadProcessId([W]::GetForegroundWindow(),[ref]$p);'
    + '(Get-Process -Id $p -ErrorAction SilentlyContinue).ProcessName';
  try {
    const result = await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], { windowsHide: true, timeout: 4000, maxBuffer: 4096 });
    return normalizeOriginApp((result.stdout || '').split(/\r?\n/)[0]);
  } catch (_) { return null; }
}

async function clearClipboard(opts = {}) {
  if (opts.clearClipboard) return opts.clearClipboard();
  if ((opts.platform || process.platform) !== 'win32') throw new Error('clipboard guard is not supported on this platform');
  const run = opts.execFileAsync || execFileAsync;
  await run('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-Command',
    "Set-Clipboard -Value ''",
  ], { windowsHide: true, timeout: 5000, maxBuffer: 1024 });
}

function sensitivityLabels(analysis = {}) {
  const labels =
    (analysis.findings || []).map((f) => f.type)
      .concat((analysis.categories || []).map((c) => c.category))
      .filter(Boolean);
  if (analysis.opaqueEncoded === true) labels.push('OPAQUE_ENCODED_CONTENT');
  return [...new Set(labels)];
}

function safePrompt(status, analysis) {
  const labels = sensitivityLabels(analysis);
  const labelText = labels.length ? labels.join(', ') : 'sensitive content';
  return `[clipboard ${status} locally] ${labelText}`.slice(0, 1000);
}

function clipboardNote(outcome, tooLarge) {
  if (tooLarge) return 'endpoint clipboard blocked locally: content too large to inspect';
  return outcome === 'action_blocked'
    ? 'endpoint clipboard cleared locally after sensitive content detection'
    : 'endpoint clipboard inspected locally; sensitive content detected';
}

function clipboardRecord(analysis, outcome, opts = {}) {
  const agent = loadAgent();
  const status = outcome === 'action_blocked' ? 'blocked' : 'flagged';
  const originApp = normalizeOriginApp(opts.originApp);
  const tooLarge = opts.reason === 'too_large';
  const policyUnavailable = opts.reason === 'policy_unavailable';
  const base = {
    prompt: policyUnavailable ? '[clipboard blocked locally] policy unavailable'
      : (tooLarge ? `[clipboard ${status} locally] too large to inspect` : safePrompt(status, analysis)),
    user: opts.user,
    destination: String(opts.destination || DEFAULT_DESTINATION).trim() || DEFAULT_DESTINATION,
    source: 'endpoint_agent',
    channel: 'clipboard',
    sensor: agent.sensorMetadata(),
    ...(originApp ? { originApp } : {}),
    clientOutcome: outcome,
    note: policyUnavailable ? 'endpoint clipboard blocked locally because no trusted signed policy is available'
      : clipboardNote(outcome, tooLarge),
  };
  if (tooLarge || policyUnavailable) return base;
  if (analysis && analysis.opaqueEncoded === true) {
    return {
      ...base,
      clientPreRedacted: true,
      clientFindings: [],
      clientCategories: [{ category: 'OPAQUE_ENCODED_CONTENT', score: 1 }],
      clientEntityCounts: { OPAQUE_ENCODED_CONTENT: 1 },
      clientRiskScore: 14,
      clientMaxSeverity: 2,
      clientMaxSeverityLabel: 'medium',
    };
  }
  return {
    ...base,
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
  const override = agent._testPolicyOverride(opts);
  if (override) return override;
  const fetched = await agent.fetchPolicy({ ...opts, silent: true });
  return fetched ? agent.sensorPolicy(fetched) : null;
}

function analyzeClipboard(text, policy, opts = {}) {
  const sample = String(text || '').slice(0, boundedNumber(opts.maxChars, DEFAULT_MAX_CHARS, 1024, 1000000));
  return D.analyze(sample, {
    ignore: policy.ignore,
    disabledDetectors: policy.disabledDetectors,
    customDetectors: policy.customDetectors,
    opaqueEncodedContent: true,
  });
}

function publicResult(status, analysis, extra = {}) {
  const opaqueEncoded = analysis && analysis.opaqueEncoded === true;
  return {
    status,
    sensitive: opaqueEncoded || !!sensitivityLabels(analysis).length,
    labels: sensitivityLabels(analysis),
    riskScore: (analysis && analysis.riskScore) || 0,
    cleared: !!extra.cleared,
    recorded: !!extra.recorded,
    ...(extra.id ? { id: extra.id } : {}),
    ...(extra.error ? { error: extra.error } : {}),
    ...(extra.reason ? { reason: extra.reason } : {}),
  };
}

async function reportClipboard(record, opts = {}) {
  if (opts.report) return opts.report(record, opts);
  return loadAgent().postJson('/api/v1/gate', record, opts);
}

async function blockTooLargeClipboard(opts = {}) {
  const analysis = { findings: [], categories: [], entityCounts: {}, riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none' };
  let cleared = false;
  try {
    await clearClipboard(opts);
    cleared = true;
  } catch {}
  const outcome = cleared ? 'action_blocked' : 'paste_flagged';
  const originApp = opts.originApp !== undefined ? opts.originApp : await foregroundApp(opts).catch(() => null);
  const record = clipboardRecord(analysis, outcome, { ...opts, originApp, reason: 'too_large' });
  const response = await reportClipboard(record, opts).catch(() => null);
  return publicResult(cleared ? 'blocked' : 'clear_failed', analysis, {
    cleared,
    recorded: !!response,
    id: response && response.id,
    reason: 'too_large',
    ...(!cleared || !response ? {
      error: !cleared
        ? 'clipboard cannot be cleared; control plane recording unavailable'
        : 'control plane recording unavailable',
    } : {}),
  });
}

async function collectClipboard(opts = {}) {
  writer.loadEndpointEnv(opts.envPath);
  const read = await readClipboardResult(opts);
  if (read.status === 'too_large') return blockTooLargeClipboard(opts);
  const raw = read.text;
  if (!String(raw || '').trim()) {
    return { status: 'empty', sensitive: false, cleared: false, recorded: false };
  }

  const policy = await policyForClipboard(opts);
  if (!policy) {
    let cleared = false;
    try { await clearClipboard(opts); cleared = true; } catch {}
    const analysis = { findings: [], categories: [], entityCounts: {}, riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none' };
    const res = await reportClipboard(clipboardRecord(analysis, 'action_blocked', { ...opts, reason: 'policy_unavailable' }), opts);
    return publicResult('blocked', analysis, {
      cleared,
      recorded: !!res,
      id: res && res.id,
      reason: 'policy_unavailable',
      ...(!res || !cleared ? {
        error: !cleared
          ? 'clipboard cannot be cleared; control plane recording unavailable'
          : 'control plane recording unavailable',
      } : {}),
    });
  }
  const analysis = analyzeClipboard(raw, policy, opts);
  // readClipboard captures up to 2MB but analyzeClipboard only inspects the
  // first maxChars; anything past that bound is uninspected, so an over-limit
  // clipboard is treated as uninspectable (fail closed) rather than reported
  // clean while sensitive content sits in the untested tail.
  const limit = boundedNumber(opts.maxChars, DEFAULT_MAX_CHARS, 1024, 1000000);
  const tooLarge = String(raw).length > limit;
  if (!tooLarge && analysis.opaqueEncoded !== true && !sensitivityLabels(analysis).length) {
    return publicResult('clean', analysis);
  }

  // Encoded findings are an explicit evasion attempt, and opaque encoded bytes
  // cannot be inspected at all. Clear those even in report-only mode so the
  // clipboard guard cannot label the event while leaving the bypass pasteable.
  const encodedEvasion = analysis.opaqueEncoded === true
    || (analysis.findings || []).some((finding) => !!finding.encoded);
  const mustClear = tooLarge || opts.clearOnBlock || encodedEvasion;
  let clearFailed = false;
  if (mustClear) {
    try {
      await clearClipboard(opts);
    } catch {
      clearFailed = true;
    }
  }

  const outcome = mustClear && !clearFailed ? 'action_blocked' : 'paste_flagged';
  // Best-effort origin-app provenance (sanitized process name only).
  const originApp = opts.originApp !== undefined ? opts.originApp : await foregroundApp(opts).catch(() => null);
  const record = clipboardRecord(analysis, outcome, { ...opts, originApp, ...(tooLarge ? { reason: 'too_large' } : {}) });
  const res = await reportClipboard(record, opts);
  const status = clearFailed ? 'clear_failed' : mustClear ? 'blocked' : 'flagged';
  if (!res) {
    return publicResult(status, analysis, {
      cleared: mustClear && !clearFailed,
      recorded: false,
      ...(tooLarge ? { reason: 'too_large' } : {}),
      error: clearFailed ? 'clipboard cannot be cleared; control plane recording unavailable' : 'control plane recording unavailable',
    });
  }
  return publicResult(status, analysis, {
    cleared: mustClear && !clearFailed,
    recorded: true,
    id: res.id,
    ...(tooLarge ? { reason: 'too_large' } : {}),
    ...(clearFailed ? { error: 'clipboard cannot be cleared' } : {}),
  });
}

function printHuman(result, io = console) {
  if (result.status === 'clean' || result.status === 'empty') {
    io.log(`RedactWall clipboard guard ${result.status}`);
    return;
  }
  const parts = [`RedactWall clipboard guard ${result.status}`];
  if (result.labels && result.labels.length) parts.push(result.labels.join(', '));
  if (result.cleared) parts.push('clipboard cleared');
  if (!result.recorded) parts.push('not recorded');
  io.log(parts.join(': '));
}

function exitCodeForResult(result) {
  if (!result) return 1;
  if (result.status === 'blocked' || result.status === 'failed' || result.status === 'clear_failed') return 1;
  return 0;
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const collect = deps.collectClipboard || collectClipboard;
  try {
    const opts = parseArgs(argv);
    if (opts.help) {
      io.log(usage());
      return 0;
    }
    const result = await collect(opts);
    if (opts.json) io.log(JSON.stringify(result, null, 2));
    else if (!opts.quiet) printHuman(result, io);
    return exitCodeForResult(result);
  } catch (err) {
    const error = publicError(err);
    if (!argv.includes('--quiet')) io.error(error);
    if (argv.includes('--json')) io.log(JSON.stringify({ status: 'failed', error }, null, 2));
    return 1;
  }
}

if (require.main === module) main().then((code) => { process.exitCode = code; });

module.exports = {
  DEFAULT_DESTINATION,
  DEFAULT_MAX_CHARS,
  analyzeClipboard,
  clipboardRecord,
  collectClipboard,
  exitCodeForResult,
  main,
  parseArgs,
  printHuman,
  publicError,
  sensitivityLabels,
  usage,
  _internal: {
    clearClipboard,
    readClipboard,
    readClipboardResult,
    isClipboardTooLargeError,
    clipboardRecord,
    foregroundApp,
    normalizeOriginApp,
  },
};
