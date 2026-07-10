'use strict';
/**
 * Windows-first desktop file-flow collector.
 *
 * This is intentionally a thin collector: it records a local upload intent by
 * calling the metadata-only handoff writer. The endpoint agent owns file reads,
 * detection, policy, redacted companion output, and sanitized reporting.
 */
const fs = require('fs');
const path = require('path');
const writer = require('../write-handoff');
const nativeHandoff = require('../native-handoff');
const { secureServerUrl } = require('../../shared/server-url');
const { cancelResponseBody, readBoundedJson } = require('../../shared/bounded-response');
const signedPolicy = require('../../shared/signed-policy');

const DEFAULT_DESTINATION = 'Desktop AI';
const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_POLL_MS = 250;
const DEFAULT_POLICY_TIMEOUT_MS = 5000;
const MAX_FILES_PER_INVOCATION = 20;

function usage() {
  return [
    'Usage: node sensors/endpoint-agent/collectors/protected-upload.js --file <path> [options]',
    '',
    'Options:',
    '  --file <path>                 Local file path selected for protected upload; repeat for multi-select',
    '  --destination <app>           Override the policy/default desktop AI app name',
    '  --destination-process <name>  Optional destination process name',
    '  --destination-url <url>       Optional destination URL',
    '  --user <id>                   Optional managed user identity',
    '  --env <path>                  Endpoint agent env file to load',
    '  --wait                        Wait for each endpoint inspection to reach a durable terminal result',
    '  --timeout-ms <ms>             Wait timeout, default 30000',
    '  --poll-ms <ms>                Wait poll interval, default 250',
    '  --json                        Print JSON result',
    '  --quiet                       Suppress non-error text output',
  ].join('\n');
}

function boundedNumber(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function parseArgs(argv = process.argv.slice(2)) {
  const args = [...argv];
  const parsed = {
    files: [],
    timeoutMs: DEFAULT_TIMEOUT_MS,
    pollMs: DEFAULT_POLL_MS,
  };
  while (args.length) {
    const arg = args.shift();
    if (arg === '--help' || arg === '-h') return { ...parsed, help: true };
    const takeValue = (key) => {
      const value = args.shift();
      if (!value) throw new Error(`${arg} requires a value`);
      parsed[key] = value;
    };
    if (arg === '--file') parsed.files.push(args.shift() || '');
    else if (arg === '--destination') takeValue('destination');
    else if (arg === '--destination-process') takeValue('destinationProcess');
    else if (arg === '--destination-url') takeValue('destinationUrl');
    else if (arg === '--user') takeValue('user');
    else if (arg === '--env') takeValue('envPath');
    else if (arg === '--timeout-ms') takeValue('timeoutMs');
    else if (arg === '--poll-ms') takeValue('pollMs');
    else if (arg === '--wait') parsed.wait = true;
    else if (arg === '--json') parsed.json = true;
    else if (arg === '--quiet') parsed.quiet = true;
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else throw new Error(`Unexpected argument: ${arg}`);
  }
  parsed.timeoutMs = boundedNumber(parsed.timeoutMs, DEFAULT_TIMEOUT_MS, 1000, 10 * 60 * 1000);
  parsed.pollMs = boundedNumber(parsed.pollMs, DEFAULT_POLL_MS, 50, 5000);
  return parsed;
}

function publicError(err) {
  const message = String((err && err.message) || err || 'protected upload failed');
  if (/ENOENT|no such file|not found/i.test(message)) return 'file is not available';
  if (/EACCES|EPERM|permission/i.test(message)) return 'file cannot be accessed';
  if (/must reference a file|path must be a local path|file path is required/i.test(message)) return message;
  if (/native handoff secret|endpoint env|already exists|unsupported|requires a value|Unknown option|Unexpected argument/i.test(message)) return message;
  return 'protected upload failed';
}

function cleanDestination(value) {
  const destination = String(value || '').trim();
  return destination || '';
}

function configuredServer(opts = {}) {
  const raw = cleanDestination(opts.server || process.env.REDACTWALL_URL || process.env.PROMPTWALL_URL || process.env.SENTINEL_URL);
  const production = String(opts.nodeEnv ?? process.env.NODE_ENV ?? '').trim().toLowerCase() === 'production';
  const allowInsecure = !production && (opts.allowInsecureServer === true
    || ['1', 'true', 'yes', 'on'].includes(String(process.env.REDACTWALL_ALLOW_INSECURE_SERVER || '').toLowerCase()));
  return secureServerUrl(raw, allowInsecure) || '';
}

function configuredKey(opts = {}) {
  return cleanDestination(opts.key || process.env.INGEST_API_KEY || process.env.REDACTWALL_INGEST_API_KEY);
}

function policyRequestTimeoutMs(opts = {}) {
  return boundedNumber(opts.policyTimeoutMs ?? process.env.REDACTWALL_REQUEST_TIMEOUT_MS, DEFAULT_POLICY_TIMEOUT_MS, 50, 120000);
}

async function fetchWithTimeout(fetchImpl, url, options, opts = {}) {
  const requestOptions = { ...(options || {}), redirect: 'error' };
  if (!globalThis.AbortController) return fetchImpl(url, requestOptions);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), policyRequestTimeoutMs(opts));
  try {
    return await fetchImpl(url, { ...requestOptions, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchPolicyDestination(opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const server = configuredServer(opts);
  const key = configuredKey(opts);
  const trustOptions = { ...opts, sensorId: 'endpoint-agent' };
  const cachedDestination = () => {
    const cached = signedPolicy.readCachedSignedPolicy(trustOptions);
    return cached.ok ? cleanDestination(cached.policy && cached.policy.desktopCollectorDestination) : '';
  };
  if (!fetchImpl || !server || !key) return cachedDestination();
  try {
    const res = await fetchWithTimeout(fetchImpl, server.replace(/\/+$/, '') + '/api/v1/policy/bundle', {
      headers: { 'x-api-key': key },
    }, opts);
    if (!res || !res.ok) {
      if (res) await cancelResponseBody(res);
      return cachedDestination();
    }
    const body = (await readBoundedJson(res, {
      maxBytes: 512 * 1024,
      timeoutMs: policyRequestTimeoutMs(opts),
      label: 'protected upload policy response',
    })).json;
    const accepted = signedPolicy.acceptSignedPolicyBundle(body, trustOptions);
    return accepted.ok
      ? cleanDestination(accepted.policy && accepted.policy.desktopCollectorDestination)
      : cachedDestination();
  } catch {
    return cachedDestination();
  }
}

async function resolveDestination(opts = {}) {
  const explicit = cleanDestination(opts.destination);
  if (explicit) return explicit;
  writer.loadEndpointEnv(opts.envPath);
  return (await fetchPolicyDestination(opts))
    || cleanDestination(process.env.ENDPOINT_AGENT_DESKTOP_DESTINATION)
    || cleanDestination(process.env.REDACTWALL_DESKTOP_DESTINATION)
    || cleanDestination(process.env.PROMPTWALL_DESKTOP_DESTINATION)
    || DEFAULT_DESTINATION;
}

function normalizeFiles(files) {
  const unique = [];
  const seen = new Set();
  for (const file of files || []) {
    if (typeof file !== 'string' || !file.trim()) continue;
    const resolved = path.resolve(file);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    unique.push(resolved);
  }
  if (!unique.length) throw new Error('at least one --file is required');
  if (unique.length > MAX_FILES_PER_INVOCATION) {
    throw new Error(`protected upload accepts at most ${MAX_FILES_PER_INVOCATION} files per invocation`);
  }
  return unique;
}

function assertLocalFile(file) {
  if (/^\\\\/.test(file)) throw new Error('native handoff filePath must be a local path');
  const stat = fs.statSync(file);
  if (!stat.isFile()) throw new Error('handoff path must reference a file');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHandoffConsumption(handoffPath, opts = {}) {
  const timeoutMs = boundedNumber(opts.timeoutMs, DEFAULT_TIMEOUT_MS, 1000, 10 * 60 * 1000);
  const pollMs = boundedNumber(opts.pollMs, DEFAULT_POLL_MS, 50, 5000);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    if (opts.event) {
      const claim = nativeHandoff.readHandoffClaim(opts.event, handoffPath, opts);
      if (claim && claim.state === 'terminal') {
        return { consumed: true, decision: claim.decision, status: claim.status, recorded: claim.recorded === true };
      }
    }
    if (!fs.existsSync(handoffPath)) {
      return { consumed: false, reason: 'handoff_missing_without_terminal_result' };
    }
    await sleep(pollMs);
  }
  return { consumed: false, reason: 'handoff_not_consumed_before_timeout' };
}

function handoffOptions(file, opts = {}) {
  return {
    envPath: opts.envPath,
    filePath: file,
    destination: opts.destination || DEFAULT_DESTINATION,
    destinationProcess: opts.destinationProcess,
    destinationUrl: opts.destinationUrl,
    user: opts.user,
    dir: opts.dir,
    id: opts.id,
    nonce: opts.nonce,
    now: opts.now,
  };
}

function publicResult(record) {
  return {
    status: record.status,
    id: record.id,
    destination: record.destination,
    consumed: !!record.consumed,
    ...(record.decision ? { decision: record.decision } : {}),
    ...(record.terminalStatus ? { terminalStatus: record.terminalStatus } : {}),
    ...(record.reason ? { reason: record.reason } : {}),
  };
}

async function collectProtectedUploads(opts = {}) {
  const files = normalizeFiles(opts.files || (opts.filePath ? [opts.filePath] : []));
  const results = [];
  let destination;
  try {
    destination = await resolveDestination(opts);
  } catch (err) {
    const error = publicError(err);
    return {
      status: 'failed',
      count: files.length,
      failed: files.length,
      results: files.map(() => ({ status: 'failed', error })),
    };
  }
  for (const file of files) {
    try {
      assertLocalFile(file);
      const written = writer.writeHandoffFile(handoffOptions(file, { ...opts, destination }));
      let consumed = false;
      let reason;
      let terminalDecision;
      let terminalStatus;
      if (opts.wait) {
        const wait = await waitForHandoffConsumption(written.path, { ...opts, event: written.event });
        consumed = wait.consumed;
        reason = wait.reason;
        terminalDecision = wait.decision;
        terminalStatus = wait.status;
        if (wait.consumed && wait.decision === 'block') {
          results.push({
            status: 'failed',
            error: 'upload was blocked by endpoint inspection',
            id: written.event.id,
            destination: nativeHandoff.publicDestination(written.event.destination),
            consumed: true,
            decision: wait.decision,
            terminalStatus: wait.status,
          });
          continue;
        }
      }
      results.push(publicResult({
        status: reason ? 'queued' : 'written',
        id: written.event.id,
        destination: nativeHandoff.publicDestination(written.event.destination),
        consumed,
        reason,
        decision: terminalDecision,
        terminalStatus,
      }));
    } catch (err) {
      results.push({ status: 'failed', error: publicError(err) });
    }
  }
  const failed = results.filter((result) => result.status === 'failed');
  const timedOut = results.filter((result) => result.reason === 'handoff_not_consumed_before_timeout');
  return {
    status: failed.length ? 'failed' : timedOut.length ? 'queued' : 'written',
    count: results.length,
    failed: failed.length,
    results,
  };
}

function printHuman(result, io = console) {
  const parts = [`RedactWall protected upload ${result.status}: ${result.count} file(s)`];
  if (result.failed) parts.push(`${result.failed} failed`);
  io.log(parts.join(', '));
  for (const item of result.results) {
    if (item.status === 'failed') io.log(`  - failed: ${item.error}`);
    else io.log(`  - ${item.status}: ${item.id} -> ${item.destination}${item.consumed ? ' (inspection complete)' : ''}`);
  }
}

function exitCodeForResult(result) {
  return result && result.status === 'written' ? 0 : 1;
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const collect = deps.collectProtectedUploads || collectProtectedUploads;
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
    io.error(publicError(err));
    return 1;
  }
}

if (require.main === module) main().then((code) => { process.exitCode = code; });

module.exports = {
  DEFAULT_DESTINATION,
  MAX_FILES_PER_INVOCATION,
  collectProtectedUploads,
  configuredKey,
  configuredServer,
  fetchPolicyDestination,
  main,
  normalizeFiles,
  parseArgs,
  printHuman,
  publicError,
  resolveDestination,
  exitCodeForResult,
  usage,
  waitForHandoffConsumption,
};
