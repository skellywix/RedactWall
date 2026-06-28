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

const DEFAULT_DESTINATION = 'Desktop AI';
const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_POLL_MS = 250;
const MAX_FILES_PER_INVOCATION = 20;

function usage() {
  return [
    'Usage: node sensors/endpoint-agent/collectors/protected-upload.js --file <path> [options]',
    '',
    'Options:',
    '  --file <path>                 Local file path selected for protected upload; repeat for multi-select',
    '  --destination <app>           Desktop AI app or destination name',
    '  --destination-process <name>  Optional destination process name',
    '  --destination-url <url>       Optional destination URL',
    '  --user <id>                   Optional managed user identity',
    '  --env <path>                  Endpoint agent env file to load',
    '  --wait                        Wait until the endpoint agent consumes each handoff event',
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
    destination: DEFAULT_DESTINATION,
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
    if (!fs.existsSync(handoffPath)) return { consumed: true };
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
    ...(record.reason ? { reason: record.reason } : {}),
  };
}

async function collectProtectedUploads(opts = {}) {
  const files = normalizeFiles(opts.files || (opts.filePath ? [opts.filePath] : []));
  const results = [];
  for (const file of files) {
    try {
      assertLocalFile(file);
      const written = writer.writeHandoffFile(handoffOptions(file, opts));
      let consumed = false;
      let reason;
      if (opts.wait) {
        const wait = await waitForHandoffConsumption(written.path, opts);
        consumed = wait.consumed;
        reason = wait.reason;
      }
      results.push(publicResult({
        status: reason ? 'queued' : 'written',
        id: written.event.id,
        destination: nativeHandoff.publicDestination(written.event.destination),
        consumed,
        reason,
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

function printHuman(result) {
  const parts = [`PromptWall protected upload ${result.status}: ${result.count} file(s)`];
  if (result.failed) parts.push(`${result.failed} failed`);
  console.log(parts.join(', '));
  for (const item of result.results) {
    if (item.status === 'failed') console.log(`  - failed: ${item.error}`);
    else console.log(`  - ${item.status}: ${item.id} -> ${item.destination}${item.consumed ? ' (consumed)' : ''}`);
  }
}

function exitCodeForResult(result) {
  return result && result.status === 'written' ? 0 : 1;
}

async function main() {
  try {
    const opts = parseArgs();
    if (opts.help) {
      console.log(usage());
      return;
    }
    const result = await collectProtectedUploads(opts);
    if (opts.json) console.log(JSON.stringify(result, null, 2));
    else if (!opts.quiet) printHuman(result);
    process.exitCode = exitCodeForResult(result);
  } catch (err) {
    console.error(publicError(err));
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  DEFAULT_DESTINATION,
  MAX_FILES_PER_INVOCATION,
  collectProtectedUploads,
  normalizeFiles,
  parseArgs,
  publicError,
  exitCodeForResult,
  usage,
  waitForHandoffConsumption,
};
