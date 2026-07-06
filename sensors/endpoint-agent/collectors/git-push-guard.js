'use strict';
/**
 * Local git pre-push guard.
 *
 * Scans outbound git diffs locally before they leave a workstation and reports
 * only masked findings to the control plane. It never uploads source code,
 * repository paths, remote repository names, or patch bodies.
 */
const { execFile } = require('child_process');
const { promisify } = require('util');
const writer = require('../write-handoff');
const D = require('../../../detection-engine/detect');

const execFileAsync = promisify(execFile);
const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
const ZERO_SHA = /^0{40}$/;
const SHA_RE = /^[0-9a-f]{40}$/i;
const DEFAULT_MAX_CHARS = 200000;
const DEFAULT_MAX_DIFF_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_DESTINATION = 'git-remote';
let endpointAgent;

function loadAgent() {
  if (!endpointAgent) endpointAgent = require('../agent');
  return endpointAgent;
}

function usage() {
  return [
    'Usage: node sensors/endpoint-agent/collectors/git-push-guard.js [options]',
    '',
    'Options:',
    '  --pre-push                   Read git pre-push ref updates from stdin',
    '  --repo <path>                Repository path, default current directory',
    '  --remote-name <name>         Optional git remote name',
    '  --remote-url <url>           Optional git remote URL; only host is reported',
    '  --base <sha>                 Explicit base SHA for manual scans',
    '  --head <sha>                 Explicit head SHA for manual scans',
    '  --staged                     Scan staged changes instead of push ranges',
    '  --allowed-host <host>        Git host allowed for source-code-only pushes; repeatable',
    '  --env <path>                 Endpoint agent env file to load',
    '  --user <id>                  Optional managed user identity',
    '  --max-chars <n>              Maximum diff characters to inspect, default 200000',
    '  --max-diff-bytes <n>         Maximum git diff bytes to collect, default 2097152',
    '  --json                       Print JSON result',
    '  --quiet                      Suppress non-error text output',
  ].join('\n');
}

function boundedNumber(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

function parseArgs(argv = process.argv.slice(2)) {
  const args = [...argv];
  const parsed = {
    repo: process.cwd(),
    allowedHosts: [],
    maxChars: DEFAULT_MAX_CHARS,
    maxDiffBytes: DEFAULT_MAX_DIFF_BYTES,
  };
  while (args.length) {
    const arg = args.shift();
    if (arg === '--help' || arg === '-h') return { ...parsed, help: true };
    const takeValue = (key) => {
      const value = args.shift();
      if (!value) throw new Error(`${arg} requires a value`);
      parsed[key] = value;
    };
    if (arg === '--pre-push') parsed.prePush = true;
    else if (arg === '--repo') takeValue('repo');
    else if (arg === '--remote-name') takeValue('remoteName');
    else if (arg === '--remote-url') takeValue('remoteUrl');
    else if (arg === '--base') takeValue('base');
    else if (arg === '--head') takeValue('head');
    else if (arg === '--staged') parsed.staged = true;
    else if (arg === '--allowed-host') parsed.allowedHosts.push(args.shift() || '');
    else if (arg === '--env') takeValue('envPath');
    else if (arg === '--user') takeValue('user');
    else if (arg === '--max-chars') takeValue('maxChars');
    else if (arg === '--max-diff-bytes') takeValue('maxDiffBytes');
    else if (arg === '--json') parsed.json = true;
    else if (arg === '--quiet') parsed.quiet = true;
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else throw new Error(`Unexpected argument: ${arg}`);
  }
  parsed.maxChars = boundedNumber(parsed.maxChars, DEFAULT_MAX_CHARS, 1024, 1000000);
  parsed.maxDiffBytes = boundedNumber(parsed.maxDiffBytes, DEFAULT_MAX_DIFF_BYTES, 4096, 12 * 1024 * 1024);
  return parsed;
}

function publicError(err) {
  const message = String((err && err.message) || err || 'git push guard failed');
  if (/requires a value|Unknown option|Unexpected argument|endpoint env/i.test(message)) return message;
  if (/ENOENT|not a git repository|outside repository|git is not available/i.test(message)) return 'git repository is not available';
  if (/diff too large|stdout maxBuffer|maxBuffer/i.test(message)) return 'git diff is too large to inspect locally';
  if (/invalid push range|invalid sha|missing push range/i.test(message)) return message;
  if (/EACCES|EPERM|permission|access/i.test(message)) return 'git repository cannot be accessed';
  return 'git push guard failed';
}

function sanitizeHost(value) {
  const host = String(value || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!/^[a-z0-9.-]{1,253}$/.test(host) || host.includes('..')) return '';
  return host;
}

function remoteHost(remoteUrl) {
  const raw = String(remoteUrl || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    return sanitizeHost(parsed.hostname);
  } catch {}
  const scp = raw.match(/^(?:[^@\s]+@)?([A-Za-z0-9.-]+):[^:]+$/);
  if (scp) return sanitizeHost(scp[1]);
  const hostOnly = raw.match(/^([A-Za-z0-9.-]+)(?:\/|$)/);
  return hostOnly ? sanitizeHost(hostOnly[1]) : '';
}

function destinationFromRemote(remoteUrl, remoteName) {
  const host = remoteHost(remoteUrl);
  if (host) return `git:${host}`;
  const name = String(remoteName || '').trim().toLowerCase();
  return name && /^[a-z0-9._-]{1,80}$/.test(name) ? `git:${name}` : DEFAULT_DESTINATION;
}

function configuredAllowedHosts(opts = {}) {
  const raw = []
    .concat(opts.allowedHosts || [])
    .concat(String(process.env.REDACTWALL_GIT_ALLOWED_HOSTS || process.env.PROMPTWALL_GIT_ALLOWED_HOSTS || process.env.ENDPOINT_AGENT_GIT_ALLOWED_HOSTS || '').split(','));
  const out = [];
  const seen = new Set();
  for (const item of raw) {
    const host = sanitizeHost(item);
    if (!host || seen.has(host)) continue;
    seen.add(host);
    out.push(host);
  }
  return out;
}

function destinationAllowed(remoteUrl, opts = {}) {
  const host = remoteHost(remoteUrl);
  if (!host) return false;
  return configuredAllowedHosts(opts).some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
}

function parsePrePushStdin(input) {
  const ranges = [];
  const lines = String(input || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    const [localRef, localSha, remoteRef, remoteSha] = line.split(/\s+/);
    if (!localRef || !localSha || !remoteRef || !remoteSha) throw new Error('invalid push range');
    if (!SHA_RE.test(localSha) || !SHA_RE.test(remoteSha)) throw new Error('invalid sha in push range');
    if (ZERO_SHA.test(localSha)) continue;
    ranges.push({
      localRef: safeRefLabel(localRef),
      remoteRef: safeRefLabel(remoteRef),
      base: ZERO_SHA.test(remoteSha) ? EMPTY_TREE : remoteSha,
      head: localSha,
      newBranch: ZERO_SHA.test(remoteSha),
    });
  }
  return ranges;
}

function safeRefLabel(value) {
  const ref = String(value || '').trim();
  const tail = ref.split('/').filter(Boolean).pop() || 'ref';
  return /^[A-Za-z0-9._-]{1,80}$/.test(tail) ? tail : 'ref';
}

function rangeFromOptions(opts = {}) {
  if (opts.staged) return [{ staged: true }];
  if (!opts.base && !opts.head) return [{ staged: true }];
  if (!SHA_RE.test(String(opts.head || ''))) throw new Error('missing push range head sha');
  const base = String(opts.base || EMPTY_TREE);
  if (!SHA_RE.test(base)) throw new Error('invalid sha in push range');
  return [{ base, head: String(opts.head), newBranch: ZERO_SHA.test(base) }];
}

async function readStdin(stream = process.stdin) {
  if (!stream || stream.isTTY) return '';
  let data = '';
  stream.setEncoding('utf8');
  for await (const chunk of stream) data += chunk;
  return data;
}

async function runGit(args, opts = {}) {
  const run = opts.execFileAsync || execFileAsync;
  try {
    const result = await run('git', ['-C', opts.repo || process.cwd(), ...args], {
      windowsHide: true,
      timeout: boundedNumber(opts.timeoutMs, DEFAULT_TIMEOUT_MS, 1000, 120000),
      maxBuffer: boundedNumber(opts.maxDiffBytes, DEFAULT_MAX_DIFF_BYTES, 4096, 12 * 1024 * 1024) + 4096,
    });
    return result.stdout || '';
  } catch (err) {
    if (err && /maxBuffer/.test(String(err.message || ''))) throw new Error('git diff too large to inspect locally');
    if (err && err.code === 'ENOENT') throw new Error('git is not available');
    throw err;
  }
}

function diffArgsForRange(range) {
  if (range.staged) return ['diff', '--cached', '--no-ext-diff', '--no-color', '--unified=0', '--find-renames'];
  return ['diff', '--no-ext-diff', '--no-color', '--unified=0', '--find-renames', range.base, range.head, '--'];
}

// A remote-side base SHA may not exist locally (teammate pushed it, we never
// fetched it). Diffing against a missing object fails the whole push; fall back
// to the empty tree so the full head content is still scanned rather than
// blocking a clean push with a confusing error.
async function ensureLocalBase(range, opts = {}) {
  if (range.staged || !range.base || range.base === EMPTY_TREE) return range;
  try {
    await runGit(['cat-file', '-e', `${range.base}^{commit}`], opts);
    return range;
  } catch (err) {
    if (/git is not available/.test(String((err && err.message) || ''))) throw err;
    return { ...range, base: EMPTY_TREE, newBranch: true };
  }
}

async function collectDiff(opts = {}) {
  if (opts.diffText !== undefined) {
    const text = String(opts.diffText || '');
    const bytes = Buffer.byteLength(text, 'utf8');
    if (bytes > boundedNumber(opts.maxDiffBytes, DEFAULT_MAX_DIFF_BYTES, 4096, 12 * 1024 * 1024)) {
      return { status: 'too_large', text: '', bytes, ranges: [] };
    }
    return { status: 'ok', text, bytes, ranges: opts.ranges || [] };
  }
  const stdin = opts.prePush ? (opts.stdin !== undefined ? opts.stdin : await readStdin(opts.stdinStream)) : '';
  const ranges = opts.prePush ? parsePrePushStdin(stdin) : rangeFromOptions(opts);
  if (!ranges.length) return { status: 'ok', text: '', bytes: 0, ranges };
  const chunks = [];
  let bytes = 0;
  const maxBytes = boundedNumber(opts.maxDiffBytes, DEFAULT_MAX_DIFF_BYTES, 4096, 12 * 1024 * 1024);
  for (const range of ranges) {
    const resolved = await ensureLocalBase(range, opts);
    const chunk = await runGit(diffArgsForRange(resolved), opts);
    bytes += Buffer.byteLength(chunk, 'utf8');
    if (bytes > maxBytes) return { status: 'too_large', text: '', bytes, ranges };
    chunks.push(chunk);
  }
  return { status: 'ok', text: chunks.join('\n'), bytes, ranges };
}

async function policyForGit(opts = {}) {
  const agent = loadAgent();
  if (opts.policy) return agent.sensorPolicy(opts.policy);
  const fetched = await agent.fetchPolicy({ ...opts, silent: true });
  return agent.sensorPolicy(fetched || {});
}

function analyzeDiff(text, policy, opts = {}) {
  const sample = String(text || '').slice(0, boundedNumber(opts.maxChars, DEFAULT_MAX_CHARS, 1024, 1000000));
  return D.analyze(sample, {
    ignore: policy.ignore,
    disabledDetectors: policy.disabledDetectors,
    customDetectors: policy.customDetectors,
  });
}

function sensitivityLabels(analysis = {}) {
  return [...new Set(
    (analysis.findings || []).map((f) => f.type)
      .concat((analysis.categories || []).map((c) => c.category))
      .filter(Boolean)
  )];
}

function findingLabels(analysis = {}) {
  return [...new Set((analysis.findings || []).map((f) => f.type).filter(Boolean))];
}

function categoryLabels(analysis = {}) {
  return [...new Set((analysis.categories || []).map((c) => c.category).filter(Boolean))];
}

function shouldBlock(analysis, opts = {}) {
  const findings = findingLabels(analysis);
  const categories = categoryLabels(analysis);
  if (!findings.length && !categories.length) return false;
  if (!destinationAllowed(opts.remoteUrl, opts)) return true;
  const allowedSourceOnly = categories.every((label) => label === 'SOURCE_CODE');
  return findings.length > 0 || !allowedSourceOnly;
}

function safePrompt(status, analysis, extra = {}) {
  const labels = sensitivityLabels(analysis);
  const labelText = labels.length ? labels.join(', ') : (extra.reason || 'uninspected git diff');
  return `[git push ${status} locally] ${labelText}`.slice(0, 1000);
}

function gitPushRecord(analysis, outcome, opts = {}, extra = {}) {
  const agent = loadAgent();
  return {
    prompt: safePrompt(outcome === 'action_blocked' ? 'blocked' : 'flagged', analysis, extra),
    user: opts.user,
    destination: destinationFromRemote(opts.remoteUrl, opts.remoteName),
    source: 'endpoint_agent',
    channel: 'git_push',
    sensor: agent.sensorMetadata(),
    clientOutcome: outcome,
    note: extra.reason === 'diff_too_large' || extra.reason === 'diff_partially_inspected'
      ? 'endpoint git push blocked locally because the diff exceeded inspection bounds'
      : 'endpoint git push blocked locally after sensitive content detection',
    clientPreRedacted: true,
    clientFindings: agent.publicFindings(analysis),
    clientCategories: agent.publicCategories(analysis),
    clientEntityCounts: analysis.entityCounts || {},
    clientRiskScore: analysis.riskScore || 0,
    clientMaxSeverity: analysis.maxSeverity || 0,
    clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
  };
}

async function reportGitPush(record, opts = {}) {
  if (opts.report) return opts.report(record, opts);
  return loadAgent().postJson('/api/v1/gate', record, opts);
}

function publicResult(status, analysis = {}, extra = {}) {
  return {
    status,
    sensitive: !!sensitivityLabels(analysis).length,
    labels: sensitivityLabels(analysis),
    riskScore: analysis.riskScore || 0,
    destination: extra.destination || DEFAULT_DESTINATION,
    blocked: status === 'blocked',
    recorded: !!extra.recorded,
    ...(extra.id ? { id: extra.id } : {}),
    ...(extra.reason ? { reason: extra.reason } : {}),
    ...(extra.refCount !== undefined ? { refCount: extra.refCount } : {}),
    ...(extra.bytesScanned !== undefined ? { bytesScanned: extra.bytesScanned } : {}),
    ...(extra.error ? { error: extra.error } : {}),
  };
}

async function collectGitPush(opts = {}) {
  writer.loadEndpointEnv(opts.envPath);
  const destination = destinationFromRemote(opts.remoteUrl, opts.remoteName);
  let diff;
  try {
    diff = await collectDiff(opts);
  } catch (err) {
    return publicResult('failed', {}, { destination, error: publicError(err) });
  }
  if (diff.status === 'too_large') {
    const record = gitPushRecord({}, 'action_blocked', opts, { reason: 'diff_too_large' });
    const res = await reportGitPush(record, opts);
    return publicResult('blocked', {}, {
      destination,
      recorded: !!res,
      id: res && res.id,
      reason: 'diff_too_large',
      refCount: diff.ranges.length,
      bytesScanned: 0,
      ...(res ? {} : { error: 'control plane recording unavailable' }),
    });
  }
  if (!String(diff.text || '').trim()) {
    return publicResult('clean', {}, {
      destination,
      refCount: diff.ranges.length,
      bytesScanned: diff.bytes,
    });
  }
  const policy = await policyForGit(opts);
  const analysis = analyzeDiff(diff.text, policy, opts);
  // analyzeDiff only inspects the first maxChars; content past that bound is
  // never scanned, so a diff larger than the window is blocked as partially
  // inspected (fail closed) rather than reported clean like the too_large path.
  const maxChars = boundedNumber(opts.maxChars, DEFAULT_MAX_CHARS, 1024, 1000000);
  const partiallyInspected = String(diff.text || '').length > maxChars;
  if (!partiallyInspected && !shouldBlock(analysis, opts)) {
    return publicResult('clean', analysis, {
      destination,
      refCount: diff.ranges.length,
      bytesScanned: diff.bytes,
    });
  }
  const extra = partiallyInspected ? { reason: 'diff_partially_inspected' } : {};
  const record = gitPushRecord(analysis, 'action_blocked', opts, extra);
  const res = await reportGitPush(record, opts);
  return publicResult('blocked', analysis, {
    destination,
    recorded: !!res,
    id: res && res.id,
    refCount: diff.ranges.length,
    bytesScanned: diff.bytes,
    ...extra,
    ...(res ? {} : { error: 'control plane recording unavailable' }),
  });
}

function printHuman(result, io = console) {
  if (result.status === 'clean') {
    io.log(`RedactWall git push guard clean: ${result.destination}`);
    return;
  }
  if (result.status === 'failed') {
    io.log(`RedactWall git push guard failed: ${result.error}`);
    return;
  }
  const parts = [`RedactWall git push guard ${result.status}: ${result.destination}`];
  if (result.labels && result.labels.length) parts.push(result.labels.join(', '));
  if (result.reason) parts.push(result.reason);
  if (!result.recorded) parts.push('not recorded');
  io.log(parts.join(': '));
}

function exitCodeForResult(result) {
  if (!result) return 1;
  if (result.status === 'clean') return 0;
  return 1;
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const collect = deps.collectGitPush || collectGitPush;
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
  DEFAULT_MAX_DIFF_BYTES,
  EMPTY_TREE,
  analyzeDiff,
  collectDiff,
  collectGitPush,
  configuredAllowedHosts,
  destinationAllowed,
  destinationFromRemote,
  exitCodeForResult,
  gitPushRecord,
  main,
  parseArgs,
  parsePrePushStdin,
  printHuman,
  publicError,
  remoteHost,
  shouldBlock,
  usage,
  _internal: {
    diffArgsForRange,
    readStdin,
    runGit,
    safeRefLabel,
  },
};
