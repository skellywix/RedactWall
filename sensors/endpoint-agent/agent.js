'use strict';
require('../../server/env').loadEnv();
/**
 * PromptWall endpoint agent (reference implementation).
 *
 * Catches sensitive FILES headed to desktop AI apps that a browser extension
 * cannot see. Watches a folder, extracts and detects locally using the same
 * engine as the other sensors, then reports sanitized evidence to the control
 * plane. Respects scanner ignore-lists.
 *
 * Usage: node agent.js [watchDir]
 *   SENTINEL_URL or PROMPTWALL_URL (default http://localhost:4000),
 *   INGEST_API_KEY or PROMPTWALL_INGEST_API_KEY (required for control-plane calls)
 *   ENDPOINT_AGENT_WATCH_DIR or PROMPTWALL_ENDPOINT_AGENT_WATCH_DIR
 *   ENDPOINT_AGENT_HANDOFF_SECRET or PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET enables signed native file-flow handoff events
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const nativeHandoff = require('./native-handoff');
const processors = require('../../server/processors');
const policyEngine = require('../../server/policy');
const D = require('../../detection-engine/detect');
const VERSION = require('../../package.json').version;

const SERVER = process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || '';
function defaultWatchDir(argv = process.argv, env = process.env) {
  return argv[2] || env.ENDPOINT_AGENT_WATCH_DIR || env.PROMPTWALL_ENDPOINT_AGENT_WATCH_DIR || path.join(os.tmpdir(), 'promptwall-watch');
}
const WATCH = defaultWatchDir();
const HANDOFF_DIR = nativeHandoff.defaultHandoffDir();
const HANDOFF_SECRET = nativeHandoff.configuredHandoffSecret();

const DEFAULT_SCANNER = {
  ignoreDirectories: ['node_modules', '.git', 'Library', 'Applications', 'AppData'],
  ignoreFilenames: ['thumbs.db', '.ds_store', 'package.json', 'package-lock.json'],
  ignoreExtensions: ['.tmp', '.log', '.lock'],
  maxFileBytes: 6.3 * 1024 * 1024,
};
const REDACTION_HANDOFF_DIR = '.promptwall-redacted';
const REDACTION_HANDOFF_SUFFIX = '.promptwall-redacted.txt';
const LEGACY_REDACTION_HANDOFF_DIR = '.promptsentinel-redacted';
const LEGACY_REDACTION_HANDOFF_SUFFIX = '.promptsentinel-redacted.txt';
const POLICY_REFRESH_MS = 15 * 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;
const HANDOFF_RETRY_DELAY_MS = 200;
let scannerState = scannerConfig(DEFAULT_SCANNER);
let policyState = sensorPolicy(policyEngine.DEFAULT_POLICY);

if (!fs.existsSync(WATCH)) fs.mkdirSync(WATCH, { recursive: true });

function configuredKey(opts = {}) {
  const value = Object.prototype.hasOwnProperty.call(opts, 'key') ? opts.key : KEY;
  return typeof value === 'string' ? value.trim() : '';
}

function handoffSecretReady(secret) {
  return typeof secret === 'string' && secret.trim().length >= 32;
}

function lowerList(value, fallback = []) {
  const src = Array.isArray(value) ? value : value instanceof Set ? Array.from(value) : fallback;
  return src
    .filter((item) => typeof item === 'string' && item.trim())
    .map((item) => item.trim().toLowerCase());
}

function detectorList(value, fallback = []) {
  const src = Array.isArray(value) ? value : fallback;
  return src.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim());
}

function scannerConfig(input = {}) {
  const merged = { ...DEFAULT_SCANNER, ...(input || {}) };
  const maxFileBytes = Number(merged.maxFileBytes);
  return {
    ignoreDirectories: new Set(lowerList(merged.ignoreDirectories, DEFAULT_SCANNER.ignoreDirectories)),
    ignoreFilenames: new Set(lowerList(merged.ignoreFilenames, DEFAULT_SCANNER.ignoreFilenames)),
    ignoreExtensions: new Set(lowerList(merged.ignoreExtensions, DEFAULT_SCANNER.ignoreExtensions).map((ext) => (
      ext.startsWith('.') ? ext : `.${ext}`
    ))),
    maxFileBytes: Number.isFinite(maxFileBytes) && maxFileBytes > 0 ? maxFileBytes : DEFAULT_SCANNER.maxFileBytes,
  };
}

function boundedNumber(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function sensorPolicy(input = {}) {
  const defaults = policyEngine.DEFAULT_POLICY;
  const merged = { ...defaults, ...(input || {}) };
  return {
    enforcementMode: ['block', 'warn', 'justify', 'redact'].includes(merged.enforcementMode) ? merged.enforcementMode : defaults.enforcementMode,
    blockMinSeverity: boundedNumber(merged.blockMinSeverity, defaults.blockMinSeverity, 1, 4),
    blockRiskScore: boundedNumber(merged.blockRiskScore, defaults.blockRiskScore, 0, 100),
    alwaysBlock: detectorList(merged.alwaysBlock, defaults.alwaysBlock),
    ignore: detectorList(merged.ignore, defaults.ignore),
    disabledDetectors: detectorList(merged.disabledDetectors, defaults.disabledDetectors),
    allowedDestinations: lowerList(merged.allowedDestinations, defaults.allowedDestinations),
    blockedDestinations: lowerList(merged.blockedDestinations, defaults.blockedDestinations),
    blockedFileUploadDestinations: lowerList(merged.blockedFileUploadDestinations, defaults.blockedFileUploadDestinations),
    scanner: scannerConfig(merged.scanner || DEFAULT_SCANNER),
  };
}

function ignoredByScanner(file, scanner) {
  const lower = String(file || '').toLowerCase();
  const parts = lower.split(/[\\/]+/).filter(Boolean);
  if (isRedactionHandoffPath(lower)) return true;
  if (parts.some((part) => scanner.ignoreDirectories.has(part))) return true;
  if (scanner.ignoreFilenames.has(path.basename(lower))) return true;
  return scanner.ignoreExtensions.has(path.extname(lower));
}

function isRedactionHandoffPath(file) {
  const lower = String(file || '').toLowerCase();
  const parts = lower.split(/[\\/]+/).filter(Boolean);
  const base = path.basename(lower);
  return parts.includes(REDACTION_HANDOFF_DIR)
    || parts.includes(LEGACY_REDACTION_HANDOFF_DIR)
    || base.endsWith(REDACTION_HANDOFF_SUFFIX)
    || base.endsWith(LEGACY_REDACTION_HANDOFF_SUFFIX);
}

function fileMode(analysis, pol = policyState) {
  const hardStop = (analysis.findings || []).some((f) => pol.alwaysBlock.includes(f.type));
  if (pol.enforcementMode === 'redact') return 'redact';
  return hardStop ? 'block' : (pol.enforcementMode || 'block');
}

function canTokenizeAllSensitivity(analysis) {
  return !!(analysis && (analysis.findings || []).length && !(analysis.categories || []).length);
}

function publicFindings(analysis) {
  return (analysis.findings || []).map((f) => ({
    type: f.type,
    severity: f.severity,
    score: f.score,
    masked: D.maskValue(f.type, f.value),
  }));
}

function publicCategories(analysis) {
  return (analysis.categories || []).map((c) => ({ category: c.category, score: c.score }));
}

function sensitivityLabels(analysis) {
  return [...new Set((analysis.findings || []).map((f) => f.type).concat((analysis.categories || []).map((c) => c.category)))];
}

function safeFileLabel(file) {
  const base = path.basename(String(file || 'file')).replace(/[\r\n\t]/g, ' ').slice(0, 128).trim() || 'file';
  const analysis = D.analyze(base);
  return sensitivityLabels(analysis).length ? '[sensitive filename]' : base;
}

function safeCompanionName(file) {
  const label = safeFileLabel(file);
  if (label === '[sensitive filename]') {
    return `redacted-${crypto.randomBytes(6).toString('hex')}${REDACTION_HANDOFF_SUFFIX}`;
  }
  const stem = path.parse(label).name
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'file';
  return `${stem}${REDACTION_HANDOFF_SUFFIX}`;
}

function uniqueCompanionPath(dir, baseName) {
  const parsed = path.parse(baseName);
  for (let i = 0; i < 100; i += 1) {
    const suffix = i ? `-${i + 1}` : '';
    const candidate = path.join(dir, `${parsed.name}${suffix}${parsed.ext}`);
    if (!fs.existsSync(candidate)) return candidate;
  }
  return path.join(dir, `${parsed.name}-${crypto.randomBytes(4).toString('hex')}${parsed.ext}`);
}

function sensorMetadata() {
  return { name: 'endpoint_agent', version: VERSION, platform: process.platform };
}

async function fetchPolicy(opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return null;
  const server = opts.server || SERVER;
  const key = configuredKey(opts);
  if (!key) return null;
  try {
    const r = await fetchWithTimeout(fetchImpl, server + '/api/v1/policy', {
      headers: { 'x-api-key': key },
    }, opts);
    if (!r || !r.ok) return null;
    return r.json();
  } catch (e) {
    if (!opts.silent) console.error('  policy refresh failed:', e.message);
    return null;
  }
}

async function refreshPolicy(opts = {}) {
  const pol = await fetchPolicy(opts);
  if (pol) {
    policyState = sensorPolicy(pol);
    scannerState = policyState.scanner;
  }
  return scannerState;
}

function requestTimeoutMs(opts = {}) {
  const n = Number(opts.timeoutMs ?? process.env.SENTINEL_REQUEST_TIMEOUT_MS ?? DEFAULT_REQUEST_TIMEOUT_MS);
  if (!Number.isFinite(n)) return DEFAULT_REQUEST_TIMEOUT_MS;
  return Math.max(50, Math.min(120000, n));
}

async function fetchWithTimeout(fetchImpl, url, options, opts = {}) {
  const timeout = requestTimeoutMs(opts);
  if (!globalThis.AbortController) return fetchImpl(url, options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetchImpl(url, { ...options, signal: controller.signal });
  } catch (e) {
    if (e && e.name === 'AbortError') e.code = 'SENTINEL_TIMEOUT';
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function postJson(apiPath, body, opts = {}) {
  const server = opts.server || SERVER;
  const key = configuredKey(opts);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return null;
  if (!key) return null;
  try {
    const r = await fetchWithTimeout(fetchImpl, server + apiPath, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': key }, body: JSON.stringify(body),
    }, opts);
    const parsed = await r.json().catch(() => null);
    if (!r.ok) return null;
    return parsed;
  } catch (e) { console.error('  report failed:', e.message); return null; }
}

async function report(rec, opts = {}) {
  return postJson('/api/v1/gate', rec, opts);
}

function unscannedFileEvent(filename, user, outcome, note, opts = {}) {
  return {
    prompt: '[file blocked unscanned] ' + safeFileLabel(filename),
    user, destination: opts.destination || 'desktop-ai-app', source: 'endpoint_agent', channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: outcome,
    note,
  };
}

function destinationBlockedEvent(user, opts = {}) {
  const destination = opts.destination || 'desktop-ai-app';
  return {
    prompt: '[destination blocked] ' + policyEngine.normalizeDestination(destination),
    user,
    destination,
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: 'destination_blocked',
    note: 'blocked locally: destination blocked by policy',
  };
}

async function blockDestinationFile(file, user, opts = {}) {
  console.log(`[BLOCK] ${safeFileLabel(file)} destination blocked by policy`);
  await (opts.report || report)(destinationBlockedEvent(user, opts), opts);
  return { decision: 'block', status: 'destination_blocked', supported: true, inspected: false };
}

function fileUploadBlockedEvent(user, opts = {}) {
  const destination = opts.destination || 'desktop-ai-app';
  return {
    prompt: '[file upload blocked] ' + policyEngine.normalizeDestination(destination),
    user,
    destination,
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: 'file_upload_blocked',
    note: 'blocked locally: file upload blocked by policy',
  };
}

async function blockFileUpload(file, user, opts = {}) {
  console.log(`[BLOCK] ${safeFileLabel(file)} file upload blocked by policy`);
  await (opts.report || report)(fileUploadBlockedEvent(user, opts), opts);
  return { decision: 'block', status: 'file_upload_blocked', supported: true, inspected: false };
}

async function blockScanUnavailable(file, user, opts = {}) {
  const label = safeFileLabel(file);
  console.log(`[BLOCK] ${label} could not be recorded by PromptWall`);
  await (opts.report || report)(unscannedFileEvent(
    file,
    user,
    'scan_unavailable',
    'blocked locally: control plane decision logging unavailable',
    opts,
  ), opts);
  return { decision: 'block', status: 'scan_unavailable', supported: true };
}

function localFileRecord(file, user, safePrompt, analysis, outcome, note, opts = {}) {
  const label = safeFileLabel(file);
  const base = {
    prompt: String(safePrompt || '').slice(0, 1000),
    user,
    destination: opts.destination || 'desktop-ai-app',
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: outcome || undefined,
    note: note || `endpoint agent inspected ${label} locally`,
  };
  if (!sensitivityLabels(analysis).length) return base;
  return {
    ...base,
    clientPreRedacted: true,
    clientFindings: publicFindings(analysis),
    clientCategories: publicCategories(analysis),
    clientEntityCounts: analysis.entityCounts || {},
    clientRiskScore: analysis.riskScore || 0,
    clientMaxSeverity: analysis.maxSeverity || 0,
    clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
  };
}

function safeFilePrompt(file, text, analysis, mode) {
  const label = safeFileLabel(file);
  const labels = sensitivityLabels(analysis);
  const prefix = `[file:${label}] `;
  if (!labels.length) return `[file inspected locally] ${label}`;
  if ((analysis.categories || []).length) return prefix + '[REDACTED: ' + labels.join(', ') + ']';
  if (mode === 'redact' && canTokenizeAllSensitivity(analysis)) {
    return prefix + Object.keys(D.tokenize(text, analysis.findings).map).join(' ');
  }
  return prefix + '[REDACTED: ' + labels.join(', ') + ']';
}

function hasRawFindingValue(text, findings) {
  return (findings || []).some((f) => f && f.value && String(text).includes(f.value));
}

function writeRedactionHandoff(file, text, analysis, opts = {}) {
  if (!canTokenizeAllSensitivity(analysis)) return null;
  const tokenized = D.tokenize(text || '', analysis.findings || []);
  const label = safeFileLabel(file);
  const body = [
    'PromptWall redacted companion file',
    `Original file: ${label}`,
    `Generated: ${new Date().toISOString()}`,
    '',
    tokenized.text,
    '',
  ].join('\n');
  if (hasRawFindingValue(body, analysis.findings)) {
    throw new Error('redaction handoff still contains a detected value');
  }
  const root = path.resolve(opts.watchDir || WATCH);
  const dir = path.join(root, REDACTION_HANDOFF_DIR);
  fs.mkdirSync(dir, { recursive: true });
  const fullPath = uniqueCompanionPath(dir, safeCompanionName(file));
  fs.writeFileSync(fullPath, body, { encoding: 'utf8', flag: 'wx' });
  return {
    path: fullPath,
    relativePath: path.relative(root, fullPath),
    tokenCount: tokenized.tokens,
    bytes: Buffer.byteLength(body, 'utf8'),
  };
}

function removeRedactionHandoff(handoff) {
  if (!handoff || !handoff.path) return;
  try { fs.rmSync(handoff.path, { force: true }); } catch {}
}

function prepareRedactionHandoff(file, text, analysis, mode, opts = {}) {
  if (mode !== 'redact' || !canTokenizeAllSensitivity(analysis)) {
    return { handoff: null, handoffError: null, outcome: null };
  }
  try {
    const handoff = writeRedactionHandoff(file, text, analysis, opts);
    return { handoff, handoffError: null, outcome: handoff ? 'redacted_available' : 'awaiting_approval' };
  } catch (e) {
    return { handoff: null, handoffError: e, outcome: 'awaiting_approval' };
  }
}

function handoffNote(handoff, handoffError) {
  if (handoff) return `; redacted companion ${handoff.relativePath}`;
  return handoffError ? '; redacted companion unavailable' : '';
}

function localFileResponse(res, analysis, handoff) {
  const keptHandoff = handoff && (res.status === 'redacted' || res.decision === 'redact');
  if (handoff && !keptHandoff) removeRedactionHandoff(handoff);
  return {
    ...res,
    inspectedLocally: true,
    localAnalysis: analysis,
    ...(keptHandoff ? { redactionHandoff: handoff } : {}),
  };
}

async function reportLocalFile(file, user, extracted, opts = {}) {
  const pol = opts.policy ? sensorPolicy(opts.policy) : policyState;
  const analysis = D.analyze(extracted.text || '', { ignore: pol.ignore, disabledDetectors: pol.disabledDetectors });
  const verdict = policyEngine.evaluate(analysis, pol);
  if (verdict.decision === 'allow') {
    const res = await (opts.report || report)(localFileRecord(file, user, safeFilePrompt(file, '', analysis), analysis, 'allowed', undefined, opts), opts);
    if (res) return { ...res, inspectedLocally: true, localAnalysis: analysis };
    return { ...(await blockScanUnavailable(file, user, opts)), inspectedLocally: true, localAnalysis: analysis };
  }
  const mode = fileMode(analysis, pol);
  const { handoff, handoffError, outcome } = prepareRedactionHandoff(file, extracted.text || '', analysis, mode, opts);
  const safePrompt = safeFilePrompt(file, extracted.text || '', analysis, mode);
  const handoffSource = opts.nativeHandoff && opts.nativeHandoff.id ? `; native handoff ${opts.nativeHandoff.id}` : '';
  const note = `endpoint agent inspected ${safeFileLabel(file)} locally: ${verdict.reasons.join('; ')}` +
    handoffNote(handoff, handoffError) + handoffSource;
  const res = await (opts.report || report)(localFileRecord(file, user, safePrompt, analysis, outcome, note, opts), opts);
  if (res) return localFileResponse(res, analysis, handoff);
  removeRedactionHandoff(handoff);
  return { ...(await blockScanUnavailable(file, user, opts)), inspectedLocally: true, localAnalysis: analysis };
}

function decisionSummary(res) {
  const localLabels = sensitivityLabels(res.localAnalysis || {});
  const responseLabels = (res.findings || []).map((f) => f.type).concat(
    (res.categories || []).map((c) => (typeof c === 'string' ? c : c.category))
  );
  return {
    labels: localLabels.length ? localLabels : responseLabels.filter(Boolean),
    riskScore: res.riskScore ?? (res.localAnalysis && res.localAnalysis.riskScore),
  };
}

async function scanResolvedFile(file, full, root, opts = {}) {
  const pol = opts.policy ? sensorPolicy(opts.policy) : policyState;
  const scanner = opts.scanner ? scannerConfig(opts.scanner) : pol.scanner || scannerState;
  const maxBytes = opts.maxBytes || scanner.maxFileBytes;
  const label = safeFileLabel(file);
  let stat; try { stat = fs.statSync(full); } catch { return; }
  if (!stat.isFile()) return;
  if (ignoredByScanner(file, scanner)) return;
  const user = opts.user || os.userInfo().username;
  if (policyEngine.destinationBlocked(opts.destination || 'desktop-ai-app', pol)) {
    return blockDestinationFile(file, user, opts);
  }
  if (policyEngine.fileUploadBlocked(opts.destination || 'desktop-ai-app', pol)) {
    return blockFileUpload(file, user, opts);
  }

  if (stat.size > maxBytes) {
    console.log(`[BLOCK] ${label} is too large to inspect`);
    await (opts.report || report)(unscannedFileEvent(file, user, 'file_too_large', 'blocked locally: file too large to inspect', opts), opts);
    return { decision: 'block', status: 'file_too_large' };
  }
  if (!processors.supported(file)) {
    console.log(`[BLOCK] ${label} is unsupported and was not uploaded for scanning`);
    await (opts.report || report)(unscannedFileEvent(file, user, 'file_unsupported', 'blocked locally: unsupported file type', opts), opts);
    return { decision: 'block', status: 'file_unsupported', supported: false };
  }
  const buf = fs.readFileSync(full);
  const extracted = await processors.extractText(file, buf, opts.extract || {});
  if (!extracted.extractionOk) {
    console.log(`[BLOCK] ${label} could not be inspected locally`);
    await (opts.report || report)(unscannedFileEvent(file, user, 'scan_unavailable', `blocked locally: ${extracted.error || 'extract_failed'}`, opts), opts);
    return { decision: 'block', status: 'scan_unavailable', supported: true, inspected: false };
  }
  const res = await reportLocalFile(file, user, extracted, { ...opts, policy: pol, watchDir: opts.redactionRoot || opts.watchDir || root });
  if (res.decision === 'allow') {
    console.log(`[ok]   ${label} -- clean`);
    return res;
  }
  if (res.decision === 'redact' && res.redactionHandoff) {
    console.log(`[ok]   ${label} -> redacted companion ${res.redactionHandoff.relativePath}`);
    return res;
  }
  const summary = decisionSummary(res);
  console.log(`[FLAG] ${label} -> ${summary.labels.join(', ') || 'sensitive content'} (risk ${summary.riskScore ?? 'unknown'})`);
  if (res && res.decision === 'block') console.log(`        held by policy (${res.mode || 'local'}) -> ${res.id || 'unrecorded'}`);
  return res;
}

async function scanFile(file, opts = {}) {
  const watchDir = opts.watchDir || WATCH;
  const root = path.resolve(watchDir);
  const full = path.resolve(root, file);
  if (full !== root && !full.startsWith(root + path.sep)) return;
  return scanResolvedFile(file, full, root, opts);
}

async function scanAbsoluteFile(filePath, opts = {}) {
  const full = path.resolve(String(filePath || ''));
  const root = path.dirname(full);
  return scanResolvedFile(path.basename(full), full, root, opts);
}

function removeHandoffEventFile(file, opts = {}) {
  try {
    fs.rmSync(file, { force: true });
  } catch {
    if (!opts.silent) console.error('  native handoff cleanup failed');
  }
}

async function processNativeHandoffFile(file, opts = {}) {
  let event;
  try {
    event = nativeHandoff.readHandoffFile(file, opts);
  } catch (e) {
    if (!opts.silent) console.error('  native handoff rejected:', e.message);
    if (opts.removeRejected) removeHandoffEventFile(file, opts);
    return { status: 'rejected', reason: e.message };
  }
  const result = await scanAbsoluteFile(event.filePath, {
    ...opts,
    user: event.user || opts.user,
    destination: nativeHandoff.publicDestination(event.destination),
    nativeHandoff: event,
    redactionRoot: opts.redactionRoot || path.dirname(file),
  });
  if (!opts.keepHandoffFile) removeHandoffEventFile(file, opts);
  return { status: 'processed', event, result };
}

function processNativeHandoffFileSafe(file, opts = {}) {
  Promise.resolve(processNativeHandoffFile(file, opts)).catch((e) => {
    if (!opts.silent) console.error('  native handoff failed:', e.message);
  });
}

function processHandoffDirectory(dir = HANDOFF_DIR, opts = {}) {
  if (!handoffSecretReady(nativeHandoff.configuredHandoffSecret(opts))) return;
  fs.mkdirSync(dir, { recursive: true });
  for (const entry of fs.readdirSync(dir)) {
    if (entry.toLowerCase().endsWith('.json')) processNativeHandoffFileSafe(path.join(dir, entry), { ...opts, silent: true });
  }
  return fs.watch(dir, (event, filename) => {
    if (filename && event === 'rename' && filename.toLowerCase().endsWith('.json')) {
      const handoffFile = path.join(dir, filename);
      setTimeout(() => {
        if (fs.existsSync(handoffFile)) processNativeHandoffFileSafe(handoffFile, opts);
      }, HANDOFF_RETRY_DELAY_MS);
    }
  });
}

function start() {
  console.log('PromptWall endpoint agent');
  console.log('  watching:', WATCH);
  console.log('  native handoff:', handoffSecretReady(HANDOFF_SECRET) ? HANDOFF_DIR : 'disabled (set 32+ char ENDPOINT_AGENT_HANDOFF_SECRET)');
  console.log('  server  :', SERVER);
  console.log('  ingest  :', KEY ? 'configured' : 'not configured (control-plane calls disabled)');
  console.log('  Supported: pdf, docx, xlsx, pptx, and text files. Drop a file in to scan.\n');

  refreshPolicy({ silent: true }).finally(() => {
    for (const f of fs.readdirSync(WATCH)) scanFile(f);
  });
  const refreshTimer = setInterval(() => refreshPolicy({ silent: true }), POLICY_REFRESH_MS);
  if (refreshTimer.unref) refreshTimer.unref();
  fs.watch(WATCH, (event, filename) => { if (filename && event === 'rename') setTimeout(() => scanFile(filename), 200); });
  if (handoffSecretReady(HANDOFF_SECRET)) processHandoffDirectory(HANDOFF_DIR, { secret: HANDOFF_SECRET });
}

if (require.main === module) start();

module.exports = {
  scanFile,
  scanAbsoluteFile,
  processNativeHandoffFile,
  processNativeHandoffFileSafe,
  processHandoffDirectory,
  report,
  postJson,
  fetchPolicy,
  refreshPolicy,
  sensorPolicy,
  decisionSummary,
  scannerConfig,
  ignoredByScanner,
  publicFindings,
  publicCategories,
  safeFileLabel,
  requestTimeoutMs,
  fetchWithTimeout,
  defaultWatchDir,
  sensorMetadata,
  configuredKey,
  handoffSecretReady,
  nativeHandoff,
  start,
};
