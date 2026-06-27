'use strict';
require('../src/env').loadEnv();
/**
 * PromptSentinel endpoint agent (reference implementation).
 *
 * Catches sensitive FILES headed to desktop AI apps that a browser extension
 * cannot see. Watches a folder, extracts and detects locally using the same
 * engine as the other sensors, then reports sanitized evidence to the control
 * plane. Respects scanner ignore-lists.
 *
 * Usage: node agent.js [watchDir]
 *   SENTINEL_URL (default http://localhost:4000), INGEST_API_KEY (required for control-plane calls)
 *   ENDPOINT_AGENT_WATCH_DIR (default OS temp promptsentinel-watch)
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const processors = require('../src/processors');
const policyEngine = require('../src/policy');
const D = require('../shared/detect');
const VERSION = require('../package.json').version;

const SERVER = process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || '';
function defaultWatchDir(argv = process.argv, env = process.env) {
  return argv[2] || env.ENDPOINT_AGENT_WATCH_DIR || path.join(os.tmpdir(), 'promptsentinel-watch');
}
const WATCH = defaultWatchDir();

const DEFAULT_SCANNER = {
  ignoreDirectories: ['node_modules', '.git', 'Library', 'Applications', 'AppData'],
  ignoreFilenames: ['thumbs.db', '.ds_store', 'package.json', 'package-lock.json'],
  ignoreExtensions: ['.tmp', '.log', '.lock'],
  maxFileBytes: 6.3 * 1024 * 1024,
};
const POLICY_REFRESH_MS = 15 * 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;
let scannerState = scannerConfig(DEFAULT_SCANNER);
let policyState = sensorPolicy(policyEngine.DEFAULT_POLICY);

if (!fs.existsSync(WATCH)) fs.mkdirSync(WATCH, { recursive: true });

function configuredKey(opts = {}) {
  const value = Object.prototype.hasOwnProperty.call(opts, 'key') ? opts.key : KEY;
  return typeof value === 'string' ? value.trim() : '';
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
    scanner: scannerConfig(merged.scanner || DEFAULT_SCANNER),
  };
}

function ignoredByScanner(file, scanner) {
  const lower = String(file || '').toLowerCase();
  const parts = lower.split(/[\\/]+/).filter(Boolean);
  if (parts.some((part) => scanner.ignoreDirectories.has(part))) return true;
  if (scanner.ignoreFilenames.has(path.basename(lower))) return true;
  return scanner.ignoreExtensions.has(path.extname(lower));
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

function unscannedFileEvent(filename, user, outcome, note) {
  return {
    prompt: '[file blocked unscanned] ' + safeFileLabel(filename),
    user, destination: 'desktop-ai-app', source: 'endpoint_agent', channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: outcome,
    note,
  };
}

async function blockScanUnavailable(file, user, opts = {}) {
  const label = safeFileLabel(file);
  console.log(`[BLOCK] ${label} could not be recorded by PromptSentinel`);
  await (opts.report || report)(unscannedFileEvent(
    file,
    user,
    'scan_unavailable',
    'blocked locally: control plane decision logging unavailable',
  ), opts);
  return { decision: 'block', status: 'scan_unavailable', supported: true };
}

function localFileRecord(file, user, safePrompt, analysis, outcome, note) {
  const label = safeFileLabel(file);
  const base = {
    prompt: String(safePrompt || '').slice(0, 1000),
    user,
    destination: 'desktop-ai-app',
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

async function reportLocalFile(file, user, extracted, opts = {}) {
  const pol = opts.policy ? sensorPolicy(opts.policy) : policyState;
  const analysis = D.analyze(extracted.text || '', { ignore: pol.ignore, disabledDetectors: pol.disabledDetectors });
  const verdict = policyEngine.evaluate(analysis, pol);
  if (verdict.decision === 'allow') {
    const res = await (opts.report || report)(localFileRecord(file, user, safeFilePrompt(file, '', analysis), analysis, 'allowed'), opts);
    if (res) return { ...res, inspectedLocally: true, localAnalysis: analysis };
    return { ...(await blockScanUnavailable(file, user, opts)), inspectedLocally: true, localAnalysis: analysis };
  }
  const mode = fileMode(analysis, pol);
  const outcome = mode === 'redact' && canTokenizeAllSensitivity(analysis) ? 'redacted_sent' : null;
  const safePrompt = safeFilePrompt(file, extracted.text || '', analysis, mode);
  const note = `endpoint agent inspected ${safeFileLabel(file)} locally: ${verdict.reasons.join('; ')}`;
  const res = await (opts.report || report)(localFileRecord(file, user, safePrompt, analysis, outcome, note), opts);
  if (res) return { ...res, inspectedLocally: true, localAnalysis: analysis };
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

async function scanFile(file, opts = {}) {
  const watchDir = opts.watchDir || WATCH;
  const pol = opts.policy ? sensorPolicy(opts.policy) : policyState;
  const scanner = opts.scanner ? scannerConfig(opts.scanner) : pol.scanner || scannerState;
  const maxBytes = opts.maxBytes || scanner.maxFileBytes;
  const label = safeFileLabel(file);
  const root = path.resolve(watchDir);
  const full = path.resolve(root, file);
  if (full !== root && !full.startsWith(root + path.sep)) return;
  let stat; try { stat = fs.statSync(full); } catch { return; }
  if (!stat.isFile()) return;
  if (ignoredByScanner(file, scanner)) return;
  const user = opts.user || os.userInfo().username;

  if (stat.size > maxBytes) {
    console.log(`[BLOCK] ${label} is too large to inspect`);
    await (opts.report || report)(unscannedFileEvent(file, user, 'file_too_large', 'blocked locally: file too large to inspect'), opts);
    return { decision: 'block', status: 'file_too_large' };
  }
  if (!processors.supported(file)) {
    console.log(`[BLOCK] ${label} is unsupported and was not uploaded for scanning`);
    await (opts.report || report)(unscannedFileEvent(file, user, 'file_unsupported', 'blocked locally: unsupported file type'), opts);
    return { decision: 'block', status: 'file_unsupported', supported: false };
  }
  const buf = fs.readFileSync(full);
  const extracted = await processors.extractText(file, buf, opts.extract || {});
  if (!extracted.extractionOk) {
    console.log(`[BLOCK] ${label} could not be inspected locally`);
    await (opts.report || report)(unscannedFileEvent(file, user, 'scan_unavailable', `blocked locally: ${extracted.error || 'extract_failed'}`), opts);
    return { decision: 'block', status: 'scan_unavailable', supported: true, inspected: false };
  }
  const res = await reportLocalFile(file, user, extracted, { ...opts, policy: pol });
  if (res.decision === 'allow') {
    console.log(`[ok]   ${label} -- clean`);
    return res;
  }
  const summary = decisionSummary(res);
  console.log(`[FLAG] ${label} -> ${summary.labels.join(', ') || 'sensitive content'} (risk ${summary.riskScore ?? 'unknown'})`);
  if (res && res.decision === 'block') console.log(`        held by policy (${res.mode || 'local'}) -> ${res.id || 'unrecorded'}`);
  return res;
}

function start() {
  console.log('PromptSentinel endpoint agent');
  console.log('  watching:', WATCH);
  console.log('  server  :', SERVER);
  console.log('  ingest  :', KEY ? 'configured' : 'not configured (control-plane calls disabled)');
  console.log('  Supported: pdf, docx, xlsx, pptx, and text files. Drop a file in to scan.\n');

  refreshPolicy({ silent: true }).finally(() => {
    for (const f of fs.readdirSync(WATCH)) scanFile(f);
  });
  const refreshTimer = setInterval(() => refreshPolicy({ silent: true }), POLICY_REFRESH_MS);
  if (refreshTimer.unref) refreshTimer.unref();
  fs.watch(WATCH, (event, filename) => { if (filename && event === 'rename') setTimeout(() => scanFile(filename), 200); });
}

if (require.main === module) start();

module.exports = {
  scanFile,
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
  start,
};
