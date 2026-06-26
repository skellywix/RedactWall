'use strict';
require('../src/env').loadEnv();
/**
 * PromptSentinel endpoint agent (reference implementation).
 *
 * Catches sensitive FILES headed to desktop AI apps that a browser extension
 * cannot see. Watches a folder and scans any file written to it using the shared
 * file-processor layer (pdf / docx / xlsx / text) + detection engine, then
 * reports verdicts to the control plane. Respects scanner ignore-lists.
 *
 * Usage: node agent.js [watchDir]
 *   SENTINEL_URL (default http://localhost:4000), INGEST_API_KEY (default dev-ingest-key)
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const processors = require('../src/processors');

const SERVER = process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';
const WATCH = process.argv[2] || path.join(os.tmpdir(), 'promptsentinel-watch');

const DEFAULT_SCANNER = {
  ignoreDirectories: ['node_modules', '.git', 'Library', 'Applications', 'AppData'],
  ignoreFilenames: ['thumbs.db', '.ds_store', 'package.json', 'package-lock.json'],
  ignoreExtensions: ['.tmp', '.log', '.lock'],
  maxFileBytes: 6.3 * 1024 * 1024,
};
const POLICY_REFRESH_MS = 15 * 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;
let scannerState = scannerConfig(DEFAULT_SCANNER);

if (!fs.existsSync(WATCH)) fs.mkdirSync(WATCH, { recursive: true });

function lowerList(value, fallback = []) {
  const src = Array.isArray(value) ? value : value instanceof Set ? Array.from(value) : fallback;
  return src
    .filter((item) => typeof item === 'string' && item.trim())
    .map((item) => item.trim().toLowerCase());
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

function ignoredByScanner(file, scanner) {
  const lower = String(file || '').toLowerCase();
  const parts = lower.split(/[\\/]+/).filter(Boolean);
  if (parts.some((part) => scanner.ignoreDirectories.has(part))) return true;
  if (scanner.ignoreFilenames.has(path.basename(lower))) return true;
  return scanner.ignoreExtensions.has(path.extname(lower));
}

async function fetchPolicy(opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return null;
  const server = opts.server || SERVER;
  const key = opts.key || KEY;
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
  if (pol && pol.scanner) scannerState = scannerConfig(pol.scanner);
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
  const key = opts.key || KEY;
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) return null;
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

async function scanFileApi(req, opts = {}) {
  return postJson('/api/v1/scan-file', req, opts);
}

function fileRequest(filename, buf, user) {
  return {
    filename,
    contentBase64: buf.toString('base64'),
    user,
    destination: 'desktop-ai-app',
    source: 'endpoint_agent',
    channel: 'file_upload',
  };
}

function unscannedFileEvent(filename, user, outcome, note) {
  return {
    prompt: '[file blocked unscanned] ' + filename,
    user, destination: 'desktop-ai-app', source: 'endpoint_agent', channel: 'file_upload',
    clientOutcome: outcome,
    note,
  };
}

async function blockScanUnavailable(file, user, opts = {}) {
  console.log(`[BLOCK] ${file} could not be sent to PromptSentinel for scanning`);
  await (opts.report || report)(unscannedFileEvent(
    file,
    user,
    'scan_unavailable',
    'blocked locally: control plane scan unavailable',
  ), opts);
  return { decision: 'block', status: 'scan_unavailable', supported: true };
}

async function scanFile(file, opts = {}) {
  const watchDir = opts.watchDir || WATCH;
  const scanner = opts.scanner ? scannerConfig(opts.scanner) : scannerState;
  const maxBytes = opts.maxBytes || scanner.maxFileBytes;
  const root = path.resolve(watchDir);
  const full = path.resolve(root, file);
  if (full !== root && !full.startsWith(root + path.sep)) return;
  let stat; try { stat = fs.statSync(full); } catch { return; }
  if (!stat.isFile()) return;
  if (ignoredByScanner(file, scanner)) return;
  const user = opts.user || os.userInfo().username;

  if (stat.size > maxBytes) {
    console.log(`[BLOCK] ${file} is too large to inspect`);
    await (opts.report || report)(unscannedFileEvent(file, user, 'file_too_large', 'blocked locally: file too large to inspect'), opts);
    return { decision: 'block', status: 'file_too_large' };
  }
  if (!processors.supported(file)) {
    console.log(`[BLOCK] ${file} is unsupported and was not uploaded for scanning`);
    await (opts.report || report)(unscannedFileEvent(file, user, 'file_unsupported', 'blocked locally: unsupported file type'), opts);
    return { decision: 'block', status: 'file_unsupported', supported: false };
  }
  const buf = fs.readFileSync(full);

  // The server path is authoritative for files. Sending a locally redacted
  // preview to /gate would make the control plane re-scan clean placeholder text
  // and lose the real finding.
  const res = await (opts.scanFileApi || scanFileApi)(fileRequest(file, buf, user), opts);
  if (!res || res.error || (!res.decision && res.supported !== false)) {
    return blockScanUnavailable(file, user, opts);
  }
  if (res.supported === false) {
    console.log(`[file] ${file} (unsupported) -> recorded`);
    return res;
  }
  if (res.inspected === false) {
    console.log(`[BLOCK] ${file} could not be inspected -> ${res.id || 'recorded'}`);
    return res;
  }
  if (res.decision === 'allow') {
    console.log(`[ok]   ${file} -- clean`);
    return res;
  }
  const summary = (res.findings || []).map((f) => f.type).concat(res.categories || []);
  console.log(`[FLAG] ${file} -> ${summary.join(', ')} (risk ${res.riskScore})`);
  if (res && res.decision === 'block') console.log(`        held by policy (${res.mode}) -> ${res.id}`);
  return res;
}

function start() {
  console.log('PromptSentinel endpoint agent');
  console.log('  watching:', WATCH);
  console.log('  server  :', SERVER);
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
  fileRequest,
  report,
  scanFileApi,
  postJson,
  fetchPolicy,
  refreshPolicy,
  scannerConfig,
  ignoredByScanner,
  requestTimeoutMs,
  fetchWithTimeout,
  start,
};
