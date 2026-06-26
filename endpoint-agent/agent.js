'use strict';
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

const IGNORE_FILES = new Set(['thumbs.db', '.ds_store', 'package.json', 'package-lock.json']);
const IGNORE_EXT = new Set(['.tmp', '.log', '.lock']);
const MAX_BYTES = 6.3 * 1024 * 1024;

if (!fs.existsSync(WATCH)) fs.mkdirSync(WATCH, { recursive: true });

async function postJson(apiPath, body, opts = {}) {
  const server = opts.server || SERVER;
  const key = opts.key || KEY;
  try {
    const r = await fetch(server + apiPath, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': key }, body: JSON.stringify(body),
    });
    return r.json();
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

async function scanFile(file, opts = {}) {
  const watchDir = opts.watchDir || WATCH;
  const maxBytes = opts.maxBytes || MAX_BYTES;
  const full = path.join(watchDir, file);
  let stat; try { stat = fs.statSync(full); } catch { return; }
  if (!stat.isFile()) return;
  const lower = file.toLowerCase();
  if (IGNORE_FILES.has(lower) || IGNORE_EXT.has(path.extname(lower))) return;
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
  if (!res) return null;
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

  fs.watch(WATCH, (event, filename) => { if (filename && event === 'rename') setTimeout(() => scanFile(filename), 200); });
  for (const f of fs.readdirSync(WATCH)) scanFile(f);
}

if (require.main === module) start();

module.exports = { scanFile, fileRequest, report, scanFileApi, postJson, start };
