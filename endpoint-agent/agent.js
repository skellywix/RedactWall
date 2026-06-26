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
const D = require('../shared/detect');
const processors = require('../src/processors');

const SERVER = process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';
const WATCH = process.argv[2] || path.join(os.tmpdir(), 'promptsentinel-watch');

const IGNORE_FILES = new Set(['thumbs.db', '.ds_store', 'package.json', 'package-lock.json']);
const IGNORE_EXT = new Set(['.tmp', '.log', '.lock']);
const MAX_BYTES = 6.3 * 1024 * 1024;

if (!fs.existsSync(WATCH)) fs.mkdirSync(WATCH, { recursive: true });

async function report(rec) {
  try {
    const r = await fetch(SERVER + '/api/v1/gate', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': KEY }, body: JSON.stringify(rec),
    });
    return r.json();
  } catch (e) { console.error('  report failed:', e.message); return null; }
}

async function scanFile(file) {
  const full = path.join(WATCH, file);
  let stat; try { stat = fs.statSync(full); } catch { return; }
  if (!stat.isFile()) return;
  const lower = file.toLowerCase();
  if (IGNORE_FILES.has(lower) || IGNORE_EXT.has(path.extname(lower))) return;
  const user = os.userInfo().username;

  if (stat.size > MAX_BYTES || !processors.supported(file)) {
    console.log(`[file] ${file} (unsupported/large) -> recorded`);
    await report({ prompt: '[file] ' + file, user, destination: 'desktop-ai-app', source: 'endpoint_agent', channel: 'file_upload' });
    return;
  }
  const buf = fs.readFileSync(full);
  let text = '';
  try { ({ text } = await processors.extractText(file, buf)); } catch {}
  const a = D.analyze(text);
  if (!a.findings.length && !a.categories.length) { console.log(`[ok]   ${file} -- clean`); return; }
  const summary = [...new Set(a.findings.map((f) => f.type).concat(a.categories.map((c) => c.category)))];
  console.log(`[FLAG] ${file} -> ${summary.join(', ')} (risk ${a.riskScore})`);
  const res = await report({
    prompt: '[file:' + file + '] ' + D.redact(text, a.findings).slice(0, 800),
    user, destination: 'desktop-ai-app', source: 'endpoint_agent', channel: 'file_upload',
  });
  if (res && res.decision === 'block') console.log(`        held by policy (${res.mode}) -> ${res.id}`);
}

console.log('PromptSentinel endpoint agent');
console.log('  watching:', WATCH);
console.log('  server  :', SERVER);
console.log('  Supported: pdf, docx, xlsx, pptx, and text files. Drop a file in to scan.\n');

fs.watch(WATCH, (event, filename) => { if (filename && event === 'rename') setTimeout(() => scanFile(filename), 200); });
for (const f of fs.readdirSync(WATCH)) scanFile(f);
