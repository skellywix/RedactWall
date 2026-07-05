'use strict';
/**
 * Bundled WASM OCR fallback for the endpoint agent.
 *
 * When a workstation has no native `tesseract` binary, this module runs the
 * pure-WASM tesseract.js engine against the locally vendored language data.
 * Everything is hard-pinned to on-disk files: the default tesseract.js langPath
 * is a remote CDN, and a bank endpoint must never phone home for model weights.
 * If the optional dependency or the vendored `tessdata` is missing, OCR stays
 * unavailable and images remain `ocr_required` — we never fetch.
 */
const fs = require('fs');
const path = require('path');

const TESSDATA_DIR = path.join(__dirname, 'tessdata');
const IDLE_TERMINATE_MS = 60000;
const DEFAULT_TIMEOUT_MS = 30000;
const NOOP = () => {};

let moduleResolvable;
let sharedWorker = null;
let idleTimer = null;

function offSwitch(env) {
  const raw = env.ENDPOINT_AGENT_OCR_WASM ?? env.REDACTWALL_ENDPOINT_AGENT_OCR_WASM ?? env.PROMPTWALL_ENDPOINT_AGENT_OCR_WASM ?? 'on';
  return /^(0|off|false|no|disabled)$/i.test(String(raw).trim());
}

function tessdataFilePath(opts = {}) {
  return opts.tessdataPath || path.join(opts.langPath || TESSDATA_DIR, 'eng.traineddata.gz');
}

function boundedTimeout(opts = {}) {
  const env = opts.env || process.env;
  const raw = Number(opts.timeoutMs || env.ENDPOINT_AGENT_OCR_TIMEOUT_MS || env.REDACTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS);
  if (!Number.isFinite(raw)) return DEFAULT_TIMEOUT_MS;
  return Math.max(1000, Math.min(120000, Math.floor(raw)));
}

function wasmOcrAvailable(opts = {}) {
  const env = opts.env || process.env;
  if (offSwitch(env)) return false;
  const resolve = opts.resolve || require.resolve;
  if (moduleResolvable === undefined || opts.fresh) {
    try { resolve('tesseract.js'); moduleResolvable = true; } catch { moduleResolvable = false; }
  }
  if (!moduleResolvable) return false;
  const statSync = opts.statSync || fs.statSync;
  try { return statSync(tessdataFilePath(opts)).isFile(); } catch { return false; }
}

function scheduleIdleTerminate() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { terminateWasmOcr().catch(NOOP); }, IDLE_TERMINATE_MS);
  if (idleTimer.unref) idleTimer.unref();
}

async function terminateWasmOcr() {
  const worker = sharedWorker;
  sharedWorker = null;
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  if (worker) { try { await worker.terminate(); } catch { /* already gone */ } }
}

function resetWasmOcr() {
  moduleResolvable = undefined;
  return terminateWasmOcr();
}

async function getWorker(opts = {}) {
  if (sharedWorker) return sharedWorker;
  const createWorker = (opts.tesseract || require('tesseract.js')).createWorker;
  const resolve = opts.resolve || require.resolve;
  sharedWorker = await createWorker('eng', 1, {
    langPath: opts.langPath || TESSDATA_DIR,
    corePath: opts.corePath || path.dirname(resolve('tesseract.js-core/package.json')),
    workerPath: opts.workerPath || resolve('tesseract.js/src/worker-script/node/index.js'),
    gzip: true,
    cacheMethod: 'none',
    logger: NOOP,
    errorHandler: NOOP,
  });
  return sharedWorker;
}

async function extractImageTextWasm(filePath, opts = {}) {
  const worker = await getWorker(opts);
  const timeoutMs = boundedTimeout(opts);
  let timer;
  // Kept ref'd on purpose: during a wedged recognition we want the timeout to
  // fire and terminate the worker, not let the process quietly exit around it.
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('ocr_timeout')), timeoutMs);
  });
  try {
    const { data } = await Promise.race([worker.recognize(filePath), timeout]);
    clearTimeout(timer);
    scheduleIdleTerminate();
    return String((data && data.text) || '');
  } catch (err) {
    clearTimeout(timer);
    // A timed-out or errored worker may be wedged — drop it so the next call is clean.
    await terminateWasmOcr();
    throw err;
  }
}

module.exports = {
  TESSDATA_DIR,
  wasmOcrAvailable,
  extractImageTextWasm,
  resetWasmOcr,
  terminateWasmOcr,
  tessdataFilePath,
};
