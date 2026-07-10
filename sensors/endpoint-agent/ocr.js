'use strict';
/**
 * Optional endpoint-local OCR bridge.
 *
 * This is endpoint-only on purpose: the control plane still treats images as
 * ocr_required unless a workstation has a local OCR command configured.
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const processors = require('../../server/processors');

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_CHARS = 1000000;
const MAX_BUFFER_BYTES = 4 * 1024 * 1024;

let discoveredCommandCache;

function configured(value) {
  return value != null && String(value).trim() !== '';
}

function boundedPositiveInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function isImageFile(name) {
  return processors.IMAGE_EXT.has(path.extname(String(name || '')).toLowerCase());
}

function parseArgsJson(value) {
  if (!configured(value)) return null;
  let parsed;
  try {
    parsed = JSON.parse(String(value));
  } catch {
    throw new Error('OCR args must be a JSON array of strings');
  }
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== 'string')) {
    throw new Error('OCR args must be a JSON array of strings');
  }
  if (parsed.length > 40 || parsed.some((item) => item.length > 1000)) {
    throw new Error('OCR args are too large');
  }
  return parsed;
}

function tesseractCandidates(env, platform) {
  const name = platform === 'win32' ? 'tesseract.exe' : 'tesseract';
  const fromPath = String(env.PATH || env.Path || '')
    .split(path.delimiter)
    .filter(Boolean)
    .map((dir) => path.join(dir, name));
  const wellKnown = platform === 'win32'
    ? [
      path.join(env.ProgramFiles || 'C:\\Program Files', 'Tesseract-OCR', name),
      env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, 'Programs', 'Tesseract-OCR', name) : '',
    ]
    : ['/usr/bin/tesseract', '/usr/local/bin/tesseract', '/opt/homebrew/bin/tesseract'];
  return fromPath.concat(wellKnown.filter(Boolean));
}

function discoverOcrCommand(opts = {}) {
  if (opts.fresh !== true && discoveredCommandCache !== undefined) return discoveredCommandCache;
  const env = opts.env || process.env;
  const platform = opts.platform || process.platform;
  const stat = opts.statSync || fs.statSync;
  discoveredCommandCache = tesseractCandidates(env, platform).find((candidate) => {
    try {
      return stat(candidate).isFile();
    } catch {
      return false;
    }
  }) || '';
  return discoveredCommandCache;
}

function resetOcrDiscovery() {
  discoveredCommandCache = undefined;
}

function ocrSettings(opts = {}) {
  const env = opts.env || process.env;
  const injected = typeof opts.extractImageText === 'function';
  let command = String(opts.command || env.ENDPOINT_AGENT_OCR_COMMAND || env.REDACTWALL_ENDPOINT_AGENT_OCR_COMMAND || '').trim();
  let autoDiscovered = false;
  if (!command && !injected && opts.discover !== false) {
    command = discoverOcrCommand(opts);
    autoDiscovered = Boolean(command);
  }
  if (!command && !injected) return { configured: false };
  const args = Array.isArray(opts.args)
    ? opts.args.map((item) => String(item))
    : parseArgsJson(opts.argsJson || env.ENDPOINT_AGENT_OCR_ARGS_JSON || env.REDACTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON);
  return {
    configured: true,
    command: command || '[injected]',
    autoDiscovered,
    args,
    timeoutMs: boundedPositiveInt(
      opts.timeoutMs || env.ENDPOINT_AGENT_OCR_TIMEOUT_MS || env.REDACTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS,
      DEFAULT_TIMEOUT_MS,
      1000,
      120000,
    ),
    maxChars: boundedPositiveInt(
      opts.maxChars || env.ENDPOINT_AGENT_OCR_MAX_CHARS || env.REDACTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS,
      DEFAULT_MAX_CHARS,
      1000,
      5000000,
    ),
  };
}

function defaultArgs(command, filePath) {
  const base = path.basename(String(command || '')).toLowerCase();
  if (base.includes('tesseract')) return [filePath, 'stdout'];
  return [filePath];
}

function materializeArgs(args, filePath) {
  if (!args || !args.length) return null;
  let usedPlaceholder = false;
  const out = args.map((item) => {
    if (item.includes('{file}')) usedPlaceholder = true;
    return item.replaceAll('{file}', filePath);
  });
  if (!usedPlaceholder) out.push(filePath);
  return out;
}

async function runOcrCommand(filePath, settings, opts = {}) {
  const args = materializeArgs(settings.args, filePath) || defaultArgs(settings.command, filePath);
  const runner = opts.execFileAsync || execFileAsync;
  const result = await runner(settings.command, args, {
    windowsHide: true,
    timeout: settings.timeoutMs,
    maxBuffer: Math.min(MAX_BUFFER_BYTES, settings.maxChars * 4),
  });
  return result && result.stdout ? result.stdout : '';
}

function fail(error, extra = {}) {
  return {
    text: '',
    processor: extra.processor || 'endpoint_ocr',
    supported: true,
    extractionOk: false,
    error,
    ...extra,
  };
}

// Sparse or blank OCR is not evidence that an image is clean. Strict handling
// is the default and cannot be disabled in production; a non-production
// workstation may opt into lenient behavior only for synthetic OCR testing.
const STRICT_MIN_CHARS = 8;

function ocrStrictMode(opts = {}) {
  const env = opts.env || process.env;
  const raw = env.ENDPOINT_AGENT_OCR_STRICT || env.REDACTWALL_ENDPOINT_AGENT_OCR_STRICT || env.PROMPTWALL_ENDPOINT_AGENT_OCR_STRICT || '';
  const runtime = String(env.NODE_ENV || '').trim().toLowerCase();
  const explicitDevelopment = runtime === 'development' || runtime === 'test';
  const lenientRequested = /^(0|off|false|no|lenient)$/i.test(String(raw).trim());
  return !(explicitDevelopment && lenientRequested);
}

function ocrMaxChars(opts = {}) {
  const env = opts.env || process.env;
  return boundedPositiveInt(
    opts.maxChars || env.ENDPOINT_AGENT_OCR_MAX_CHARS || env.REDACTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS,
    DEFAULT_MAX_CHARS, 1000, 5000000,
  );
}

function finalizeOcr(raw, maxChars, strict, extra = {}) {
  const text = String(raw || '');
  if (text.length > maxChars) {
    return fail('ocr_output_truncated', {
      processor: 'ocr_required',
      ocrRequired: true,
      ocrApplied: true,
      truncated: true,
      ...extra,
    });
  }
  if (strict && text.trim().length < STRICT_MIN_CHARS) {
    return fail('ocr_required', { processor: 'ocr_required', ocrRequired: true, ocrStrict: true, ...extra });
  }
  return {
    text,
    processor: 'endpoint_ocr',
    supported: true,
    extractionOk: true,
    ocrApplied: true,
    truncated: false,
    ...extra,
  };
}

// Precedence: explicit env command > native discovered tesseract > bundled WASM
// > ocr_required. This branch runs only when no native/injected engine is set.
async function extractWithWasm(filePath, opts, strict) {
  let wasm;
  try {
    wasm = opts.ocrWasm || require('./ocr-wasm');
  } catch {
    return fail('ocr_required', { processor: 'ocr_required', ocrRequired: true, ocrConfigured: false });
  }
  if (!wasm.wasmOcrAvailable(opts)) {
    return fail('ocr_required', { processor: 'ocr_required', ocrRequired: true, ocrConfigured: false });
  }
  try {
    const raw = await wasm.extractImageTextWasm(filePath, opts);
    return finalizeOcr(raw, ocrMaxChars(opts), strict, { ocrConfigured: true, ocrEngine: 'wasm' });
  } catch {
    // The bundled engine could not read the image (bad decode or timeout): it
    // still needs OCR, so route it to the queue rather than call it a scan failure.
    return fail('ocr_required', { processor: 'ocr_required', ocrRequired: true, ocrConfigured: false, ocrEngine: 'wasm' });
  }
}

async function extractImageFile(name, filePath, opts = {}) {
  if (!isImageFile(name)) return { text: '', processor: null, supported: false, extractionOk: false, error: 'unsupported' };
  let settings;
  try {
    settings = ocrSettings(opts);
  } catch {
    return fail('ocr_config_invalid', { ocrConfigured: true });
  }
  const strict = ocrStrictMode(opts);
  if (!settings.configured) {
    return extractWithWasm(filePath, opts, strict);
  }
  try {
    const raw = typeof opts.extractImageText === 'function'
      ? await opts.extractImageText(filePath, { filename: name, settings })
      : await runOcrCommand(filePath, settings, opts);
    return finalizeOcr(raw, settings.maxChars, strict, { ocrConfigured: true });
  } catch {
    return fail('extract_failed', { ocrConfigured: true, ocrApplied: false });
  }
}

module.exports = {
  DEFAULT_MAX_CHARS,
  DEFAULT_TIMEOUT_MS,
  discoverOcrCommand,
  extractImageFile,
  isImageFile,
  materializeArgs,
  ocrMaxChars,
  ocrSettings,
  ocrStrictMode,
  parseArgsJson,
  resetOcrDiscovery,
  runOcrCommand,
};
