'use strict';
/**
 * Optional endpoint-local OCR bridge.
 *
 * This is endpoint-only on purpose: the control plane still treats images as
 * ocr_required unless a workstation has a local OCR command configured.
 */
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const processors = require('../../server/processors');

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_CHARS = 1000000;
const MAX_BUFFER_BYTES = 4 * 1024 * 1024;

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

function ocrSettings(opts = {}) {
  const env = opts.env || process.env;
  const injected = typeof opts.extractImageText === 'function';
  const command = String(opts.command || env.ENDPOINT_AGENT_OCR_COMMAND || env.PROMPTWALL_ENDPOINT_AGENT_OCR_COMMAND || '').trim();
  if (!command && !injected) return { configured: false };
  const args = Array.isArray(opts.args)
    ? opts.args.map((item) => String(item))
    : parseArgsJson(opts.argsJson || env.ENDPOINT_AGENT_OCR_ARGS_JSON || env.PROMPTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON);
  return {
    configured: true,
    command: command || '[injected]',
    args,
    timeoutMs: boundedPositiveInt(
      opts.timeoutMs || env.ENDPOINT_AGENT_OCR_TIMEOUT_MS || env.PROMPTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS,
      DEFAULT_TIMEOUT_MS,
      1000,
      120000,
    ),
    maxChars: boundedPositiveInt(
      opts.maxChars || env.ENDPOINT_AGENT_OCR_MAX_CHARS || env.PROMPTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS,
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

async function extractImageFile(name, filePath, opts = {}) {
  if (!isImageFile(name)) return { text: '', processor: null, supported: false, extractionOk: false, error: 'unsupported' };
  let settings;
  try {
    settings = ocrSettings(opts);
  } catch {
    return fail('ocr_config_invalid', { ocrConfigured: true });
  }
  if (!settings.configured) {
    return fail('ocr_required', { processor: 'ocr_required', ocrRequired: true, ocrConfigured: false });
  }
  try {
    const raw = typeof opts.extractImageText === 'function'
      ? await opts.extractImageText(filePath, { filename: name, settings })
      : await runOcrCommand(filePath, settings, opts);
    const text = String(raw || '');
    return {
      text: text.slice(0, settings.maxChars),
      processor: 'endpoint_ocr',
      supported: true,
      extractionOk: true,
      ocrApplied: true,
      ocrConfigured: true,
      truncated: text.length > settings.maxChars,
    };
  } catch {
    return fail('extract_failed', { ocrConfigured: true, ocrApplied: false });
  }
}

module.exports = {
  DEFAULT_MAX_CHARS,
  DEFAULT_TIMEOUT_MS,
  extractImageFile,
  isImageFile,
  materializeArgs,
  ocrSettings,
  parseArgsJson,
  runOcrCommand,
};
