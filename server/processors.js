'use strict';
/**
 * File-processor registry (inspired by Strac's processors).
 *
 * Each processor extracts plain text from a file type so the detection engine
 * can scan it. Add a processor by pushing to PROCESSORS with the contract:
 *   { id, supports(filename) -> bool, extract(buffer) -> Promise<string> }
 *
 * Closes the biggest gap vs. plain-text-only scanning: PDFs, Word, Excel, and
 * PowerPoint files uploaded to AI tools now get inspected.
 */
require('./env').loadEnv();
const path = require('path');

const TEXT_EXT = new Set(['.txt', '.csv', '.tsv', '.json', '.yaml', '.yml', '.xml', '.html', '.htm',
  '.md', '.log', '.js', '.ts', '.py', '.java', '.sql', '.env', '.ini', '.conf', '.rtf', '.eml']);
const OFFICE_EXT = new Set(['.docx', '.xlsx', '.pptx']);
const PDF_EXT = new Set(['.pdf']);
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.tif', '.tiff', '.bmp', '.webp']);
const DEFAULT_EXTRACT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_EXTRACTED_CHARS = 1000000;

function ext(name) { return path.extname(String(name || '')).toLowerCase(); }
function stripXml(xml) {
  return String(xml)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/\s+/g, ' ').trim();
}

const TextProcessor = {
  id: 'text',
  supports: (name) => TEXT_EXT.has(ext(name)),
  extract: async (buf) => buf.toString('utf8'),
};

const OfficeProcessor = {
  id: 'office',
  // No extractable text from a rich/binary format means we could not read it
  // (e.g. an image-only doc) — hold it for OCR instead of treating '' as clean.
  holdIfEmpty: true,
  supports: (name) => OFFICE_EXT.has(ext(name)),
  extract: async (buf, opts = {}) => {
    const AdmZip = require('adm-zip');
    let zip;
    try { zip = new AdmZip(buf); } catch {
      const err = new Error('office extract failed');
      err.code = 'EXTRACT_FAILED';
      throw err;
    }
    // Decompression-bomb guard: a small OOXML file can inflate to gigabytes.
    // Bound the cumulative uncompressed bytes we will inflate, using the sizes
    // declared in each entry's zip header, and refuse the file if it exceeds the
    // budget (fail closed — the file is blocked unscanned rather than OOMing).
    const budget = maxOfficeBytes(opts);
    const parts = [];
    let used = 0;
    for (const entry of zip.getEntries()) {
      const n = entry.entryName;
      // Document body XML parts that carry visible text.
      if (/^word\/(document|header\d*|footer\d*)\.xml$/.test(n) ||
          /^xl\/sharedStrings\.xml$/.test(n) ||
          /^xl\/worksheets\/sheet\d+\.xml$/.test(n) ||
          /^word\/(comments|footnotes|endnotes)\.xml$/.test(n) ||
          /^ppt\/slides\/slide\d+\.xml$/.test(n) ||
          /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(n)) {
        const declared = entry.header && Number(entry.header.size);
        if (Number.isFinite(declared) && used + declared > budget) {
          const err = new Error('office extract exceeds size budget');
          err.code = 'EXTRACT_FAILED';
          throw err;
        }
        try {
          const data = entry.getData();
          used += data.length;
          if (used > budget) {
            const err = new Error('office extract exceeds size budget');
            err.code = 'EXTRACT_FAILED';
            throw err;
          }
          parts.push(stripXml(data.toString('utf8')));
        } catch (e) {
          if (e && e.code === 'EXTRACT_FAILED') throw e;
        }
      }
    }
    return parts.join('\n');
  },
};

const PdfProcessor = {
  id: 'pdf',
  // A PDF with no text layer (scanned/image-only) extracts '' — hold for OCR
  // rather than passing the un-inspected imagery through as clean.
  holdIfEmpty: true,
  supports: (name) => PDF_EXT.has(ext(name)),
  extract: async (buf) => {
    try {
      const mod = require('pdf-parse');
      if (mod.PDFParse) {                       // pdf-parse v2 (class API)
        const parser = new mod.PDFParse({ data: buf });
        const r = await parser.getText();
        return (r && r.text) ? r.text : '';
      }
      const fn = typeof mod === 'function' ? mod : (mod.pdf || mod.default); // v1 fallback
      const data = await fn(buf);
      return (data && data.text) ? data.text : '';
    } catch (e) {
      const err = new Error('pdf extract failed');
      err.code = 'EXTRACT_FAILED';
      throw err;
    }
  },
};

const OcrRequiredProcessor = {
  id: 'ocr_required',
  supports: (name) => IMAGE_EXT.has(ext(name)),
  requiresOcr: true,
  extract: async () => {
    const err = new Error('ocr required');
    err.code = 'OCR_REQUIRED';
    throw err;
  },
};

const PROCESSORS = [TextProcessor, OfficeProcessor, PdfProcessor, OcrRequiredProcessor];

function supported(name) { return PROCESSORS.some((p) => p.supports(name)); }

function boundedPositiveInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function timeoutMs(opts) {
  return boundedPositiveInt(
    opts.timeoutMs ?? process.env.FILE_EXTRACT_TIMEOUT_MS,
    DEFAULT_EXTRACT_TIMEOUT_MS,
    100,
    60000,
  );
}

function maxTextChars(opts) {
  return boundedPositiveInt(
    opts.maxTextChars ?? process.env.FILE_EXTRACT_MAX_CHARS,
    DEFAULT_MAX_EXTRACTED_CHARS,
    1000,
    5000000,
  );
}

function maxOfficeBytes(opts) {
  return boundedPositiveInt(
    opts.maxOfficeBytes ?? process.env.FILE_EXTRACT_MAX_OFFICE_BYTES,
    64 * 1024 * 1024,
    64 * 1024,
    512 * 1024 * 1024,
  );
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      const err = new Error('extract timed out');
      err.code = 'EXTRACT_TIMEOUT';
      reject(err);
    }, ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Extract text from a file buffer. Returns { text, processor, supported }. */
async function extractText(name, buf, opts = {}) {
  const p = PROCESSORS.find((x) => x.supports(name));
  if (!p) return { text: '', processor: null, supported: false, extractionOk: false, error: 'unsupported' };
  if (p.requiresOcr) {
    return {
      text: '',
      processor: p.id,
      supported: true,
      extractionOk: false,
      error: 'ocr_required',
      ocrRequired: true,
    };
  }
  try {
    const raw = await withTimeout(Promise.resolve().then(() => p.extract(buf, opts)), timeoutMs(opts));
    const text = String(raw || '');
    const max = maxTextChars(opts);
    if (text.length > max) {
      // Fail closed: we can only scan the first `max` chars, so the unscanned
      // tail could carry PII (benign padding then SSNs/cards). Returning a
      // truncated window with extractionOk:true let that content through
      // unscanned, so treat truncation as an extraction failure — the caller's
      // fail-closed path then holds the file unscanned instead of allowing it.
      return {
        text: '',
        processor: p.id,
        supported: true,
        extractionOk: false,
        error: 'truncated',
        truncated: true,
      };
    }
    if (p.holdIfEmpty && text.trim() === '') {
      // Fail closed: a binary/rich format that yielded no text was not truly
      // "scanned clean" — route it to the OCR hold so PII in imagery can't slip
      // through as an allowed empty extraction.
      return { text: '', processor: p.id, supported: true, extractionOk: false, error: 'ocr_required', ocrRequired: true };
    }
    return {
      text,
      processor: p.id,
      supported: true,
      extractionOk: true,
      truncated: false,
    };
  } catch (e) {
    return {
      text: '',
      processor: p.id,
      supported: true,
      extractionOk: false,
      error: e && e.code === 'EXTRACT_TIMEOUT' ? 'timeout'
        : e && e.code === 'OCR_REQUIRED' ? 'ocr_required'
        : 'extract_failed',
      ...(e && e.code === 'OCR_REQUIRED' ? { ocrRequired: true } : {}),
    };
  }
}

module.exports = {
  extractText,
  supported,
  PROCESSORS,
  TEXT_EXT,
  OFFICE_EXT,
  PDF_EXT,
  IMAGE_EXT,
  DEFAULT_EXTRACT_TIMEOUT_MS,
  DEFAULT_MAX_EXTRACTED_CHARS,
};
