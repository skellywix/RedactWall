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
const MARKUP_EXT = new Set(['.xml', '.html', '.htm']);
const HTML_EXT = new Set(['.html', '.htm']);
const PLAIN_TEXT_EXT = new Set([...TEXT_EXT].filter((value) => !MARKUP_EXT.has(value) && !['.json', '.rtf', '.eml'].includes(value)));
const OFFICE_EXT = new Set(['.docx', '.xlsx', '.pptx']);
const PDF_EXT = new Set(['.pdf']);
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.tif', '.tiff', '.bmp', '.webp']);
const DEFAULT_EXTRACT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_EXTRACTED_CHARS = 1000000;
const OFFICE_TEXT_ENTRY = /(?:\.xml|\.rels)$/i;
const MIME_DEPTH_MAX = 8;
const MIME_PARTS_MAX = 128;
const OPAQUE_HTML_TAGS = new Set(['script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'svg']);
const PDF_OPAQUE_PAINT_OP_NAMES = [
  'constructPath', 'stroke', 'closeStroke', 'fill', 'eoFill', 'fillStroke', 'eoFillStroke',
  'closeFillStroke', 'closeEOFillStroke', 'shadingFill', 'paintXObject', 'rawFillPath',
  'paintImageMaskXObject', 'paintImageMaskXObjectGroup', 'paintImageXObject', 'paintInlineImageXObject',
  'paintInlineImageXObjectGroup', 'paintImageXObjectRepeat', 'paintImageMaskXObjectRepeat', 'paintSolidColorImageMask',
];
const PDF_OPAQUE_ANNOTATIONS = new Set([
  'fileattachment', 'sound', 'movie', 'screen', '3d', 'richmedia',
]);
const PDF_VECTOR_ANNOTATIONS = new Set([
  'line', 'square', 'circle', 'polygon', 'polyline', 'ink', 'stamp', 'watermark', 'redact',
]);
const PDF_OBJECT_DEPTH_MAX = 16;
const PDF_OBJECT_NODES_MAX = 10000;
let pdfOpaquePaintOpsPromise;

function ext(name) { return path.extname(String(name || '')).toLowerCase(); }

function extractionError(message, code = 'EXTRACT_FAILED') {
  const error = new Error(message);
  error.code = code;
  return error;
}

function decodeWith(encoding, buf) {
  try { return new TextDecoder(encoding, { fatal: true }).decode(buf); } catch {
    throw extractionError('invalid text encoding');
  }
}

function guessedUtf16(buf) {
  if (buf.length < 4 || buf.length % 2 !== 0) return '';
  let evenZero = 0;
  let oddZero = 0;
  const pairs = Math.min(buf.length / 2, 4096);
  for (let i = 0; i < pairs * 2; i += 2) {
    if (buf[i] === 0) evenZero += 1;
    if (buf[i + 1] === 0) oddZero += 1;
  }
  if (oddZero / pairs >= 0.3 && evenZero / pairs <= 0.05) return 'utf-16le';
  if (evenZero / pairs >= 0.3 && oddZero / pairs <= 0.05) return 'utf-16be';
  return '';
}

function normalizeCharset(value) {
  const charset = String(value || '').trim().toLowerCase().replace(/^['"]|['"]$/g, '');
  if (['utf8', 'utf-8', 'us-ascii', 'ascii'].includes(charset)) return charset.includes('ascii') ? 'ascii' : 'utf-8';
  if (['utf16', 'utf-16', 'utf-16le'].includes(charset)) return 'utf-16le';
  if (charset === 'utf-16be') return 'utf-16be';
  if (['iso-8859-1', 'latin1', 'windows-1252', 'cp1252'].includes(charset)) return 'windows-1252';
  return charset;
}

function decodeTextBuffer(value, declaredCharset = '') {
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(value || '');
  let encoding = normalizeCharset(declaredCharset);
  let offset = 0;
  if (buf.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) { encoding = 'utf-8'; offset = 3; }
  else if (buf.subarray(0, 2).equals(Buffer.from([0xff, 0xfe]))) { encoding = 'utf-16le'; offset = 2; }
  else if (buf.subarray(0, 2).equals(Buffer.from([0xfe, 0xff]))) { encoding = 'utf-16be'; offset = 2; }
  else if (!encoding) encoding = guessedUtf16(buf) || 'utf-8';
  if (!['utf-8', 'utf-16le', 'utf-16be', 'ascii', 'windows-1252'].includes(encoding)) {
    throw extractionError('unsupported text encoding');
  }
  const bytes = buf.subarray(offset);
  if (encoding.startsWith('utf-16') && bytes.length % 2 !== 0) throw extractionError('invalid utf-16 length');
  if (encoding === 'ascii' && bytes.some((byte) => byte > 0x7f)) throw extractionError('invalid ascii text');
  const text = decodeWith(encoding === 'ascii' ? 'utf-8' : encoding, bytes).replace(/^\uFEFF/, '');
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) throw extractionError('unsafe control byte in text');
  return text;
}

function decodeMarkupEntities(value) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  return String(value).replace(/&(#(?:x[0-9a-f]{1,6}|[0-9]{1,7});?|(?:amp|lt|gt|quot|apos|nbsp);)/gi, (whole, token) => {
    token = token.replace(/;$/, '');
    if (token[0] !== '#') return named[token.toLowerCase()] || whole;
    const hex = token[1].toLowerCase() === 'x';
    const point = Number.parseInt(token.slice(hex ? 2 : 1), hex ? 16 : 10);
    if (!Number.isInteger(point) || point < 0 || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) return whole;
    if ((point < 0x20 && ![0x09, 0x0a, 0x0d].includes(point)) || point === 0x7f) throw extractionError('unsafe markup entity');
    return String.fromCodePoint(point);
  });
}

function visibleXmlText(xml) {
  const visible = String(xml)
    .replace(/<!--([\s\S]*?)-->/g, '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<\/(?:w:p|a:p|p|tr|row|div|li|h[1-6])\s*>/gi, '\n')
    .replace(/<(?:w:tab|w:br|a:br|br)\b[^>]*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, '');
  return decodeMarkupEntities(visible).replace(/[\t ]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

function rejectMarkupDeclarations(value) {
  if (/<!ENTITY\b|<!DOCTYPE\b[^>]*\[/i.test(String(value))) throw extractionError('unsafe markup declaration');
}

function stripXml(xml) {
  const raw = String(xml);
  const extras = [];
  raw.replace(/<!--([\s\S]*?)-->|<!\[CDATA\[([\s\S]*?)\]\]>|\s[\w:.-]+\s*=\s*(["'])([\s\S]*?)\3/g,
    (_whole, comment, cdata, _quote, attr) => { extras.push(comment ?? cdata ?? attr ?? ''); return ''; });
  raw.replace(/<([^>]+)>/g, (_whole, tagBody) => { if (/[="']/.test(tagBody)) extras.push(tagBody); return ''; });
  return decodeMarkupEntities([visibleXmlText(raw), ...extras].join('\n')).replace(/[\t ]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

function decodeCssEscapes(value) {
  const source = String(value);
  if (/\/\*[\s\S]*$/.test(source.replace(/\/\*[\s\S]*?\*\//g, ''))) throw extractionError('unterminated css comment');
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(
    /\\([0-9a-f]{1,6})(?:\r\n|[\t\n\f\r ])?|\\([^\r\n0-9a-f])/gi,
    (_whole, hex, escaped) => {
      if (escaped !== undefined) return escaped;
      const point = Number.parseInt(hex, 16);
      if (!point || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) throw extractionError('invalid css escape');
      return String.fromCodePoint(point);
    },
  );
}

function rejectOpaqueUrl(value) {
  const normalized = decodeCssEscapes(decodeMarkupEntities(value)).replace(/[\t\n\f\r ]/g, '');
  if (/(?:^|[^a-z0-9+.-])(?:data|blob|javascript):/i.test(normalized)) {
    throw extractionError('opaque or active html url');
  }
}

function walkHtmlTags(source, visit) {
  let cursor = 0;
  while (cursor < source.length) {
    const start = source.indexOf('<', cursor);
    if (start < 0) return;
    if (source.startsWith('<!--', start)) {
      const end = source.indexOf('-->', start + 4);
      if (end < 0) throw extractionError('unterminated html comment');
      cursor = end + 3;
      continue;
    }
    if (!/[A-Za-z!?/]/.test(source[start + 1] || '')) { cursor = start + 1; continue; }
    let quote = '';
    let end = start + 1;
    for (; end < source.length; end += 1) {
      const char = source[end];
      if (quote) { if (char === quote) quote = ''; continue; }
      if (char === '"' || char === "'") { quote = char; continue; }
      if (char === '>') break;
    }
    if (end >= source.length) throw extractionError('unterminated html tag');
    visit(source.slice(start, end + 1), start, end + 1);
    cursor = end + 1;
  }
}

function inspectHtmlTag(tag) {
  const head = tag.match(/^<\s*(\/?)\s*([A-Za-z][\w:-]*)/);
  if (!head) return { name: '', closing: false };
  const name = head[2].toLowerCase();
  const closing = head[1] === '/';
  if (OPAQUE_HTML_TAGS.has(name)) throw extractionError('opaque or active html element');
  if (closing) return { name, closing };
  const attributes = tag.slice(head[0].length, -1);
  const attr = /\s+([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let match;
  let refresh = false;
  while ((match = attr.exec(attributes))) {
    const attrName = match[1].toLowerCase();
    const attrValue = match[2] ?? match[3] ?? match[4] ?? '';
    if (/^on[a-z]/i.test(attrName) || attrName === 'srcdoc') throw extractionError('active html attribute');
    if (attrName === 'http-equiv' && decodeMarkupEntities(attrValue).trim().toLowerCase() === 'refresh') refresh = true;
    rejectOpaqueUrl(attrValue);
  }
  if (refresh) throw extractionError('active html refresh');
  return { name, closing };
}

function rejectOpaqueHtml(value) {
  const source = String(value);
  let styleStart = -1;
  walkHtmlTags(source, (tag, start, end) => {
    const info = inspectHtmlTag(tag);
    if (info.name !== 'style') return;
    if (info.closing) {
      if (styleStart < 0) throw extractionError('unbalanced html style');
      rejectOpaqueUrl(source.slice(styleStart, start));
      styleStart = -1;
    } else {
      if (styleStart >= 0) throw extractionError('nested html style');
      styleStart = end;
    }
  });
  if (styleStart >= 0) throw extractionError('unterminated html style');
}

function startsWithBytes(buf, bytes) {
  return buf.length >= bytes.length && buf.subarray(0, bytes.length).equals(Buffer.from(bytes));
}

function decodedSniffHead(buf) {
  const slice = buf.subarray(0, Math.min(buf.length, 8192));
  let encoding = guessedUtf16(slice) || 'utf-8';
  let offset = 0;
  if (slice.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) { encoding = 'utf-8'; offset = 3; }
  else if (slice.subarray(0, 2).equals(Buffer.from([0xff, 0xfe]))) { encoding = 'utf-16le'; offset = 2; }
  else if (slice.subarray(0, 2).equals(Buffer.from([0xfe, 0xff]))) { encoding = 'utf-16be'; offset = 2; }
  try { return new TextDecoder(encoding).decode(slice.subarray(offset)); } catch { return slice.toString('latin1'); }
}

function sniffFormat(value) {
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(value || '');
  if (startsWithBytes(buf, [0x50, 0x4b, 0x03, 0x04]) || startsWithBytes(buf, [0x50, 0x4b, 0x05, 0x06]) ||
      startsWithBytes(buf, [0x50, 0x4b, 0x07, 0x08])) return 'zip';
  if (startsWithBytes(buf, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole';
  const head = buf.subarray(0, 1024).toString('latin1');
  if (head.includes('%PDF-')) return 'pdf';
  if (startsWithBytes(buf, [0x89, 0x50, 0x4e, 0x47]) || startsWithBytes(buf, [0xff, 0xd8, 0xff]) ||
      startsWithBytes(buf, [0x49, 0x49, 0x2a, 0x00]) || startsWithBytes(buf, [0x4d, 0x4d, 0x00, 0x2a]) ||
      startsWithBytes(buf, [0x42, 0x4d]) || (head.startsWith('RIFF') && head.slice(8, 12) === 'WEBP')) return 'image';
  const textHead = decodedSniffHead(buf);
  const sample = textHead.replace(/^\uFEFF/, '').trimStart();
  if (/^\{\\rtf[0-9]+\b/i.test(sample)) return 'rtf';
  const mimeHead = textHead;
  if (/^(?:MIME-Version|Content-Type|Content-Transfer-Encoding):[^\r\n]*(?:\r?\n)/im.test(mimeHead) && /\r?\n\r?\n/.test(mimeHead)) return 'mime';
  const headerBlock = mimeHead.split(/\r?\n\r?\n/, 1)[0] || '';
  const mailHeaders = headerBlock.match(/^(?:From|To|Cc|Subject|Date|Message-ID):/gim) || [];
  if ((mailHeaders.length >= 2 || /=\?[^?]+\?[bq]\?[^?]*\?=/i.test(headerBlock)) && /\r?\n\r?\n/.test(mimeHead)) return 'mime';
  return 'text';
}

function validateFormat(processor, buf) {
  const actual = sniffFormat(buf);
  if (processor.id === 'office' && actual !== 'zip') throw extractionError('office signature mismatch');
  if (processor.id === 'pdf' && actual !== 'pdf') throw extractionError('pdf signature mismatch');
  if (processor.id === 'rtf' && actual !== 'rtf') throw extractionError('rtf signature mismatch');
  if (processor.id === 'email' && !['text', 'mime'].includes(actual)) throw extractionError('email signature mismatch', 'FORMAT_MISMATCH');
  if (['text', 'json', 'markup'].includes(processor.id) && actual !== 'text') {
    throw extractionError('file signature conflicts with extension', 'FORMAT_MISMATCH');
  }
}

const TextProcessor = {
  id: 'text',
  supports: (name) => PLAIN_TEXT_EXT.has(ext(name)),
  extract: async (buf) => decodeTextBuffer(buf),
};

const JsonProcessor = {
  id: 'json',
  requiresIsolation: true,
  supports: (name) => ext(name) === '.json',
  extract: async (buf) => {
    try {
      const source = decodeTextBuffer(buf);
      const parsed = JSON.parse(source);
      const strings = source.match(/"(?:\\[\s\S]|[^"\\])*"/g) || [];
      return [JSON.stringify(parsed), ...strings.map((token) => JSON.parse(token))].join('\n');
    } catch (error) {
      if (error && error.code === 'EXTRACT_FAILED') throw error;
      throw extractionError('json extract failed');
    }
  },
};

const MarkupProcessor = {
  id: 'markup',
  requiresIsolation: true,
  supports: (name) => MARKUP_EXT.has(ext(name)),
  extract: async (buf, _opts, filename) => {
    const decoded = decodeTextBuffer(buf);
    rejectMarkupDeclarations(decoded);
    if (HTML_EXT.has(ext(filename))) rejectOpaqueHtml(decoded);
    return stripXml(decoded);
  },
};

function officeFamily(name) {
  return { '.docx': 'word', '.xlsx': 'xl', '.pptx': 'ppt' }[ext(name)] || '';
}

function visibleOfficeEntry(name) {
  return /^word\/(document|header\d*|footer\d*|comments|footnotes|endnotes)\.xml$/i.test(name) ||
    /^xl\/(sharedStrings\.xml|worksheets\/sheet\d+\.xml)$/i.test(name) ||
    /^ppt\/(slides\/slide\d+|notesSlides\/notesSlide\d+)\.xml$/i.test(name);
}

function safeOfficeEntryName(entry) {
  const raw = String(entry.entryName || '');
  const name = raw.replace(/\\/g, '/');
  if (!name || name.includes('\0') || name.startsWith('/') || name.split('/').includes('..')) {
    throw extractionError('unsafe office entry');
  }
  return name;
}

function readOfficeEntry(entry, state) {
  const declared = entry.header && Number(entry.header.size);
  if (Number.isFinite(declared) && (declared < 0 || state.used + declared > state.budget)) {
    throw extractionError('office extract exceeds size budget');
  }
  try {
    const data = entry.getData();
    state.used += data.length;
    if (state.used > state.budget) throw extractionError('office extract exceeds size budget');
    return data;
  } catch (error) {
    if (error && error.code === 'EXTRACT_FAILED') throw error;
    throw extractionError('office extract failed');
  }
}

const OfficeProcessor = {
  id: 'office',
  requiresIsolation: true,
  // No extractable text from a rich/binary format means we could not read it
  // (e.g. an image-only doc) — hold it for OCR instead of treating '' as clean.
  holdIfEmpty: true,
  supports: (name) => OFFICE_EXT.has(ext(name)),
  extract: async (buf, opts = {}, filename = '') => {
    const AdmZip = require('adm-zip');
    let zip;
    try { zip = new AdmZip(buf); } catch {
      throw extractionError('office extract failed');
    }
    // Decompression-bomb guard: a small OOXML file can inflate to gigabytes.
    // Bound the cumulative uncompressed bytes we will inflate, using the sizes
    // declared in each entry's zip header, and refuse the file if it exceeds the
    // budget (fail closed — the file is blocked unscanned rather than OOMing).
    const state = { budget: maxOfficeBytes(opts), used: 0 };
    const parts = [];
    let familyFound = false;
    let visibleFound = false;
    const family = officeFamily(filename);
    for (const entry of zip.getEntries()) {
      if (entry.isDirectory) continue;
      const n = safeOfficeEntryName(entry);
      if (family && n.toLowerCase().startsWith(family + '/')) familyFound = true;
      // OOXML is an XML package. Any embedded media, object, macro, font, or
      // other opaque member cannot be inspected here, so the whole file holds.
      if (!OFFICE_TEXT_ENTRY.test(n)) throw extractionError('opaque office entry');
      const decoded = decodeTextBuffer(readOfficeEntry(entry, state));
      rejectMarkupDeclarations(decoded);
      const text = stripXml(decoded);
      if (visibleOfficeEntry(n) && visibleXmlText(decoded)) visibleFound = true;
      if (text) parts.push(text);
    }
    if (!familyFound) throw extractionError('office family mismatch');
    if (!visibleFound) throw extractionError('ocr required', 'OCR_REQUIRED');
    return parts.join('\n');
  },
};

const PdfProcessor = {
  id: 'pdf',
  requiresIsolation: true,
  // A PDF with no text layer (scanned/image-only) extracts '' — hold for OCR
  // rather than passing the un-inspected imagery through as clean.
  holdIfEmpty: true,
  supports: (name) => PDF_EXT.has(ext(name)),
  extract: async (buf, opts = {}) => {
    try {
      assertCanonicalPdf(buf);
      const mod = require('pdf-parse');
      if (typeof mod.PDFParse !== 'function') throw extractionError('pdf parser cannot inspect complete content');
      const parser = new mod.PDFParse({ data: buf });
      try {
        const supplemental = await inspectPdfDocument(parser, opts);
        const r = await parser.getText();
        return [(r && r.text) || '', ...supplemental].filter(Boolean).join('\n');
      } finally {
        if (typeof parser.destroy === 'function') await parser.destroy();
      }
    } catch (e) {
      if (e && e.code === 'OCR_REQUIRED') throw e;
      throw extractionError('pdf extract failed');
    }
  },
};

function assertCanonicalPdf(value) {
  const source = (Buffer.isBuffer(value) ? value : Buffer.from(value || '')).toString('latin1');
  const endings = [...source.matchAll(/(?:^|[\r\n])startxref[\x00\t\n\f\r ]+([0-9]+)[\x00\t\n\f\r ]+%%EOF/g)];
  if (endings.length !== 1) throw extractionError('pdf incremental or unaccounted content');
  const ending = endings[0];
  const tail = source.slice(ending.index + ending[0].length);
  if (/[^\x00\t\n\f\r ]/.test(tail)) throw extractionError('pdf trailing content');
  const xrefOffset = Number(ending[1]);
  if (!Number.isSafeInteger(xrefOffset) || xrefOffset < 0 || xrefOffset >= source.length) {
    throw extractionError('invalid pdf xref offset');
  }
  const xrefTarget = source.slice(xrefOffset, xrefOffset + 96).replace(/^[\x00\t\n\f\r ]+/, '');
  if (!xrefTarget.startsWith('xref') && !/^[0-9]+[\x00\t\n\f\r ]+[0-9]+[\x00\t\n\f\r ]+obj\b/.test(xrefTarget)) {
    throw extractionError('invalid pdf xref target');
  }
}

function hasPdfContent(value) {
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}

function requirePdfApi(value, methods, label) {
  if (!value || methods.some((method) => typeof value[method] !== 'function')) {
    throw extractionError(`pdf ${label} inspection unavailable`);
  }
}

function addPdfText(state, value) {
  const text = String(value || '');
  if (!text) return;
  state.characters += text.length;
  if (state.characters > state.maxCharacters) throw extractionError('pdf supplemental text exceeds size budget');
  state.text.push(text);
}

function collectPdfStrings(value, state, depth = 0, key = '') {
  if (value === null || value === undefined || typeof value === 'number' || typeof value === 'boolean') return;
  if (typeof value === 'string') { addPdfText(state, value); return; }
  if (typeof value !== 'object') throw extractionError('opaque pdf supplemental value');
  if (ArrayBuffer.isView(value)) {
    if (key.toLowerCase().endsWith('color') && value.byteLength <= 16) return;
    throw extractionError('opaque pdf binary value');
  }
  if (value instanceof ArrayBuffer) throw extractionError('opaque pdf binary value');
  if (depth >= PDF_OBJECT_DEPTH_MAX || ++state.nodes > PDF_OBJECT_NODES_MAX) {
    throw extractionError('pdf supplemental structure exceeds size budget');
  }
  if (state.seen.has(value)) throw extractionError('cyclic pdf supplemental structure');
  state.seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (const item of value) collectPdfStrings(item, state, depth + 1, key);
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw extractionError('opaque pdf supplemental object');
    for (const [name, item] of Object.entries(value)) {
      addPdfText(state, name);
      collectPdfStrings(item, state, depth + 1, name);
    }
  } finally {
    state.seen.delete(value);
  }
}

async function pdfOpaquePaintOps() {
  if (!pdfOpaquePaintOpsPromise) {
    pdfOpaquePaintOpsPromise = import('pdfjs-dist/legacy/build/pdf.mjs').then(({ OPS }) => {
      const values = PDF_OPAQUE_PAINT_OP_NAMES.map((name) => OPS && OPS[name]);
      if (values.some((value) => !Number.isInteger(value))) throw extractionError('pdf paint inspection unavailable');
      return new Set(values);
    });
  }
  return pdfOpaquePaintOpsPromise;
}

async function inspectPdfPage(page, opaquePaintOps, state) {
  requirePdfApi(page, ['getOperatorList', 'getAnnotations', 'getJSActions'], 'page');
  const pageActions = await page.getJSActions();
  if (hasPdfContent(pageActions)) throw extractionError('active pdf page content');
  const annotations = await page.getAnnotations({ intent: 'display' });
  if (!Array.isArray(annotations)) throw extractionError('invalid pdf annotations');
  for (const annotation of annotations) {
    const subtype = String(annotation && annotation.subtype || '').toLowerCase();
    if (PDF_OPAQUE_ANNOTATIONS.has(subtype) || (annotation && (annotation.file || annotation.attachment))) {
      throw extractionError('opaque pdf annotation');
    }
    if (PDF_VECTOR_ANNOTATIONS.has(subtype)) throw extractionError('pdf vector annotation requires ocr', 'OCR_REQUIRED');
    collectPdfStrings(annotation, state);
  }
  const operators = await page.getOperatorList();
  if (!operators || !Array.isArray(operators.fnArray)) throw extractionError('invalid pdf operator list');
  if (operators.fnArray.some((operation) => opaquePaintOps.has(operation))) {
    throw extractionError('pdf non-text paint requires ocr', 'OCR_REQUIRED');
  }
}

async function inspectPdfDocument(parser, opts = {}) {
  requirePdfApi(parser, ['load'], 'document');
  const [doc, opaquePaintOps] = await Promise.all([parser.load(), pdfOpaquePaintOps()]);
  if (!doc || !Number.isSafeInteger(doc.numPages) || doc.numPages < 1) throw extractionError('invalid pdf page count');
  requirePdfApi(doc, [
    'getAttachments', 'getJSActions', 'getOpenAction', 'getFieldObjects', 'getMetadata', 'getOutline', 'getPage',
  ], 'document');
  if (hasPdfContent(await doc.getAttachments())) throw extractionError('pdf attachments are not inspectable');
  if (hasPdfContent(await doc.getJSActions())) throw extractionError('active pdf document content');

  const state = {
    text: [],
    characters: 0,
    maxCharacters: maxTextChars(opts),
    nodes: 0,
    seen: new WeakSet(),
  };
  collectPdfStrings(await doc.getOpenAction(), state);
  const fields = await doc.getFieldObjects();
  collectPdfStrings(fields, state);
  const metadata = await doc.getMetadata();
  if (!metadata || !metadata.info || typeof metadata.info !== 'object') throw extractionError('invalid pdf metadata');
  if (metadata.info.IsXFAPresent === true || metadata.info.IsCollectionPresent === true) {
    throw extractionError('opaque pdf document structure');
  }
  collectPdfStrings(metadata.info, state);
  if (metadata.metadata !== null && metadata.metadata !== undefined) {
    if (typeof metadata.metadata.getRaw !== 'function') throw extractionError('pdf metadata inspection unavailable');
    collectPdfStrings(metadata.metadata.getRaw(), state);
  }
  collectPdfStrings(await doc.getOutline(), state);

  for (let pageNumber = 1; pageNumber <= doc.numPages; pageNumber += 1) {
    const page = await doc.getPage(pageNumber);
    try {
      await inspectPdfPage(page, opaquePaintOps, state);
    } finally {
      if (page && typeof page.cleanup === 'function') page.cleanup();
    }
  }
  return state.text;
}

function skipRtfFallback(input, offset, count) {
  let i = offset;
  for (let n = 0; n < count && i < input.length; n += 1) {
    if (input[i] !== '\\') { i += 1; continue; }
    if (input[i + 1] === "'" && /^[0-9a-f]{2}$/i.test(input.slice(i + 2, i + 4))) i += 4;
    else i += 2;
  }
  return i;
}

function readRtfControl(input, offset) {
  let i = offset;
  while (/[A-Za-z]/.test(input[i] || '')) i += 1;
  const word = input.slice(offset, i).toLowerCase();
  let sign = 1;
  if (input[i] === '-') { sign = -1; i += 1; }
  const start = i;
  while (/[0-9]/.test(input[i] || '')) i += 1;
  const arg = start === i ? null : sign * Number(input.slice(start, i));
  if (input[i] === ' ') i += 1;
  return { word, arg, next: i };
}

function extractRtf(input) {
  const source = String(input).replace(/^\uFEFF/, '');
  if (!/^\s*\{\\rtf[0-9]+\b/i.test(source)) throw extractionError('invalid rtf');
  if (/\\(?:bin[0-9]*|object|objdata|pict)\b/i.test(source)) throw extractionError('opaque rtf content');
  let out = '';
  let ucSkip = 1;
  for (let i = 0; i < source.length;) {
    const ch = source[i];
    if (ch === '{' || ch === '}') { i += 1; continue; }
    if (ch !== '\\') { out += ch; i += 1; continue; }
    const symbol = source[i + 1] || '';
    if (symbol === "'" && /^[0-9a-f]{2}$/i.test(source.slice(i + 2, i + 4))) {
      out += String.fromCharCode(Number.parseInt(source.slice(i + 2, i + 4), 16)); i += 4; continue;
    }
    if (['\\', '{', '}'].includes(symbol)) { out += symbol; i += 2; continue; }
    if (symbol === '~' || symbol === '_') { out += symbol === '_' ? '-' : ' '; i += 2; continue; }
    if (!/[A-Za-z]/.test(symbol)) { i += 2; continue; }
    const control = readRtfControl(source, i + 1);
    i = control.next;
    if (control.word === 'uc' && control.arg !== null) ucSkip = Math.max(0, Math.min(16, control.arg));
    else if (control.word === 'u' && control.arg !== null) {
      out += String.fromCharCode(control.arg < 0 ? control.arg + 65536 : control.arg);
      i = skipRtfFallback(source, i, ucSkip);
    } else if (['par', 'line'].includes(control.word)) out += '\n';
    else if (control.word === 'tab') out += '\t';
  }
  if (out.includes('\0')) throw extractionError('nul byte in rtf');
  return out.replace(/[\t ]+/g, ' ').trim();
}

const RtfProcessor = {
  id: 'rtf',
  requiresIsolation: true,
  supports: (name) => ext(name) === '.rtf',
  extract: async (buf) => extractRtf(decodeTextBuffer(buf)),
};

function parseMimeHeaders(raw) {
  const normalized = String(raw).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const end = normalized.indexOf('\n\n');
  if (end < 0) {
    if (/^(?:MIME-Version|Content-Type|Content-Disposition|Content-Transfer-Encoding):/im.test(normalized)) {
      throw extractionError('malformed mime headers');
    }
    return { headers: new Map(), body: normalized, text: '' };
  }
  const block = normalized.slice(0, end);
  const unfolded = block.replace(/\n[ \t]+/g, ' ');
  const lines = unfolded.split('\n');
  if (lines.some((line) => line && !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+\s*:/.test(line))) {
    if (lines.some((line) => /^[!#$%&'*+.^_`|~0-9A-Za-z-]+\s*:/.test(line))) {
      throw extractionError('malformed mime headers');
    }
    return { headers: new Map(), body: normalized, text: '' };
  }
  if (lines.length > 200) throw extractionError('too many mime headers');
  const headers = new Map();
  for (const line of lines) {
    if (!line) continue;
    const colon = line.indexOf(':');
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    headers.set(key, headers.has(key) ? headers.get(key) + ', ' + value : value);
  }
  return { headers, body: normalized.slice(end + 2), text: block };
}

function mimeParam(value, name) {
  const match = String(value || '').match(new RegExp('(?:^|;)\\s*' + name + '\\s*=\\s*(?:"([^"]*)"|([^;\\s]*))', 'i'));
  return match ? (match[1] ?? match[2] ?? '') : '';
}

function decodeQuotedPrintable(value) {
  const input = String(value).replace(/=\n/g, '');
  const chunks = [];
  let start = 0;
  for (let i = 0; i < input.length; i += 1) {
    if (input[i] !== '=') continue;
    if (!/^[0-9a-f]{2}$/i.test(input.slice(i + 1, i + 3))) throw extractionError('invalid quoted-printable');
    if (i > start) chunks.push(Buffer.from(input.slice(start, i), 'utf8'));
    chunks.push(Buffer.from([Number.parseInt(input.slice(i + 1, i + 3), 16)]));
    i += 2;
    start = i + 1;
  }
  if (start < input.length) chunks.push(Buffer.from(input.slice(start), 'utf8'));
  return Buffer.concat(chunks);
}

function decodeBase64Strict(value) {
  const compact = String(value).replace(/\s+/g, '');
  if (!compact) return Buffer.alloc(0);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 === 1) throw extractionError('invalid mime base64');
  const padded = compact + '='.repeat((4 - (compact.length % 4)) % 4);
  const decoded = Buffer.from(padded, 'base64');
  if (decoded.toString('base64').replace(/=+$/, '') !== padded.replace(/=+$/, '')) throw extractionError('invalid mime base64');
  return decoded;
}

function decodeTransfer(body, encoding) {
  const normalized = String(encoding || '7bit').trim().toLowerCase();
  if (normalized === 'quoted-printable') return decodeQuotedPrintable(body);
  if (normalized === 'base64') return decodeBase64Strict(body);
  if (['7bit', '8bit', 'binary', ''].includes(normalized)) return Buffer.from(body, 'utf8');
  throw extractionError('unsupported content-transfer-encoding');
}

function decodeEncodedWords(value) {
  const joined = String(value || '').replace(/(\?=)[ \t\r\n]+(?==\?)/g, '$1');
  return joined.replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (_all, charset, kind, payload) => {
    const bytes = kind.toLowerCase() === 'b' ? decodeBase64Strict(payload) : decodeQuotedPrintable(payload.replace(/_/g, ' '));
    return decodeTextBuffer(bytes, charset);
  });
}

function splitMultipart(body, boundary) {
  if (!boundary || boundary.length > 70 || /[\r\n]/.test(boundary)) throw extractionError('invalid mime boundary');
  const marker = '--' + boundary;
  const parts = [];
  const preamble = [];
  const epilogue = [];
  let current = null;
  let closed = false;
  for (const line of String(body).replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')) {
    if (line === marker || line === marker + '--') {
      if (current) parts.push(current.join('\n'));
      current = line.endsWith('--') ? null : [];
      if (line.endsWith('--')) closed = true;
    } else if (current) current.push(line);
    else (closed ? epilogue : preamble).push(line);
  }
  if (!closed || !parts.length) throw extractionError('malformed mime multipart');
  return { parts, preamble: preamble.join('\n'), epilogue: epilogue.join('\n') };
}

function mimeHeaderText(parsed) {
  const values = [];
  for (const [key, value] of parsed.headers) values.push(key + ' ' + decodeEncodedWords(value));
  return values.join('\n');
}

function extractMimeTextPart(type, bytes, charset) {
  const decoded = decodeTextBuffer(bytes, charset);
  if (type === 'text/html' || type === 'text/xml') {
    rejectMarkupDeclarations(decoded);
    if (type === 'text/html') rejectOpaqueHtml(decoded);
    return stripXml(decoded);
  }
  if (type === 'text/rtf') return extractRtf(decoded);
  return decoded;
}

function extractMimeEntity(raw, state, depth = 0) {
  if (depth > MIME_DEPTH_MAX || ++state.parts > MIME_PARTS_MAX) throw extractionError('mime nesting limit exceeded');
  const parsed = parseMimeHeaders(raw);
  const contentType = parsed.headers.get('content-type') || 'text/plain';
  const type = contentType.split(';', 1)[0].trim().toLowerCase();
  const headers = mimeHeaderText(parsed);
  if (type.startsWith('multipart/')) {
    const split = splitMultipart(parsed.body, mimeParam(contentType, 'boundary'));
    const children = split.parts.map((part) => extractMimeEntity(part, state, depth + 1));
    return [headers, split.preamble, ...children, children.join(''), split.epilogue].filter(Boolean).join('\n');
  }
  const bytes = decodeTransfer(parsed.body, parsed.headers.get('content-transfer-encoding'));
  if (type === 'message/rfc822') return [headers, extractMimeEntity(decodeTextBuffer(bytes), state, depth + 1)].join('\n');
  if (!type.startsWith('text/')) throw extractionError('opaque mime attachment');
  const charset = mimeParam(contentType, 'charset');
  return [headers, extractMimeTextPart(type, bytes, charset)].filter(Boolean).join('\n');
}

const EmailProcessor = {
  id: 'email',
  requiresIsolation: true,
  supports: (name) => ext(name) === '.eml',
  extract: async (buf) => extractMimeEntity(decodeTextBuffer(buf), { parts: 0 }),
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

const PROCESSORS = [JsonProcessor, MarkupProcessor, RtfProcessor, EmailProcessor,
  TextProcessor, OfficeProcessor, PdfProcessor, OcrRequiredProcessor];

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
  try { validateFormat(p, buf); } catch (error) {
    return {
      text: '',
      processor: p.id,
      supported: true,
      extractionOk: false,
      error: error && error.code === 'FORMAT_MISMATCH' ? 'format_mismatch' : 'extract_failed',
    };
  }
  const inParseChild = process.env.REDACTWALL_PARSE_CHILD === '1' && typeof process.send === 'function' && !!process.channel;
  if (p.requiresIsolation && !inParseChild) {
    // Preserve the public processors.extractText contract while ensuring a
    // caller cannot accidentally run a synchronous rich parser on its event
    // loop. Lazy loading avoids the processors <-> parse-pool module cycle.
    return require('./parse-pool').extractText(name, buf, opts);
  }
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
    const raw = await withTimeout(Promise.resolve().then(() => p.extract(buf, opts, name)), timeoutMs(opts));
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
  _internal: { decodeTextBuffer, decodeMarkupEntities, stripXml, extractRtf, extractMimeEntity, sniffFormat },
};
