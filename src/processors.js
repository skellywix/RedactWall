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
const path = require('path');

const TEXT_EXT = new Set(['.txt', '.csv', '.tsv', '.json', '.yaml', '.yml', '.xml', '.html', '.htm',
  '.md', '.log', '.js', '.ts', '.py', '.java', '.sql', '.env', '.ini', '.conf', '.rtf', '.eml']);
const OFFICE_EXT = new Set(['.docx', '.xlsx', '.pptx']);
const PDF_EXT = new Set(['.pdf']);

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
  supports: (name) => OFFICE_EXT.has(ext(name)),
  extract: async (buf) => {
    const AdmZip = require('adm-zip');
    let zip;
    try { zip = new AdmZip(buf); } catch { return ''; }
    const parts = [];
    for (const entry of zip.getEntries()) {
      const n = entry.entryName;
      // Document body XML parts that carry visible text.
      if (/^word\/(document|header\d*|footer\d*)\.xml$/.test(n) ||
          /^xl\/sharedStrings\.xml$/.test(n) ||
          /^xl\/worksheets\/sheet\d+\.xml$/.test(n) ||
          /^ppt\/slides\/slide\d+\.xml$/.test(n) ||
          /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(n)) {
        try { parts.push(stripXml(entry.getData().toString('utf8'))); } catch {}
      }
    }
    return parts.join('\n');
  },
};

const PdfProcessor = {
  id: 'pdf',
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
    } catch (e) { return ''; }
  },
};

const PROCESSORS = [TextProcessor, OfficeProcessor, PdfProcessor];

function supported(name) { return PROCESSORS.some((p) => p.supports(name)); }

/** Extract text from a file buffer. Returns { text, processor, supported }. */
async function extractText(name, buf) {
  const p = PROCESSORS.find((x) => x.supports(name));
  if (!p) return { text: '', processor: null, supported: false };
  const text = await p.extract(buf);
  return { text: text || '', processor: p.id, supported: true };
}

module.exports = { extractText, supported, PROCESSORS, TEXT_EXT, OFFICE_EXT, PDF_EXT };
