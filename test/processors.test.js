'use strict';
/** File extraction safety: bounded processors and fail-closed scan-file handling. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const Module = require('node:module');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-processors-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-processors-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

function setPolicy(patch = {}) {
  fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 20,
    storeRawForApproval: true,
    ...patch,
  }, null, 2));
}

setPolicy();

const processors = require('../server/processors');
const parsePool = require('../server/parse-pool');
const app = require('../server/app');
const { listen } = require('./support/listen');

async function withFakePdfParse(fakeModule, fn) {
  const originalLoad = Module._load;
  Module._load = function patchedLoad(request, parent, isMain) {
    if (request === 'pdf-parse') return fakeModule;
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return await fn();
  } finally {
    Module._load = originalLoad;
  }
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
  }
}

async function scanFile(port, filename, text) {
  return scanFileBuffer(port, filename, Buffer.from(text));
}

async function scanFileBuffer(port, filename, content) {
  return fetch(`http://127.0.0.1:${port}/api/v1/scan-file`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      filename,
      contentBase64: content.toString('base64'),
      user: 'analyst@example.test',
      destination: 'desktop-ai-app',
    }),
  });
}

function officeZipWithCorruptContentEntry() {
  const AdmZip = require('adm-zip');
  const zip = new AdmZip();
  zip.addFile('word/document.xml', Buffer.from('<w:t>ordinary visible text</w:t>'));
  zip.addFile('word/comments.xml', Buffer.from('<w:t>SSN 524-71-9043</w:t>'));
  const original = zip.toBuffer();
  const parsed = new AdmZip(original);
  const corrupt = parsed.getEntry('word/comments.xml');
  corrupt.getCompressedData();
  const result = Buffer.from(original);
  result[corrupt.header.realDataOffset + Math.floor(corrupt.header.compressedSize / 2)] ^= 0xff;
  return result;
}

function officeZip(parts) {
  const AdmZip = require('adm-zip');
  const zip = new AdmZip();
  for (const [name, content] of Object.entries(parts)) zip.addFile(name, Buffer.isBuffer(content) ? content : Buffer.from(content));
  return zip.toBuffer();
}

function minimalPdf({
  withImage = false,
  catalogExtra = '',
  pageExtra = '',
  contentExtra = '',
  extraObjects = [],
  trailerExtra = '',
} = {}) {
  const objects = new Map();
  const add = (number, body) => objects.set(number, Buffer.concat([
    Buffer.from(`${number} 0 obj\n`), Buffer.isBuffer(body) ? body : Buffer.from(body), Buffer.from('\nendobj\n'),
  ]));
  add(1, `<< /Type /Catalog /Pages 2 0 R ${catalogExtra} >>`);
  add(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
  const resources = withImage
    ? '<< /Font << /F1 5 0 R >> /XObject << /Im1 6 0 R >> >>'
    : '<< /Font << /F1 5 0 R >> >>';
  add(3, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources ${resources} /Contents 4 0 R ${pageExtra} >>`);
  const content = Buffer.from('BT /F1 12 Tf 72 720 Td (Visible quarterly report) Tj ET' +
    (withImage ? '\nq 20 0 0 20 72 680 cm /Im1 Do Q' : '') + contentExtra);
  add(4, Buffer.concat([Buffer.from(`<< /Length ${content.length} >>\nstream\n`), content, Buffer.from('\nendstream')]));
  add(5, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  if (withImage) {
    const pixels = Buffer.from([255, 255, 255]);
    add(6, Buffer.concat([
      Buffer.from(`<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length ${pixels.length} >>\nstream\n`),
      pixels, Buffer.from('\nendstream'),
    ]));
  }
  for (const [number, body] of extraObjects) add(number, body);
  const header = Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n', 'binary');
  const offsets = new Map();
  let position = header.length;
  const ordered = [...objects.entries()].sort(([left], [right]) => left - right);
  for (const [number, object] of ordered) { offsets.set(number, position); position += object.length; }
  const maxObject = Math.max(...objects.keys());
  let xref = `xref\n0 ${maxObject + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= maxObject; i += 1) {
    xref += offsets.has(i)
      ? `${String(offsets.get(i)).padStart(10, '0')} 00000 n \n`
      : '0000000000 00000 f \n';
  }
  const trailer = `trailer\n<< /Size ${maxObject + 1} /Root 1 0 R ${trailerExtra} >>\nstartxref\n${position}\n%%EOF\n`;
  return Buffer.concat([header, ...ordered.map(([, object]) => object), Buffer.from(xref + trailer)]);
}

function pdfStream(value, dictionary = '') {
  const content = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return Buffer.concat([
    Buffer.from(`<< ${dictionary} /Length ${content.length} >>\nstream\n`),
    content,
    Buffer.from('\nendstream'),
  ]);
}

function utf16be(value, bom = true) {
  const bytes = Buffer.from(value, 'utf16le');
  for (let i = 0; i < bytes.length; i += 2) [bytes[i], bytes[i + 1]] = [bytes[i + 1], bytes[i]];
  return bom ? Buffer.concat([Buffer.from([0xfe, 0xff]), bytes]) : bytes;
}

test('corrupt supported office files report extraction failure', async () => {
  const result = await processors.extractText('member-loan.docx', Buffer.from('not a zip archive'));

  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'office');
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'extract_failed');
  assert.strictEqual(result.text, '');
});

test('a corrupt content entry fails the complete office extraction closed', async () => {
  const result = await parsePool.extractText('partial-member-loan.docx', officeZipWithCorruptContentEntry());

  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'office');
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'extract_failed');
  assert.strictEqual(result.text, '');
});

test('image files return ocr_required without attempting text extraction', async () => {
  const result = await processors.extractText('loan-scan.png', Buffer.from('pretend image bytes with SSN 524-71-9043'));

  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'ocr_required');
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'ocr_required');
  assert.strictEqual(result.ocrRequired, true);
  assert.strictEqual(result.text, '');
});

test('unsupported files fail closed with typed extraction metadata', async () => {
  const result = await processors.extractText('archive.bin', Buffer.from('SSN 524-71-9043'));

  assert.strictEqual(processors.supported('archive.bin'), false);
  assert.strictEqual(result.supported, false);
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'unsupported');
  assert.strictEqual(result.processor, null);
  assert.strictEqual(result.text, '');
});

test('office processor extracts visible document text from zip XML parts', async () => {
  const AdmZip = require('adm-zip');
  const zip = new AdmZip();
  zip.addFile('word/document.xml', Buffer.from('<w:t>Member &amp; loan SSN 524-71-9043</w:t>'));
  zip.addFile('docProps/core.xml', Buffer.from('<dc:title>package metadata</dc:title>'));

  const result = await parsePool.extractText('member-loan.docx', zip.toBuffer());

  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'office');
  assert.strictEqual(result.extractionOk, true);
  assert.match(result.text, /Member & loan SSN 524-71-9043/);
  assert.match(result.text, /package metadata/, 'textual metadata is scanned too');
});

test('OOXML renamed as plain text fails closed on its ZIP signature', async () => {
  const disguised = officeZip({ 'word/document.xml': '<w:t>SSN 524-71-9043</w:t>' });
  const result = await processors.extractText('innocent.txt', disguised);

  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'text');
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'format_mismatch');
  assert.strictEqual(result.text, '');
});

test('OOXML scans numeric entities and every textual package member', async () => {
  const doc = officeZip({
    'word/document.xml': '<w:document><w:t>visible cover</w:t></w:document>',
    'customXml/item1.xml': '<member>SSN &#53;&#50;&#52;-&#x37;&#x31;-&#57;&#48;&#52;&#51;</member>',
  });
  const result = await parsePool.extractText('member.docx', doc);

  assert.strictEqual(result.extractionOk, true);
  assert.match(result.text, /524-71-9043/);
});

test('Word, Excel, and PowerPoint OOXML families all scan their visible XML', async () => {
  const cases = [
    ['member.docx', 'word/document.xml', '<w:t>SSN 524-71-9043</w:t>'],
    ['member.xlsx', 'xl/worksheets/sheet1.xml', '<c><v>SSN 524-71-9043</v></c>'],
    ['member.pptx', 'ppt/slides/slide1.xml', '<a:t>SSN 524-71-9043</a:t>'],
  ];
  for (const [name, entry, xml] of cases) {
    const result = await parsePool.extractText(name, officeZip({ [entry]: xml }));
    assert.strictEqual(result.extractionOk, true, name);
    assert.match(result.text, /524-71-9043/, name);
  }
});

test('OOXML with embedded media or objects fails closed instead of scanning only visible text', async () => {
  for (const opaqueName of ['word/media/member.png', 'word/embeddings/member.bin']) {
    const doc = officeZip({
      'word/document.xml': '<w:t>ordinary cover text</w:t>',
      [opaqueName]: Buffer.from('opaque member SSN 524-71-9043'),
    });
    const result = await parsePool.extractText('member.docx', doc);
    assert.strictEqual(result.extractionOk, false, opaqueName);
    assert.strictEqual(result.error, 'extract_failed', opaqueName);
    assert.strictEqual(result.text, '', opaqueName);
  }
});

test('plain text decoding is strict and supports UTF-8, UTF-16LE, and UTF-16BE', async () => {
  const secret = 'Member SSN 524-71-9043';
  const cases = [
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(secret)]),
    Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(secret, 'utf16le')]),
    utf16be(secret),
    Buffer.from(secret, 'utf16le'),
    utf16be(secret, false),
  ];
  for (const buf of cases) {
    const result = await processors.extractText('member.txt', buf);
    assert.strictEqual(result.extractionOk, true);
    assert.strictEqual(result.text, secret);
  }

  const invalid = await processors.extractText('member.txt', Buffer.from([0xc3, 0x28]));
  assert.strictEqual(invalid.extractionOk, false);
  assert.strictEqual(invalid.error, 'extract_failed');
});

test('markup and JSON decoding reconstruct numeric entities and unicode escapes', async () => {
  const xml = await parsePool.extractText('member.xml', Buffer.from('<member>SSN &#53;&#50;&#52;-&#x37;&#x31;-&#57;&#48;&#52;&#51;</member>'));
  assert.strictEqual(xml.extractionOk, true);
  assert.match(xml.text, /524-71-9043/);

  const json = await parsePool.extractText('member.json', Buffer.from('{"member":"\\u0035\\u0032\\u0034-\\u0037\\u0031-\\u0039\\u0030\\u0034\\u0033"}'));
  assert.strictEqual(json.extractionOk, true);
  assert.match(json.text, /524-71-9043/);

  const duplicate = await parsePool.extractText('duplicate.json', Buffer.from('{"member":"\\u0035\\u0032\\u0034-71-9043","member":"safe"}'));
  assert.strictEqual(duplicate.extractionOk, true);
  assert.match(duplicate.text, /524-71-9043/, 'overwritten duplicate values remain in the scan text');

  const unsafeEntity = await parsePool.extractText('unsafe.xml', Buffer.from('<member>524&#0;-71-9043</member>'));
  assert.strictEqual(unsafeEntity.extractionOk, false);
  assert.strictEqual(unsafeEntity.error, 'extract_failed');

  const html = await parsePool.extractText('member.html', Buffer.from('<p>SSN &#53&#50&#52-&#55&#49-9043</p>'));
  assert.strictEqual(html.extractionOk, true);
  assert.match(html.text, /524-71-9043/, 'semicolon-free HTML numeric entities are decoded');

  const entityDeclaration = await parsePool.extractText('entity.xml', Buffer.from('<!DOCTYPE x [<!ENTITY member "524-71-9043">]><x>&member;</x>'));
  assert.strictEqual(entityDeclaration.extractionOk, false);
  assert.strictEqual(entityDeclaration.error, 'extract_failed');
});

test('standalone HTML rejects active and opaque embedded content but keeps static text useful', async () => {
  const unsafe = [
    '<p>Quarterly report</p><script>const member=[524,71,9043].join("-")</script>',
    '<p>Quarterly report</p><img src="d&#97;ta&#58;image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB">',
    '<p>Quarterly report</p><object data="member-record.bin"></object>',
    '<p onclick="sendMember()">Quarterly report</p>',
    '<style>body{background:url(d\\61 ta:image/png;base64,AAAA)}</style><p>Quarterly report</p>',
  ];
  for (const [index, html] of unsafe.entries()) {
    const result = await parsePool.extractText(`unsafe-${index}.html`, Buffer.from(html));
    assert.strictEqual(result.extractionOk, false, html);
    assert.strictEqual(result.error, 'extract_failed', html);
    assert.strictEqual(result.text, '', html);
  }

  const benign = await parsePool.extractText('quarterly.html', Buffer.from(
    '<!doctype html><html><head><style>body { color: #123; }</style></head>' +
    '<body><h1>Quarterly report</h1><p>No regulated data.</p></body></html>',
  ));
  assert.strictEqual(benign.extractionOk, true);
  assert.match(benign.text, /Quarterly report/);
  assert.match(benign.text, /No regulated data/);
});

test('RTF unicode and hex escapes are reconstructed while opaque objects fail closed', async () => {
  const hex = await parsePool.extractText('member.rtf', Buffer.from(String.raw`{\rtf1\ansi Member SSN \'35\'32\'34-\'37\'31-\'39\'30\'34\'33}`));
  assert.strictEqual(hex.extractionOk, true);
  assert.match(hex.text, /524-71-9043/);

  const unicode = await parsePool.extractText('member.rtf', Buffer.from(String.raw`{\rtf1\ansi Member SSN \u53?\u50?\u52?-\u55?\u49?-\u57?\u48?\u52?\u51?}`));
  assert.strictEqual(unicode.extractionOk, true);
  assert.match(unicode.text, /524-71-9043/);

  const opaque = await parsePool.extractText('member.rtf', Buffer.from(String.raw`{\rtf1\ansi ordinary text {\pict 3532342d37312d39303433}}`));
  assert.strictEqual(opaque.extractionOk, false);
  assert.strictEqual(opaque.error, 'extract_failed');
});

test('EML recursively decodes multipart quoted-printable text and rejects binary attachments', async () => {
  const eml = [
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="member-boundary"',
    '',
    '--member-boundary',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Member SSN =35=32=34-71-9043',
    '--member-boundary',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Member SSN &#53;&#50;&#52;-&#55;&#49;-9043</p>',
    '--member-boundary--',
    '',
  ].join('\r\n');
  const result = await parsePool.extractText('member.eml', Buffer.from(eml));
  assert.strictEqual(result.extractionOk, true);
  assert.match(result.text, /524-71-9043/);

  const withAttachment = eml.replace('multipart/alternative', 'multipart/mixed').replace(
    '--member-boundary--',
    '--member-boundary\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n' +
      Buffer.from('SSN 524-71-9043').toString('base64') + '\r\n--member-boundary--',
  );
  const blocked = await parsePool.extractText('attachment.eml', Buffer.from(withAttachment));
  assert.strictEqual(blocked.extractionOk, false);
  assert.strictEqual(blocked.error, 'extract_failed');
  assert.strictEqual(blocked.text, '');
});

test('mail signatures prevent RFC 2047 EML content from being smuggled through a text extension', async () => {
  const disguised = [
    'From: sender@example.test',
    'Subject: =?UTF-8?Q?SSN_=35=32=34-71-9043?=',
    '',
    'ordinary body',
  ].join('\r\n');
  const result = await processors.extractText('message.txt', Buffer.from(disguised));
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'format_mismatch');

  const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(disguised, 'utf16le')]);
  const encodedResult = await processors.extractText('message.txt', utf16);
  assert.strictEqual(encodedResult.extractionOk, false);
  assert.strictEqual(encodedResult.error, 'format_mismatch');
});

test('EML decodes adjacent RFC 2047 header words before scanning', async () => {
  const eml = [
    'From: sender@example.test',
    'Subject: =?UTF-8?Q?SSN_=35=32?= =?UTF-8?Q?=34-71-9043?=',
    '',
    'ordinary body',
  ].join('\r\n');
  const result = await parsePool.extractText('message.eml', Buffer.from(eml));
  assert.strictEqual(result.extractionOk, true);
  assert.match(result.text, /SSN 524-71-9043/);

  const malformed = await parsePool.extractText('malformed.eml', Buffer.from(
    'Content-Transfer-Encoding: quoted-printable\r\nmalformed-header\r\n\r\nSSN =35=32=34-71-9043',
  ));
  assert.strictEqual(malformed.extractionOk, false);
  assert.strictEqual(malformed.error, 'extract_failed');
});

test('pdf processor requires the v2 image-inspection API and destroys parser state', async () => {
  const pdf = processors.PROCESSORS.find((processor) => processor.id === 'pdf');
  let destroyed = false;
  await withFakePdfParse({
    PDFParse: class FakePDFParse {
      constructor(opts) {
        assert.ok(Buffer.isBuffer(opts.data));
      }
      async getText() {
        return { text: 'PDF v2 member SSN 524-71-9043' };
      }
      async load() {
        return {
          numPages: 1,
          getAttachments: async () => null,
          getJSActions: async () => null,
          getOpenAction: async () => null,
          getFieldObjects: async () => null,
          getMetadata: async () => ({ info: {}, metadata: null }),
          getOutline: async () => null,
          getPage: async () => ({
            getOperatorList: async () => ({ fnArray: [] }),
            getAnnotations: async () => [],
            getJSActions: async () => null,
            cleanup() {},
          }),
        };
      }
      async destroy() { destroyed = true; }
    },
  }, async () => {
    const text = await pdf.extract(minimalPdf());
    assert.strictEqual(text, 'PDF v2 member SSN 524-71-9043');
    assert.strictEqual(destroyed, true);
  });

  await withFakePdfParse(async (buf) => {
    assert.ok(Buffer.isBuffer(buf));
    return { text: 'PDF v1 member SSN 524-71-9043' };
  }, async () => {
    await assert.rejects(() => pdf.extract(minimalPdf()), (error) => {
      assert.strictEqual(error.code, 'EXTRACT_FAILED');
      return true;
    });
  });
});

test('mixed text and raster PDF is held for OCR while text-only PDF remains extractable', async () => {
  const mixed = await parsePool.extractText('mixed.pdf', minimalPdf({ withImage: true }));
  assert.strictEqual(mixed.extractionOk, false);
  assert.strictEqual(mixed.error, 'ocr_required');
  assert.strictEqual(mixed.ocrRequired, true);
  assert.strictEqual(mixed.text, '');

  const textOnly = await parsePool.extractText('text-only.pdf', minimalPdf());
  assert.strictEqual(textOnly.extractionOk, true);
  assert.match(textOnly.text, /Visible quarterly report/);
});

test('PDF attachments, JavaScript, and XFA fail closed instead of scanning only page text', async () => {
  const secret = 'Member SSN 524-71-9043';
  const cases = [
    ['catalog attachment', minimalPdf({
      catalogExtra: '/Names << /EmbeddedFiles << /Names [(member.txt) 7 0 R] >> >>',
      extraObjects: [
        [7, '<< /Type /Filespec /F (member.txt) /EF << /F 8 0 R >> >>'],
        [8, pdfStream(secret, '/Type /EmbeddedFile')],
      ],
    })],
    ['annotation attachment', minimalPdf({
      pageExtra: '/Annots [7 0 R]',
      extraObjects: [
        [7, '<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] /FS 8 0 R >>'],
        [8, '<< /Type /Filespec /F (member.txt) /EF << /F 9 0 R >> >>'],
        [9, pdfStream(secret, '/Type /EmbeddedFile')],
      ],
    })],
    ['JavaScript name tree', minimalPdf({
      catalogExtra: '/Names << /JavaScript << /Names [(member-action) 7 0 R] >> >>',
      extraObjects: [[7, `<< /S /JavaScript /JS (${secret}) >>`]],
    })],
    ['XFA form', minimalPdf({
      catalogExtra: '/AcroForm 7 0 R',
      extraObjects: [
        [7, '<< /Fields [] /XFA 8 0 R >>'],
        [8, pdfStream(`<template><field>${secret}</field></template>`)],
      ],
    })],
  ];

  for (const [label, content] of cases) {
    const result = await parsePool.extractText(`${label.replace(/\s+/g, '-')}.pdf`, content);
    assert.strictEqual(result.extractionOk, false, label);
    assert.strictEqual(result.error, 'extract_failed', label);
    assert.strictEqual(result.text, '', label);
  }
});

test('PDF annotations, form values, metadata, and outlines are included in scanned text', async () => {
  const secret = 'Member SSN 524-71-9043';
  const cases = [
    ['text annotation', minimalPdf({
      pageExtra: '/Annots [7 0 R]',
      extraObjects: [[7, `<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (${secret}) >>`]],
    })],
    ['AcroForm value', minimalPdf({
      catalogExtra: '/AcroForm << /Fields [7 0 R] >>',
      pageExtra: '/Annots [7 0 R]',
      extraObjects: [[7, `<< /Type /Annot /Subtype /Widget /FT /Tx /T (member) /V (${secret}) /Rect [0 0 10 10] /P 3 0 R >>`]],
    })],
    ['Info dictionary', minimalPdf({
      trailerExtra: '/Info 7 0 R',
      extraObjects: [[7, `<< /Subject (${secret}) >>`]],
    })],
    ['XMP metadata', minimalPdf({
      catalogExtra: '/Metadata 7 0 R',
      extraObjects: [[7, pdfStream(
        `<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description>${secret}</rdf:Description></rdf:RDF></x:xmpmeta>`,
        '/Type /Metadata /Subtype /XML',
      )]],
    })],
    ['outline title', minimalPdf({
      catalogExtra: '/Outlines 7 0 R',
      extraObjects: [
        [7, '<< /Type /Outlines /First 8 0 R /Last 8 0 R /Count 1 >>'],
        [8, `<< /Title (${secret}) /Parent 7 0 R >>`],
      ],
    })],
  ];

  for (const [label, content] of cases) {
    const result = await parsePool.extractText(`${label.replace(/\s+/g, '-')}.pdf`, content);
    assert.strictEqual(result.extractionOk, true, `${label}: ${JSON.stringify(result)}`);
    assert.match(result.text, /524-71-9043/, label);
  }
});

test('vector-rendered PDF content requires OCR and trailing payload bytes fail closed', async () => {
  const vector = await parsePool.extractText('vector-member.pdf', minimalPdf({
    contentExtra: '\n0 0 m 50 0 l 50 50 l 0 50 l h S',
  }));
  assert.strictEqual(vector.extractionOk, false);
  assert.strictEqual(vector.error, 'ocr_required');
  assert.strictEqual(vector.ocrRequired, true);

  const secret = Buffer.from('Member SSN 524-71-9043');
  for (const content of [
    Buffer.concat([minimalPdf(), secret]),
    Buffer.concat([minimalPdf(), secret, Buffer.from('\nstartxref\n0\n%%EOF\n')]),
  ]) {
    const result = await parsePool.extractText('trailing-member.pdf', content);
    assert.strictEqual(result.extractionOk, false);
    assert.strictEqual(result.error, 'extract_failed');
    assert.strictEqual(result.text, '');
  }
});

test('pdf processor converts parser failures to typed extraction errors', async () => {
  const pdf = processors.PROCESSORS.find((processor) => processor.id === 'pdf');
  await withFakePdfParse({
    PDFParse: class BrokenPDFParse {
      async load() { throw new Error('parse failed'); }
      async destroy() {}
      async getText() { return { text: 'must not run' }; }
    },
  }, async () => {
    await assert.rejects(() => pdf.extract(minimalPdf()), (error) => {
      assert.strictEqual(error.code, 'EXTRACT_FAILED');
      return true;
    });
  });
});

test('ocr-required processor throws a typed error when called directly', async () => {
  const ocr = processors.PROCESSORS.find((processor) => processor.id === 'ocr_required');

  await assert.rejects(() => ocr.extract(), (err) => {
    assert.strictEqual(err.code, 'OCR_REQUIRED');
    return true;
  });
});

test('slow processors time out with a typed extraction error', async (t) => {
  const slow = {
    id: 'slow-test',
    supports: (name) => String(name).endsWith('.slow'),
    extract: () => new Promise((resolve) => setTimeout(() => resolve('late text'), 150)),
  };
  processors.PROCESSORS.unshift(slow);
  t.after(() => {
    const idx = processors.PROCESSORS.indexOf(slow);
    if (idx >= 0) processors.PROCESSORS.splice(idx, 1);
  });

  const result = await processors.extractText('demo.slow', Buffer.from(''), { timeoutMs: 100, maxTextChars: 1000 });

  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'slow-test');
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'timeout');
});

test('oversized extracted text fails closed instead of scanning a truncated window', async () => {
  const raw = 'x'.repeat(1000) + ' Member SSN 524-71-9043';
  const result = await processors.extractText('large.txt', Buffer.from(raw), { maxTextChars: 1000 });

  // The tail (holding the SSN) is past the scan window, so a truncated scan
  // would clear regulated PII to send. Truncation must fail closed instead.
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'truncated');
  assert.strictEqual(result.truncated, true);
  assert.strictEqual(result.text, '');
});

test('text within the scan window is not marked truncated', async () => {
  const raw = 'Member SSN 524-71-9043';
  const result = await processors.extractText('small.txt', Buffer.from(raw), { maxTextChars: 1000 });

  assert.strictEqual(result.extractionOk, true);
  assert.strictEqual(result.truncated, false);
  assert.strictEqual(result.text, raw);
});

test('scan-file holds a file whose PII sits past the extraction window', async () => withServer(async (port) => {
  setPolicy();
  const secret = '524-71-9043';
  // Pad past the default 1,000,000-char extraction window, then place the SSN in
  // the unscanned tail. The upload is under maxFileBytes, so without fail-closed
  // truncation handling it would extract a clean window and be allowed to send.
  const fileText = 'a'.repeat(1000050) + ' Member SSN ' + secret;
  const res = await scanFile(port, 'padded-loan.txt', fileText);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'file_blocked_unscanned');
  assert.strictEqual(body.supported, true);
  assert.strictEqual(body.inspected, false);
  assert.ok(!JSON.stringify(body).includes(secret));
}));

test('scan-file blocks OOXML renamed as text before any partial text scan', async () => withServer(async (port) => {
  setPolicy();
  const disguised = officeZip({ 'word/document.xml': '<w:t>Member SSN 524-71-9043</w:t>' });
  const res = await scanFileBuffer(port, 'quarterly-report.txt', disguised);
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'file_blocked_unscanned');
  assert.strictEqual(body.inspected, false);
  assert.strictEqual(body.processor, 'text');
  assert.ok(!JSON.stringify(body).includes(disguised.toString('base64')));
}));

test('scan-file detects PII decoded from UTF-16BE text', async () => withServer(async (port) => {
  setPolicy();
  const res = await scanFileBuffer(port, 'member.txt', utf16be('Member SSN 524-71-9043'));
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.ok(body.findings.some((finding) => finding.type === 'US_SSN'));
  assert.ok(!JSON.stringify(body).includes('524-71-9043'));
}));

test('scan-file blocks PII found only in PDF metadata without echoing it', async () => withServer(async (port) => {
  setPolicy();
  const content = minimalPdf({
    trailerExtra: '/Info 7 0 R',
    extraObjects: [[7, '<< /Subject (Member SSN 524-71-9043) >>']],
  });
  const res = await scanFileBuffer(port, 'quarterly-report.pdf', content);
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.ok(body.findings.some((finding) => finding.type === 'US_SSN'));
  assert.ok(!JSON.stringify(body).includes('524-71-9043'));
}));

test('scan-file blocks partially corrupt Office files without echoing file bytes', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const contentBase64 = officeZipWithCorruptContentEntry().toString('base64');
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/scan-file`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      filename: 'member-loan.docx',
      contentBase64,
      user: 'analyst@example.test',
      destination: 'desktop-ai-app',
    }),
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'file_blocked_unscanned');
  assert.strictEqual(body.supported, true);
  assert.strictEqual(body.inspected, false);
  assert.strictEqual(body.processor, 'office');
  assert.ok(!JSON.stringify(body).includes(secret));
  assert.ok(!JSON.stringify(body).includes(contentBase64));
}));

test('scan-file blocks image uploads as ocr_required without echoing file bytes', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const contentBase64 = Buffer.from('pretend image bytes with member SSN ' + secret).toString('base64');
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/scan-file`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      filename: 'member-loan-scan.png',
      contentBase64,
      user: 'analyst@example.test',
      destination: 'desktop-ai-app',
    }),
  });

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.status, 'ocr_required');
  assert.strictEqual(body.supported, true);
  assert.strictEqual(body.inspected, false);
  assert.strictEqual(body.processor, 'ocr_required');
  assert.strictEqual(body.ocrRequired, true);
  assert.ok(!JSON.stringify(body).includes(secret));
  assert.ok(!JSON.stringify(body).includes(contentBase64));
}));

test('scan-file redacts structured findings under redact policy', async () => withServer(async (port) => {
  setPolicy({ enforcementMode: 'redact' });
  const secret = '524-71-9043';
  const fileText = 'Loan file. Member SSN ' + secret + ' is pending review.';
  const res = await scanFile(port, 'member-loan.txt', fileText);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'redact');
  assert.strictEqual(body.mode, 'redact');
  assert.strictEqual(body.status, 'redacted');
  assert.strictEqual(body.supported, true);
  assert.match(body.tokenizedPrompt, /\[\[US_SSN_1\]\]/);
  assert.match(body.releaseToken, /^[A-Za-z0-9_-]{32,}$/);
  assert.ok(!JSON.stringify(body).includes(secret));
  assert.ok(!JSON.stringify(body).includes(Buffer.from(fileText).toString('base64')));

  const noToken = await fetch(`http://127.0.0.1:${port}/api/v1/rehydrate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({ id: body.id, text: 'Reviewed [[US_SSN_1]].' }),
  });
  assert.strictEqual(noToken.status, 401);

  const rehydrate = await fetch(`http://127.0.0.1:${port}/api/v1/rehydrate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
      'x-release-token': body.releaseToken,
    },
    body: JSON.stringify({ id: body.id, text: 'Reviewed [[US_SSN_1]].' }),
  });
  assert.strictEqual(rehydrate.status, 200);
  const opened = await rehydrate.json();
  assert.strictEqual(opened.rehydrated, true);
  assert.strictEqual(opened.text, 'Reviewed ' + secret + '.');
}));

test('scan-file holds category-only findings under redact policy', async () => withServer(async (port) => {
  setPolicy({ enforcementMode: 'redact' });
  const confidential = 'Strictly confidential: our largest commercial relationship is about to walk; draft retention options before the board hears.';
  const res = await scanFile(port, 'board-retention-plan.txt', confidential);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.mode, 'redact');
  assert.strictEqual(body.status, 'pending');
  assert.ok(body.categories.includes('CONFIDENTIAL_BUSINESS'));
  assert.strictEqual(body.tokenizedPrompt, undefined);
  assert.ok(!JSON.stringify(body).includes(confidential));
}));

test('scan-file holds mixed structured and semantic findings under redact policy', async () => withServer(async (port) => {
  setPolicy({ enforcementMode: 'redact' });
  const secret = '524-71-9043';
  const confidential = 'Strictly confidential: our largest commercial relationship is about to walk; draft retention options before the board hears. Member SSN ' + secret + '.';
  const res = await scanFile(port, 'board-member-risk.txt', confidential);

  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'block');
  assert.strictEqual(body.mode, 'redact');
  assert.strictEqual(body.status, 'pending');
  assert.ok(body.findings.some((f) => f.type === 'US_SSN'));
  assert.ok(body.categories.includes('CONFIDENTIAL_BUSINESS'));
  assert.strictEqual(body.tokenizedPrompt, undefined);
  assert.ok(!JSON.stringify(body).includes(secret));
  assert.ok(!JSON.stringify(body).includes(confidential));
}));

test.after(() => {
  parsePool.shutdown();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.REDACTWALL_POLICY_PATH); } catch {}
});
