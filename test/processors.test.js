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
  return fetch(`http://127.0.0.1:${port}/api/v1/scan-file`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': 'unit-ingest-key',
    },
    body: JSON.stringify({
      filename,
      contentBase64: Buffer.from(text).toString('base64'),
      user: 'analyst@example.test',
      destination: 'desktop-ai-app',
    }),
  });
}

test('corrupt supported office files report extraction failure', async () => {
  const result = await processors.extractText('member-loan.docx', Buffer.from('not a zip archive'));

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
  zip.addFile('docProps/core.xml', Buffer.from('<dc:title>ignored metadata</dc:title>'));

  const result = await processors.extractText('member-loan.docx', zip.toBuffer());

  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'office');
  assert.strictEqual(result.extractionOk, true);
  assert.strictEqual(result.text, 'Member & loan SSN 524-71-9043');
});

test('pdf processor supports v2 class API and v1 function API modules', async () => {
  await withFakePdfParse({
    PDFParse: class FakePDFParse {
      constructor(opts) {
        assert.ok(Buffer.isBuffer(opts.data));
      }
      async getText() {
        return { text: 'PDF v2 member SSN 524-71-9043' };
      }
    },
  }, async () => {
    const result = await processors.extractText('member-loan.pdf', Buffer.from('pdf bytes'));
    assert.strictEqual(result.extractionOk, true);
    assert.strictEqual(result.processor, 'pdf');
    assert.strictEqual(result.text, 'PDF v2 member SSN 524-71-9043');
  });

  await withFakePdfParse(async (buf) => {
    assert.ok(Buffer.isBuffer(buf));
    return { text: 'PDF v1 member SSN 524-71-9043' };
  }, async () => {
    const result = await processors.extractText('member-loan.pdf', Buffer.from('pdf bytes'));
    assert.strictEqual(result.extractionOk, true);
    assert.strictEqual(result.processor, 'pdf');
    assert.strictEqual(result.text, 'PDF v1 member SSN 524-71-9043');
  });
});

test('pdf processor converts parser failures to typed extraction errors', async () => {
  await withFakePdfParse(async () => {
    throw new Error('parse failed');
  }, async () => {
    const result = await processors.extractText('member-loan.pdf', Buffer.from('bad pdf'));
    assert.strictEqual(result.supported, true);
    assert.strictEqual(result.processor, 'pdf');
    assert.strictEqual(result.extractionOk, false);
    assert.strictEqual(result.error, 'extract_failed');
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

test('extracted text is bounded before detection', async () => {
  const raw = 'x'.repeat(1200);
  const result = await processors.extractText('large.txt', Buffer.from(raw), { maxTextChars: 1000 });

  assert.strictEqual(result.extractionOk, true);
  assert.strictEqual(result.truncated, true);
  assert.strictEqual(result.text.length, 1000);
  assert.strictEqual(result.text, raw.slice(0, 1000));
});

test('scan-file blocks corrupt supported files without echoing file bytes', async () => withServer(async (port) => {
  const secret = '524-71-9043';
  const contentBase64 = Buffer.from('corrupt office bytes with member SSN ' + secret).toString('base64');
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
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.REDACTWALL_POLICY_PATH); } catch {}
});
