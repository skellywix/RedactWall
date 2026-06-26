'use strict';
/** File extraction safety: bounded processors and fail-closed scan-file handling. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-processors-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const processors = require('../src/processors');
const app = require('../server');

function listen(appUnderTest) {
  return new Promise((resolve, reject) => {
    const server = appUnderTest.listen(0, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
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

test('corrupt supported office files report extraction failure', async () => {
  const result = await processors.extractText('member-loan.docx', Buffer.from('not a zip archive'));

  assert.strictEqual(result.supported, true);
  assert.strictEqual(result.processor, 'office');
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'extract_failed');
  assert.strictEqual(result.text, '');
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

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
});
