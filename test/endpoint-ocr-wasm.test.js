'use strict';
/** Bundled WASM OCR fallback must stay offline, bounded, opt-outable, and fail closed. */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const ocrWasm = require('../sensors/endpoint-agent/ocr-wasm');
const endpointOcr = require('../sensors/endpoint-agent/ocr');

const FIXTURE = path.join(__dirname, '..', 'sensors', 'endpoint-agent', 'fixtures', 'ocr-sample.png');

function fakeTesseract(behavior) {
  return {
    createWorker: async () => ({
      recognize: behavior.recognize,
      terminate: behavior.terminate || (async () => {}),
    }),
  };
}

test('wasmOcrAvailable honors the kill switch, missing module, and missing tessdata', () => {
  assert.strictEqual(ocrWasm.wasmOcrAvailable({ env: { ENDPOINT_AGENT_OCR_WASM: 'off' }, fresh: true }), false);
  assert.strictEqual(ocrWasm.wasmOcrAvailable({ env: { PROMPTWALL_ENDPOINT_AGENT_OCR_WASM: 'false' }, fresh: true }), false);
  assert.strictEqual(
    ocrWasm.wasmOcrAvailable({ env: {}, fresh: true, resolve: () => { throw new Error('not installed'); } }),
    false,
  );
  assert.strictEqual(
    ocrWasm.wasmOcrAvailable({ env: {}, fresh: true, resolve: () => 'ok', statSync: () => { throw new Error('missing'); } }),
    false,
  );
});

test('wasmOcrAvailable reports true when the optional engine and tessdata are present', (t) => {
  t.after(() => ocrWasm.resetWasmOcr());
  let installed = true;
  try { require.resolve('tesseract.js'); } catch { installed = false; }
  if (!installed) { t.skip('tesseract.js optional dependency not installed'); return; }
  assert.strictEqual(ocrWasm.wasmOcrAvailable({ fresh: true }), true);
});

test('extractImageTextWasm returns extracted text from a reused worker', async (t) => {
  t.after(() => ocrWasm.resetWasmOcr());
  const tess = fakeTesseract({ recognize: async () => ({ data: { text: 'ledger balance sheet' } }) });
  const text = await ocrWasm.extractImageTextWasm('/tmp/x.png', {
    tesseract: tess, langPath: '/x', corePath: '/x', workerPath: '/x',
  });
  assert.strictEqual(text, 'ledger balance sheet');
});

test('extractImageTextWasm races a timeout and terminates the wedged worker', async (t) => {
  t.after(() => ocrWasm.resetWasmOcr());
  let terminated = 0;
  const tess = fakeTesseract({
    recognize: () => new Promise(() => {}),
    terminate: async () => { terminated += 1; },
  });
  await assert.rejects(
    () => ocrWasm.extractImageTextWasm('/tmp/x.png', {
      tesseract: tess, langPath: '/x', corePath: '/x', workerPath: '/x', timeoutMs: 1000,
    }),
    /ocr_timeout/,
  );
  assert.strictEqual(terminated, 1);
});

test('extractImageFile falls back to bundled WASM when only WASM is available', async () => {
  const result = await endpointOcr.extractImageFile('scan.png', '/tmp/scan.png', {
    discover: false,
    env: {},
    ocrWasm: { wasmOcrAvailable: () => true, extractImageTextWasm: async () => 'quarterly statement of cash flows' },
  });
  assert.strictEqual(result.extractionOk, true);
  assert.strictEqual(result.ocrEngine, 'wasm');
  assert.strictEqual(result.ocrConfigured, true);
  assert.match(result.text, /statement of cash flows/);
});

test('extractImageFile stays ocr_required when the WASM engine is unavailable', async () => {
  const result = await endpointOcr.extractImageFile('scan.png', '/tmp/scan.png', {
    discover: false,
    env: {},
    ocrWasm: { wasmOcrAvailable: () => false, extractImageTextWasm: async () => { throw new Error('should not run'); } },
  });
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'ocr_required');
  assert.strictEqual(result.ocrConfigured, false);
  assert.strictEqual(result.ocrEngine, undefined);
});

test('extractImageFile routes an unreadable image back to ocr_required when WASM throws', async () => {
  const result = await endpointOcr.extractImageFile('scan.png', '/tmp/scan.png', {
    discover: false,
    env: {},
    ocrWasm: { wasmOcrAvailable: () => true, extractImageTextWasm: async () => { throw new Error('bad decode'); } },
  });
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'ocr_required');
  assert.strictEqual(result.ocrRequired, true);
  assert.strictEqual(result.ocrEngine, 'wasm');
});

test('a native engine takes precedence and never invokes the WASM fallback', async (t) => {
  const file = path.join(__dirname, 'fixtures-native.png');
  let wasmTouched = 0;
  const result = await endpointOcr.extractImageFile('scan.png', file, {
    command: process.execPath,
    args: ['-e', 'process.stdout.write("native tesseract text")'],
    maxChars: 100,
    ocrWasm: {
      wasmOcrAvailable: () => { wasmTouched += 1; return true; },
      extractImageTextWasm: async () => { wasmTouched += 1; return 'wasm text'; },
    },
  });
  assert.strictEqual(result.extractionOk, true);
  assert.match(result.text, /native tesseract text/);
  assert.strictEqual(wasmTouched, 0);
});

test('strict mode routes sparse OCR back to the approval queue', async () => {
  const strict = await endpointOcr.extractImageFile('scan.png', '/tmp/scan.png', {
    discover: false,
    env: { ENDPOINT_AGENT_OCR_STRICT: 'on' },
    ocrWasm: { wasmOcrAvailable: () => true, extractImageTextWasm: async () => '  x ' },
  });
  assert.strictEqual(strict.extractionOk, false);
  assert.strictEqual(strict.error, 'ocr_required');
  assert.strictEqual(strict.ocrStrict, true);
  assert.strictEqual(strict.ocrEngine, 'wasm');

  const lenient = await endpointOcr.extractImageFile('scan.png', '/tmp/scan.png', {
    discover: false,
    env: {},
    ocrWasm: { wasmOcrAvailable: () => true, extractImageTextWasm: async () => '  x ' },
  });
  assert.strictEqual(lenient.extractionOk, true);
  assert.strictEqual(lenient.text, '  x ');
});

test('strict mode applies to the native path when extraction is near-empty', async () => {
  const result = await endpointOcr.extractImageFile('scan.png', '/tmp/scan.png', {
    env: { ENDPOINT_AGENT_OCR_STRICT: 'on' },
    extractImageText: async () => '',
  });
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'ocr_required');
  assert.strictEqual(result.ocrStrict, true);
});

test('the kill switch yields a byte-for-byte ocr_required result through the real module', async () => {
  const result = await endpointOcr.extractImageFile('scan.png', '/tmp/scan.png', {
    discover: false,
    env: { ENDPOINT_AGENT_OCR_WASM: 'off' },
  });
  assert.strictEqual(result.extractionOk, false);
  assert.strictEqual(result.error, 'ocr_required');
  assert.strictEqual(result.ocrRequired, true);
  assert.strictEqual(result.ocrConfigured, false);
  assert.strictEqual(result.ocrEngine, undefined);
});

test('bundled WASM extracts real fixture text fully offline', async (t) => {
  if (!ocrWasm.wasmOcrAvailable({ fresh: true })) { t.skip('tesseract.js or tessdata unavailable'); return; }
  t.after(() => ocrWasm.resetWasmOcr());
  const result = await endpointOcr.extractImageFile('ocr-sample.png', FIXTURE, {
    discover: false,
    env: { PATH: '/nonexistent' },
    platform: 'linux',
  });
  assert.strictEqual(result.extractionOk, true);
  assert.strictEqual(result.ocrEngine, 'wasm');
  assert.match(result.text, /PROMPTWALL/i);
});
