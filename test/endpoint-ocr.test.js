'use strict';
/** Endpoint-local OCR bridge must stay local, bounded, and optional. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const endpointOcr = require('../sensors/endpoint-agent/ocr');

function tempImage(t, name = 'scan.png') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-endpoint-ocr-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, name);
  fs.writeFileSync(file, 'pretend image bytes');
  return file;
}

test('endpoint OCR args parse as bounded JSON string arrays', () => {
  assert.deepStrictEqual(endpointOcr.parseArgsJson('["--input","{file}","--stdout"]'), ['--input', '{file}', '--stdout']);
  assert.strictEqual(endpointOcr.parseArgsJson(''), null);
  assert.throws(() => endpointOcr.parseArgsJson('{bad json'), /JSON array/);
  assert.throws(() => endpointOcr.parseArgsJson('["ok",42]'), /array of strings/);
  assert.throws(() => endpointOcr.parseArgsJson(JSON.stringify(Array.from({ length: 41 }, () => 'x'))), /too large/);
});

test('endpoint OCR materializes file args without shell interpolation', () => {
  const file = path.join('C:\\', 'PromptWall', 'scan one.png');
  assert.deepStrictEqual(
    endpointOcr.materializeArgs(['--input', '{file}', '--stdout'], file),
    ['--input', file, '--stdout'],
  );
  assert.deepStrictEqual(endpointOcr.materializeArgs(['--stdout'], file), ['--stdout', file]);
});

test('endpoint OCR settings accept PromptWall aliases', () => {
  const settings = endpointOcr.ocrSettings({
    env: {
      PROMPTWALL_ENDPOINT_AGENT_OCR_COMMAND: 'ocr-cli',
      PROMPTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON: '["{file}","stdout"]',
      PROMPTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS: '20000',
      PROMPTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS: '250000',
    },
  });

  assert.strictEqual(settings.configured, true);
  assert.strictEqual(settings.command, 'ocr-cli');
  assert.deepStrictEqual(settings.args, ['{file}', 'stdout']);
  assert.strictEqual(settings.timeoutMs, 20000);
  assert.strictEqual(settings.maxChars, 250000);
});

test('endpoint OCR returns ocr_required for images when no local OCR is configured', async (t) => {
  const file = tempImage(t);
  const extracted = await endpointOcr.extractImageFile(path.basename(file), file, { env: {} });

  assert.strictEqual(extracted.extractionOk, false);
  assert.strictEqual(extracted.error, 'ocr_required');
  assert.strictEqual(extracted.ocrRequired, true);
  assert.strictEqual(extracted.ocrConfigured, false);
});

test('endpoint OCR accepts injected local extraction and bounds returned text', async (t) => {
  const file = tempImage(t);
  const longText = 'OCR text SSN 524-71-9043 '.repeat(80);
  const extracted = await endpointOcr.extractImageFile(path.basename(file), file, {
    maxChars: 1000,
    extractImageText: async (filePath, ctx) => {
      assert.strictEqual(filePath, file);
      assert.strictEqual(ctx.filename, path.basename(file));
      return longText;
    },
  });

  assert.strictEqual(extracted.extractionOk, true);
  assert.strictEqual(extracted.processor, 'endpoint_ocr');
  assert.strictEqual(extracted.ocrApplied, true);
  assert.strictEqual(extracted.text, longText.slice(0, 1000));
  assert.strictEqual(extracted.text.length, 1000);
  assert.strictEqual(extracted.truncated, true);
});

test('endpoint OCR can call a local command without a shell', async (t) => {
  const file = tempImage(t);
  const extracted = await endpointOcr.extractImageFile(path.basename(file), file, {
    command: process.execPath,
    args: ['-e', 'process.stdout.write("OCR command SSN 524-71-9043")'],
    maxChars: 100,
  });

  assert.strictEqual(extracted.extractionOk, true);
  assert.strictEqual(extracted.processor, 'endpoint_ocr');
  assert.match(extracted.text, /OCR command SSN/);
});

test('endpoint OCR supplies safe default command arguments', async (t) => {
  const file = tempImage(t);
  const calls = [];
  const execFileAsync = async (command, args, options) => {
    calls.push({ command, args, options });
    return { stdout: 'local OCR text' };
  };

  assert.strictEqual(await endpointOcr.runOcrCommand(file, {
    command: 'tesseract.exe',
    args: null,
    timeoutMs: 1200,
    maxChars: 2000,
  }, { execFileAsync }), 'local OCR text');
  assert.deepStrictEqual(calls[0].args, [file, 'stdout']);
  assert.strictEqual(calls[0].options.windowsHide, true);
  assert.strictEqual(calls[0].options.timeout, 1200);
  assert.strictEqual(calls[0].options.maxBuffer, 8000);

  await endpointOcr.runOcrCommand(file, {
    command: 'ocr-cli',
    timeoutMs: 1200,
    maxChars: 2000,
  }, { execFileAsync });
  assert.deepStrictEqual(calls[1].args, [file]);
});

test('endpoint OCR fails closed on invalid config and local extraction errors', async (t) => {
  const file = tempImage(t);

  const invalidConfig = await endpointOcr.extractImageFile(path.basename(file), file, {
    argsJson: '{bad',
    command: 'ocr-cli',
    env: {},
  });
  assert.strictEqual(invalidConfig.extractionOk, false);
  assert.strictEqual(invalidConfig.error, 'ocr_config_invalid');
  assert.strictEqual(invalidConfig.ocrConfigured, true);

  const failedExtraction = await endpointOcr.extractImageFile(path.basename(file), file, {
    extractImageText: async () => {
      throw new Error('boom');
    },
  });
  assert.strictEqual(failedExtraction.extractionOk, false);
  assert.strictEqual(failedExtraction.error, 'extract_failed');
  assert.strictEqual(failedExtraction.ocrConfigured, true);
  assert.strictEqual(failedExtraction.ocrApplied, false);
});
