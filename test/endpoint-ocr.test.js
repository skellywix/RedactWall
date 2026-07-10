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
  const file = path.join('C:\\', 'RedactWall', 'scan one.png');
  assert.deepStrictEqual(
    endpointOcr.materializeArgs(['--input', '{file}', '--stdout'], file),
    ['--input', file, '--stdout'],
  );
  assert.deepStrictEqual(endpointOcr.materializeArgs(['--stdout'], file), ['--stdout', file]);
});

test('endpoint OCR settings accept RedactWall aliases', () => {
  const settings = endpointOcr.ocrSettings({
    env: {
      REDACTWALL_ENDPOINT_AGENT_OCR_COMMAND: 'ocr-cli',
      REDACTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON: '["{file}","stdout"]',
      REDACTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS: '20000',
      REDACTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS: '250000',
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
  // No native command and the bundled WASM fallback disabled: images must stay
  // ocr_required rather than being inspected.
  const extracted = await endpointOcr.extractImageFile(path.basename(file), file, {
    env: { ENDPOINT_AGENT_OCR_WASM: 'off' },
    discover: false,
  });

  assert.strictEqual(extracted.extractionOk, false);
  assert.strictEqual(extracted.error, 'ocr_required');
  assert.strictEqual(extracted.ocrRequired, true);
  assert.strictEqual(extracted.ocrConfigured, false);
});

test('endpoint OCR fails closed when injected output exceeds the configured bound', async (t) => {
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

  assert.strictEqual(extracted.extractionOk, false);
  assert.strictEqual(extracted.processor, 'ocr_required');
  assert.strictEqual(extracted.ocrApplied, true);
  assert.strictEqual(extracted.error, 'ocr_output_truncated');
  assert.strictEqual(extracted.ocrRequired, true);
  assert.strictEqual(extracted.text, '');
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

test('endpoint OCR auto-discovers a local tesseract engine', (t) => {
  t.after(() => endpointOcr.resetOcrDiscovery());
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-ocr-discover-'));
  t.after(() => fs.rmSync(binDir, { recursive: true, force: true }));
  const engine = path.join(binDir, 'tesseract');
  fs.writeFileSync(engine, '#!/bin/sh');

  endpointOcr.resetOcrDiscovery();
  const found = endpointOcr.discoverOcrCommand({ fresh: true, env: { PATH: binDir }, platform: 'linux' });
  assert.strictEqual(found, engine);

  const settings = endpointOcr.ocrSettings({ env: { PATH: binDir }, platform: 'linux' });
  assert.strictEqual(settings.configured, true);
  assert.strictEqual(settings.command, engine);
  assert.strictEqual(settings.autoDiscovered, true);

  const cached = endpointOcr.discoverOcrCommand({ env: { PATH: '/nonexistent' }, platform: 'linux' });
  assert.strictEqual(cached, engine, 'discovery result is cached for the process lifetime');
});

test('endpoint OCR discovery checks well-known windows install dirs', (t) => {
  t.after(() => endpointOcr.resetOcrDiscovery());
  const programDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-ocr-win-'));
  t.after(() => fs.rmSync(programDir, { recursive: true, force: true }));
  const engine = path.join(programDir, 'Tesseract-OCR', 'tesseract.exe');
  fs.mkdirSync(path.dirname(engine), { recursive: true });
  fs.writeFileSync(engine, 'stub');

  const found = endpointOcr.discoverOcrCommand({
    fresh: true,
    env: { PATH: '', ProgramFiles: programDir },
    platform: 'win32',
  });
  assert.strictEqual(found, engine);
});

test('endpoint OCR discovery yields nothing without an engine and stays ocr_required', async (t) => {
  t.after(() => endpointOcr.resetOcrDiscovery());
  const noEngine = () => { throw new Error('missing'); };
  const found = endpointOcr.discoverOcrCommand({
    fresh: true,
    env: { PATH: '/nonexistent' },
    platform: 'linux',
    statSync: noEngine,
  });
  assert.strictEqual(found, '');
  const file = tempImage(t);
  endpointOcr.resetOcrDiscovery();
  const extracted = await endpointOcr.extractImageFile(path.basename(file), file, {
    env: { PATH: '/nonexistent' },
    platform: 'linux',
    statSync: noEngine,
  });
  assert.strictEqual(extracted.error, 'ocr_required');
});
