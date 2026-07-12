'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const ts = require('../console/node_modules/typescript');

const MODULE_PATH = path.join(__dirname, '..', 'console', 'src', 'lib', 'bounded-response.ts');

function loadBoundedResponseModule() {
  const source = fs.readFileSync(MODULE_PATH, 'utf8');
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const module = { exports: {} };
  new Function('module', 'exports', output)(module, module.exports);
  return module.exports;
}

const { readBoundedJsonBody } = loadBoundedResponseModule();

function jsonResponse(body, headers = {}) {
  return new Response(body, {
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

function cancellableResponse(chunks, headers = {}) {
  let cancelledResolve;
  const cancelled = new Promise((resolve) => { cancelledResolve = resolve; });
  const stream = new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
    },
    cancel() {
      cancelledResolve();
    },
  });
  return { response: new Response(stream, { headers }), cancelled };
}

async function expectCancellation(cancelled) {
  let timeoutId;
  const observed = await Promise.race([
    cancelled.then(() => true),
    new Promise((resolve) => { timeoutId = setTimeout(() => resolve(false), 250); }),
  ]);
  clearTimeout(timeoutId);
  assert.strictEqual(observed, true, 'response stream was cancelled');
}

test('bounded console reader parses a valid native JSON response', async () => {
  const response = jsonResponse('{"ok":true,"count":2}');
  assert.deepStrictEqual(await readBoundedJsonBody(response, 128, 1_000), { ok: true, count: 2 });
  assert.strictEqual(response.bodyUsed, true);
});

test('bounded console reader cancels a declared oversized response before reading', async () => {
  const body = new TextEncoder().encode('{"ok":true}');
  const { response, cancelled } = cancellableResponse([body], {
    'content-type': 'application/json',
    'content-length': '4096',
  });
  assert.strictEqual(await readBoundedJsonBody(response, 32, 1_000), null);
  await expectCancellation(cancelled);
  assert.strictEqual(response.bodyUsed, true);
});

test('bounded console reader cancels unknown-length content at the first oversized chunk', async () => {
  const encoder = new TextEncoder();
  const { response, cancelled } = cancellableResponse([
    encoder.encode('{"value":"'),
    encoder.encode('0123456789abcdef'),
    encoder.encode('never-read"}'),
  ], { 'content-type': 'application/json' });
  assert.strictEqual(await readBoundedJsonBody(response, 16, 1_000), null);
  await expectCancellation(cancelled);
  assert.strictEqual(response.bodyUsed, true);
});

test('bounded console reader cancels a stalled native stream at its deadline', async () => {
  let cancelledResolve;
  const cancelled = new Promise((resolve) => { cancelledResolve = resolve; });
  const response = new Response(new ReadableStream({
    cancel() {
      cancelledResolve();
    },
  }), { headers: { 'content-type': 'application/json' } });
  const startedAt = Date.now();
  assert.strictEqual(await readBoundedJsonBody(response, 128, 20), null);
  assert.ok(Date.now() - startedAt < 500, 'deadline remains bounded');
  await expectCancellation(cancelled);
  assert.strictEqual(response.bodyUsed, true);
});

test('bounded console reader rejects malformed UTF-8', async () => {
  const response = jsonResponse(new Uint8Array([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d]));
  assert.strictEqual(await readBoundedJsonBody(response, 128, 1_000), null);
});

test('bounded console reader rejects malformed JSON', async () => {
  assert.strictEqual(await readBoundedJsonBody(jsonResponse('{"open":'), 128, 1_000), null);
});

test('bounded console reader rejects and cancels a non-JSON media type', async () => {
  const { response, cancelled } = cancellableResponse([
    new TextEncoder().encode('{"looks":"json"}'),
  ], { 'content-type': 'text/plain' });
  assert.strictEqual(await readBoundedJsonBody(response, 128, 1_000), null);
  await expectCancellation(cancelled);
  assert.strictEqual(response.bodyUsed, true);
});

test('bounded console reader consumes each Response body at most once', async () => {
  const response = jsonResponse('{"once":true}');
  assert.deepStrictEqual(await readBoundedJsonBody(response, 128, 1_000), { once: true });
  assert.strictEqual(await readBoundedJsonBody(response, 128, 1_000), null);
  assert.strictEqual(response.bodyUsed, true);
});
