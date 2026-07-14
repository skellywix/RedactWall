'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const worker = path.join(__dirname, 'support', 'customer-secret-material-detector-worker.js');
const WORKER_HEAP_MIB = 64;

function runBoundedWorker(mode, timeout) {
  const result = spawnSync(process.execPath, [`--max-old-space-size=${WORKER_HEAP_MIB}`, worker, mode], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024,
    timeout,
    windowsHide: true,
  });
  assert.notStrictEqual(result.error?.code, 'ETIMEDOUT', `${mode} detector worker exceeded ${timeout}ms`);
  assert.strictEqual(result.signal, null, result.stderr);
  assert.strictEqual(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function assertBoundedDetections(mode, expected, timeout = 2_000) {
  const result = runBoundedWorker(mode, timeout);
  assert.deepStrictEqual(result.detections, expected, `${mode} detector results`);
  assert.strictEqual(result.count, expected.length, `${mode} detector count`);
}

test('exact mismatched JWK object terminates in a strictly bounded child', () => {
  assert.deepStrictEqual(runBoundedWorker('exact', 2_000), { count: 1, detections: 0 });
});

test('malformed property corpus terminates within one bounded child budget', () => {
  const result = runBoundedWorker('corpus', 5_000);
  assert.strictEqual(result.count, 2606);
  assert.strictEqual(result.detections, 0);
});

test('mixed and fully escaped kty property markers are found in a bounded child', () => {
  assertBoundedDetections('escaped-markers', [true, true, true, true, true, true, true]);
});

test('lexical object selection ignores braces in values and comments in a bounded child', () => {
  assertBoundedDetections('lexical-boundaries', [true, true, true, true, true]);
});

test('recognized malformed and oversized JWK candidates fail closed in a bounded child', () => {
  assertBoundedDetections('fail-closed', [true, true, true, true, true, true, true]);
});

test('recognized 61549-byte JWK objects truncated on either side fail closed in a bounded child', () => {
  assertBoundedDetections('truncation', [true, true]);
});

test('escaped public JWKs and private-looking comments remain non-findings in a bounded child', () => {
  assertBoundedDetections('non-findings', [false, false, false, false, false, false]);
});

test('marker and parser step ceilings fail closed within a bounded child', () => {
  assertBoundedDetections('ceilings', [true, true, true]);
});

test('bounded extension objects preserve private and public classification in both orders', () => {
  assertBoundedDetections('extension-windows', [true, true, false, false, false]);
});

test('96KiB boundary matrix is field-order stable without public or prose false positives', () => {
  assertBoundedDetections(
    'boundary-matrix',
    [...Array(9).fill(true), ...Array(10).fill(false)],
    5_000,
  );
});

test('exact 96KiB marker distances bind only same-object top-level private fields', () => {
  assertBoundedDetections(
    'heldout-distances',
    [...Array(6).fill(true), ...Array(9).fill(false)],
    5_000,
  );
});

test('escaped unquoted JWK identifiers are decoded without crossing object ownership', () => {
  assertBoundedDetections(
    'escaped-identifiers',
    [...Array(10).fill(true), ...Array(6).fill(false)],
    5_000,
  );
});

test('malformed and overflowing kty values retain same-frame private evidence', () => {
  assertBoundedDetections(
    'lost-kty-evidence',
    [false, true, true, true, true, true, true, false, false, false],
    5_000,
  );
});

test('deep encoded JWK detection preserves same-object ownership at the recursion cap', () => {
  assertBoundedDetections(
    'deep-object-ownership',
    [false, false, false, true, true],
    5_000,
  );
});

test('deep encoded JWKs recover complete bounded strings across the marker window', () => {
  assertBoundedDetections(
    'deep-window-boundary',
    [true, true, false, false, false, false],
    5_000,
  );
});

test('encoded JWKs cannot hide a same-object private field behind an oversized extension value', () => {
  assertBoundedDetections(
    'encoded-oversized-extension',
    [true, true, true, true, false, false],
    5_000,
  );
});

test('encoded malformed extension values cannot suppress same-object private fields', () => {
  assertBoundedDetections(
    'encoded-malformed-extension',
    [true, true, true, true, false, false],
    5_000,
  );
});

test('complete encoded strings beyond the retention ceiling preserve exact object ownership', () => {
  assertBoundedDetections(
    'encoded-retention-overflow',
    [true, true, true, true, false, false],
    10_000,
  );
});

test('nested retention-overflow scanning preserves ownership through the recursion cap', () => {
  assertBoundedDetections(
    'nested-retention-overflow',
    [true, true, true, true, false, false, true, true, true, true, false, false],
    20_000,
  );
});
