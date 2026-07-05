'use strict';
/**
 * Detector-tier latency budget: re-run the benchmark (scripts/bench-detect.js)
 * and hold the same p95 budgets CI holds. If a detector change makes the
 * per-scan hot path an order of magnitude slower, this tier goes red.
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const { runBench, failures, BUDGETS } = require(path.join(ROOT, 'scripts', 'bench-detect'));

const results = runBench({ quick: true });

test('per-scan latency stays within published budgets', () => {
  const unmet = failures(results);
  assert.strictEqual(unmet.length, 0, 'budgets exceeded:\n  - ' + unmet.join('\n  - '));
});

test('short-prompt throughput clears the floor', () => {
  assert.ok(results['benign-short'].scansPerSec >= BUDGETS['benign-short'].minScansPerSec,
    `benign-short throughput ${results['benign-short'].scansPerSec}/s`);
});
