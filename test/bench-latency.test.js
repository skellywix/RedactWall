'use strict';
/**
 * CI latency budget over the shared engine (scripts/bench-detect.js). Catches
 * order-of-magnitude regressions on the per-scan hot path — e.g. a new detector
 * regex that backtracks catastrophically — without flaking on shared runners
 * (p95 gate, ~10-20x headroom). Also guards the no-raw-text-in-output rule.
 */
const test = require('node:test');
const assert = require('node:assert');
const { runBench, failures, report, buildWorkloads } = require('../scripts/bench-detect');

test('bench — latency budgets met on the quick preset', () => {
  const f = failures(runBench({ quick: true }));
  assert.strictEqual(f.length, 0, 'budgets exceeded:\n  - ' + f.join('\n  - '));
});

test('bench — report and JSON output never contain workload text (no PII in logs)', () => {
  const results = runBench({ quick: true });
  const workloads = buildWorkloads();
  const rendered = report(results) + '\n' + JSON.stringify(results);
  // The synthetic PII marker and a benign-sentence fragment must not leak.
  assert.ok(!rendered.includes('123-45-6789'), 'output must not contain the synthetic SSN');
  assert.ok(!rendered.includes('4111 1111 1111 1111'), 'output must not contain the synthetic card');
  assert.ok(!rendered.includes(workloads['benign-short'].slice(0, 40)), 'output must not echo workload prose');
});
