'use strict';
/**
 * CI gate over the held-out detection eval (scripts/eval-detect.js +
 * test/fixtures/semantic-eval.json). Locks in precision/recall and, above all,
 * ZERO false positives on benign prompts — the number that decides whether an
 * admin keeps the control switched on.
 */
const test = require('node:test');
const assert = require('node:assert');
const { evaluate, failures, main, report, SEM_CATS, summaryJson } = require('../scripts/eval-detect');

test('eval — all precision/recall floors met on held-out corpus', () => {
  const f = failures(evaluate());
  assert.strictEqual(f.length, 0, 'floors unmet:\n  - ' + f.join('\n  - '));
});

test('eval — zero false positives on benign prompts and ordinary ids', () => {
  const r = evaluate();
  assert.strictEqual(r.benignFPs.length, 0, 'benign FPs: ' + JSON.stringify(r.benignFPs.map((b) => b.fired)));
  assert.strictEqual(r.baitFPs.length, 0, 'bait FPs: ' + JSON.stringify(r.baitFPs.map((b) => b.fired)));
});

test('eval — semantic generalization stays strong (micro P>=0.99, R>=0.85)', () => {
  const r = evaluate();
  assert.ok(r.microSem.precision >= 0.99, 'semantic micro precision ' + r.microSem.precision.toFixed(3));
  assert.ok(r.microSem.recall >= 0.85, 'semantic micro recall ' + r.microSem.recall.toFixed(3));
  assert.strictEqual(r.microStruct.recall, 1, 'structured recall must stay 1.0');
});

function failingResult() {
  const semantic = {};
  for (const category of SEM_CATS) {
    semantic[category] = { tp: 0, fp: 1, fn: 1, precision: 0, recall: 0, f1: 0 };
  }
  return {
    semantic,
    structured: {
      US_SSN: { tp: 0, fp: 0, fn: 1, precision: 1, recall: 0, f1: 0 },
    },
    benignFPs: [{ text: 'ordinary quarterly planning note', fired: ['SOURCE_CODE'] }],
    baitFPs: [{ text: 'ticket id 123456789', fired: ['US_SSN'] }],
    microSem: { tp: 0, fp: 4, fn: 4, precision: 0, recall: 0, f1: 0 },
    microStruct: { tp: 0, fp: 0, fn: 1, precision: 1, recall: 0, f1: 0 },
  };
}

test('eval report, JSON summary, and CLI cover floor failure output', () => {
  const r = failingResult();
  const f = failures(r);
  assert.ok(f.some((item) => /CONFIDENTIAL_BUSINESS recall/.test(item)));
  assert.ok(f.some((item) => /precision/.test(item)));
  assert.ok(f.some((item) => /benign false positives/.test(item)));
  assert.ok(f.some((item) => /US_SSN recall/.test(item)));
  assert.ok(f.some((item) => /structured bait false positives/.test(item)));
  assert.strictEqual(summaryJson(r).benignFPs, 1);
  assert.match(report(r), /ordinary quarterly planning note/);
  assert.match(report(r), /ticket id 123456789/);

  const logs = [];
  const exits = [];
  const io = { log: (line) => logs.push(String(line)) };
  const cli = main(['--ci'], {
    console: io,
    evaluate: () => r,
    setExitCode: (code) => exits.push(code),
  });
  assert.strictEqual(cli.failures.length, f.length);
  assert.ok(logs.some((line) => /FLOORS UNMET/.test(line)));
  assert.deepStrictEqual(exits, [1]);

  logs.length = 0;
  exits.length = 0;
  main(['--json', '--ci'], {
    console: io,
    evaluate: () => r,
    setExitCode: (code) => exits.push(code),
  });
  assert.match(logs.join('\n'), /"benignFPs": 1/);
  assert.deepStrictEqual(exits, [1]);
});
