'use strict';
/**
 * CI gate over the held-out detection eval (scripts/eval-detect.js +
 * test/fixtures/semantic-eval.json). Locks in precision/recall and, above all,
 * ZERO false positives on benign prompts — the number that decides whether an
 * admin keeps the control switched on.
 */
const test = require('node:test');
const assert = require('node:assert');
const { evaluate, failures } = require('../scripts/eval-detect');

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
