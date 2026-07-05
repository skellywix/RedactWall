'use strict';
/**
 * Detector quality gate: re-run the held-out eval (scripts/eval-detect.js over
 * test/fixtures/semantic-eval.json) and hold the same floors CI holds. If the
 * evolving detector regresses on generalization or starts crying wolf on
 * benign business prompts, this tier goes red.
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const { evaluate, failures, FLOORS, SEM_CATS } = require(path.join(ROOT, 'scripts', 'eval-detect'));

const result = evaluate();

test('all published precision/recall floors are met on the held-out corpus', () => {
  const unmet = failures(result);
  assert.strictEqual(unmet.length, 0, 'floors unmet:\n  - ' + unmet.join('\n  - '));
});

test('zero false positives on benign prompts and ordinary ids', () => {
  assert.strictEqual(result.benignFPs.length, FLOORS.semanticBenignFP,
    'benign FPs: ' + JSON.stringify(result.benignFPs.map((b) => b.fired)));
  assert.strictEqual(result.baitFPs.length, FLOORS.structuredBaitFP,
    'bait FPs: ' + JSON.stringify(result.baitFPs.map((b) => b.fired)));
});

test('per-category semantic floors hold for every evaluated category', () => {
  for (const category of SEM_CATS) {
    const m = result.semantic[category];
    if (m.tp + m.fn > 0) {
      assert.ok(m.recall >= FLOORS.semanticRecall, `${category} recall ${m.recall.toFixed(2)} < ${FLOORS.semanticRecall}`);
    }
    if (m.tp + m.fp > 0) {
      assert.ok(m.precision >= FLOORS.semanticPrecision, `${category} precision ${m.precision.toFixed(2)} < ${FLOORS.semanticPrecision}`);
    }
  }
});

test('structured PII micro recall stays at 1.0', () => {
  assert.strictEqual(result.microStruct.recall, 1, `structured micro recall ${result.microStruct.recall.toFixed(3)}`);
});
