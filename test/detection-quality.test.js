'use strict';
/** Detection quality proof must expose metrics without eval prompt bodies. */
const test = require('node:test');
const assert = require('node:assert');
const detectionQuality = require('../server/detection-quality');
const { SEM_CATS } = require('../scripts/eval-detect');

function failingEval() {
  const semantic = {};
  for (const category of SEM_CATS) {
    semantic[category] = { tp: 0, fp: category === 'CONFIDENTIAL_BUSINESS' ? 1 : 0, fn: 1, precision: 0, recall: 0, f1: 0 };
  }
  return {
    semantic,
    structured: {
      US_SSN: { tp: 0, fp: 0, fn: 1, precision: 1, recall: 0, f1: 0 },
    },
    microSem: { tp: 0, fp: 1, fn: 2, precision: 0, recall: 0, f1: 0 },
    microStruct: { tp: 0, fp: 0, fn: 1, precision: 1, recall: 0, f1: 0 },
    benignFPs: [{ text: 'ordinary quarterly planning note', fired: ['CONFIDENTIAL_BUSINESS'] }],
    baitFPs: [{ text: 'confirmation 412227843', fired: ['US_SSN'] }],
  };
}

test('detection quality summarizes held-out eval without raw examples', () => {
  const report = detectionQuality.report({ generatedAt: '2026-07-04T00:00:00.000Z' });
  assert.strictEqual(report.generatedAt, '2026-07-04T00:00:00.000Z');
  assert.strictEqual(report.summary.floorsMet, true);
  assert.ok(report.summary.score >= 90);
  assert.strictEqual(report.summary.privacy, 'held-out synthetic fixture only; prompt bodies excluded');
  assert.ok(report.gates.some((item) => item.id === 'semantic_recall'));
  assert.ok(report.semantic.some((item) => item.id === 'CONFIDENTIAL_BUSINESS' && item.recall >= 70));
  assert.ok(report.structured.some((item) => item.id === 'US_SSN' && item.recall === 100));
  const json = JSON.stringify(report);
  assert.strictEqual(json.includes('Leadership has decided'), false);
  assert.strictEqual(json.includes('412-22-7843'), false);
});

test('detection quality reports floor failures without leaking example text', () => {
  const report = detectionQuality.report({
    generatedAt: '2026-07-04T00:00:00.000Z',
    evaluate: failingEval,
  });
  assert.strictEqual(report.summary.floorsMet, false);
  assert.strictEqual(report.summary.state, 'attention');
  assert.ok(report.summary.failures > 0);
  assert.strictEqual(report.summary.benignFalsePositives, 1);
  assert.strictEqual(report.summary.baitFalsePositives, 1);
  assert.ok(report.failures.some((item) => /CONFIDENTIAL_BUSINESS recall/.test(item)));
  const json = JSON.stringify(report);
  assert.strictEqual(json.includes('ordinary quarterly planning note'), false);
  assert.strictEqual(json.includes('confirmation 412227843'), false);
});

test('detection quality handles eval failures as an attention state', () => {
  const report = detectionQuality.report({
    evaluate: () => { throw new Error('fixture unavailable'); },
  });
  assert.strictEqual(report.summary.score, 0);
  assert.strictEqual(report.summary.state, 'attention');
  assert.ok(report.failures.some((item) => /fixture unavailable/.test(item)));
});
