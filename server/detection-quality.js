'use strict';
/**
 * Metadata-only detector quality proof from the held-out eval harness.
 */
const evalDetect = require('../scripts/eval-detect');

function n(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function pct(value) {
  return Math.max(0, Math.min(100, Math.round(n(value) * 100)));
}

function safeText(value, fallback = 'unknown', limit = 160) {
  const text = String(value || '').replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim();
  return (text || fallback).slice(0, limit);
}

function metricState({ precision = 1, recall = 1, precisionFloor = 0, recallFloor = 0 } = {}) {
  if (precision < precisionFloor || recall < recallFloor) return 'attention';
  return 'ready';
}

function metricRow(id, metric = {}, floors = {}, kind = 'semantic') {
  const precision = n(metric.precision);
  const recall = n(metric.recall);
  const f1 = n(metric.f1);
  const state = metricState({
    precision,
    recall,
    precisionFloor: floors.precision || 0,
    recallFloor: floors.recall || 0,
  });
  return {
    id: safeText(id, '', 80),
    kind,
    precision: pct(precision),
    recall: pct(recall),
    f1: pct(f1),
    tp: Math.max(0, Math.round(n(metric.tp))),
    fp: Math.max(0, Math.round(n(metric.fp))),
    fn: Math.max(0, Math.round(n(metric.fn))),
    state,
    status: state === 'ready' ? 'normal' : 'warning',
    detail: `P ${pct(precision)} / R ${pct(recall)} / F1 ${pct(f1)}`,
  };
}

function average(values = []) {
  const clean = values.map(n).filter((value) => Number.isFinite(value));
  return clean.length ? clean.reduce((sum, value) => sum + value, 0) / clean.length : 0;
}

function scoreFor(result = {}, failureCount = 0) {
  const base = average([
    result.microSem && result.microSem.precision,
    result.microSem && result.microSem.recall,
    result.microSem && result.microSem.f1,
    result.microStruct && result.microStruct.recall,
    result.microStruct && result.microStruct.f1,
  ]);
  const falsePositivePenalty = (Array.isArray(result.benignFPs) ? result.benignFPs.length : 0)
    + (Array.isArray(result.baitFPs) ? result.baitFPs.length : 0);
  return Math.max(0, Math.min(100, Math.round(base * 100) - (failureCount * 8) - (falsePositivePenalty * 12)));
}

function report(opts = {}) {
  const generatedAt = opts.generatedAt || new Date().toISOString();
  try {
    const evaluate = opts.evaluate || evalDetect.evaluate;
    const result = evaluate();
    const failures = evalDetect.failures(result);
    const semanticFloors = {
      precision: evalDetect.FLOORS.semanticPrecision,
      recall: evalDetect.FLOORS.semanticRecall,
    };
    const structuredFloors = {
      precision: 0,
      recall: evalDetect.FLOORS.structuredRecall,
    };
    const semantic = Object.keys(result.semantic || {})
      .sort()
      .map((id) => metricRow(id, result.semantic[id], semanticFloors, 'semantic'));
    const structured = Object.keys(result.structured || {})
      .sort()
      .map((id) => metricRow(id, result.structured[id], structuredFloors, 'structured'));
    const benignFalsePositives = Array.isArray(result.benignFPs) ? result.benignFPs.length : 0;
    const baitFalsePositives = Array.isArray(result.baitFPs) ? result.baitFPs.length : 0;
    const floorsMet = failures.length === 0;
    const score = scoreFor(result, failures.length);
    return {
      generatedAt,
      summary: {
        score,
        state: floorsMet ? 'ready' : 'attention',
        status: floorsMet ? 'normal' : 'warning',
        floorsMet,
        failures: failures.length,
        semanticPrecision: pct(result.microSem && result.microSem.precision),
        semanticRecall: pct(result.microSem && result.microSem.recall),
        semanticF1: pct(result.microSem && result.microSem.f1),
        structuredRecall: pct(result.microStruct && result.microStruct.recall),
        structuredF1: pct(result.microStruct && result.microStruct.f1),
        benignFalsePositives,
        baitFalsePositives,
        semanticCategories: semantic.length,
        structuredTypes: structured.length,
        fixture: 'test/fixtures/semantic-eval.json',
        privacy: 'held-out synthetic fixture only; prompt bodies excluded',
      },
      gates: [
        { id: 'semantic_precision', label: 'Semantic Precision', value: pct(result.microSem && result.microSem.precision), floor: pct(evalDetect.FLOORS.semanticPrecision), state: pct(result.microSem && result.microSem.precision) >= pct(evalDetect.FLOORS.semanticPrecision) ? 'ready' : 'attention' },
        { id: 'semantic_recall', label: 'Semantic Recall', value: pct(result.microSem && result.microSem.recall), floor: pct(evalDetect.FLOORS.semanticRecall), state: pct(result.microSem && result.microSem.recall) >= pct(evalDetect.FLOORS.semanticRecall) ? 'ready' : 'attention' },
        { id: 'structured_recall', label: 'Structured Recall', value: pct(result.microStruct && result.microStruct.recall), floor: pct(evalDetect.FLOORS.structuredRecall), state: pct(result.microStruct && result.microStruct.recall) >= pct(evalDetect.FLOORS.structuredRecall) ? 'ready' : 'attention' },
        { id: 'false_positive_floor', label: 'False Positive Floor', value: benignFalsePositives + baitFalsePositives, floor: 0, state: benignFalsePositives + baitFalsePositives === 0 ? 'ready' : 'attention' },
      ],
      semantic,
      structured,
      failures: failures.map((item) => safeText(item, '', 160)).slice(0, 12),
    };
  } catch (err) {
    return {
      generatedAt,
      summary: {
        score: 0,
        state: 'attention',
        status: 'warning',
        floorsMet: false,
        failures: 1,
        semanticPrecision: 0,
        semanticRecall: 0,
        structuredRecall: 0,
        benignFalsePositives: 0,
        baitFalsePositives: 0,
        fixture: 'test/fixtures/semantic-eval.json',
        privacy: 'held-out synthetic fixture only; prompt bodies excluded',
      },
      gates: [],
      semantic: [],
      structured: [],
      failures: [safeText(err && err.message, 'eval unavailable', 160)],
    };
  }
}

module.exports = {
  metricRow,
  report,
  scoreFor,
};
