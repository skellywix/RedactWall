'use strict';
/**
 * Detection eval harness — precision / recall / F1 on a HELD-OUT labeled corpus
 * (test/fixtures/semantic-eval.json), separate from the trainer's synthetic data.
 *
 *   node scripts/eval-detect.js            # human-readable report
 *   node scripts/eval-detect.js --json     # machine-readable metrics
 *   node scripts/eval-detect.js --ci       # exit 1 if any FLOOR is unmet
 *
 * Why this exists: the trainer calibrates on its own negatives, which is
 * optimistic. This measures generalization to phrasings the model never saw and,
 * crucially, the false-positive rate on benign business prompts — the number that
 * decides whether an admin keeps the tool switched on. require()-able so
 * test/eval.test.js can enforce the same floors in CI.
 */
const fs = require('fs');
const path = require('path');
const D = require('../detection-engine/detect');

const FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'semantic-eval.json');
const SEM_CATS = ['CONFIDENTIAL_BUSINESS', 'SOURCE_CODE', 'LEGAL_CONTRACT', 'CREDENTIALS', 'PROMPT_ATTACK', 'FINANCIAL_STATEMENT', 'TAX_FILING', 'HR_RECORD'];

// Minimum acceptable quality. A DLP control that cries wolf gets switched off, so
// benign false positives are the hard gate; recall floors keep real leaks caught.
const FLOORS = {
  semanticPrecision: 0.90, // per category, over examples that fired it
  semanticRecall: 0.70,    // per category, over examples labeled with it
  semanticBenignFP: 0,     // benign prompts must trigger NOTHING
  structuredRecall: 0.95,  // tested PII types must be caught
  structuredBaitFP: 0,     // ordinary ids must not fire a tested PII type
};

function prf(tp, fp, fn) {
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { tp, fp, fn, precision, recall, f1 };
}

function evaluate(fixture) {
  const data = fixture || JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));

  // ---- semantic ----
  const sem = {};
  for (const c of SEM_CATS) sem[c] = { tp: 0, fp: 0, fn: 0 };
  const benignFPs = [];
  for (const ex of data.semantic) {
    const pred = new Set(D.analyze(ex.text).categories.map((c) => c.category));
    const labels = new Set(ex.labels || []);
    for (const c of SEM_CATS) {
      if (labels.has(c) && pred.has(c)) sem[c].tp++;
      else if (!labels.has(c) && pred.has(c)) sem[c].fp++;
      else if (labels.has(c) && !pred.has(c)) sem[c].fn++;
    }
    if (labels.size === 0 && pred.size > 0) benignFPs.push({ text: ex.text, fired: [...pred] });
  }
  const semantic = {};
  for (const c of SEM_CATS) semantic[c] = prf(sem[c].tp, sem[c].fp, sem[c].fn);

  // ---- structured ----
  const tested = new Set();
  for (const ex of data.structured) (ex.types || []).forEach((t) => tested.add(t));
  const st = {};
  for (const t of tested) st[t] = { tp: 0, fp: 0, fn: 0 };
  const baitFPs = [];
  for (const ex of data.structured) {
    const all = new Set(D.analyze(ex.text).findings.map((f) => f.type));
    const pred = new Set([...all].filter((t) => tested.has(t))); // only judge tested types
    const labels = new Set(ex.types || []);
    for (const t of tested) {
      if (labels.has(t) && pred.has(t)) st[t].tp++;
      else if (!labels.has(t) && pred.has(t)) st[t].fp++;
      else if (labels.has(t) && !pred.has(t)) st[t].fn++;
    }
    if (labels.size === 0 && pred.size > 0) baitFPs.push({ text: ex.text, fired: [...pred] });
  }
  const structured = {};
  for (const t of tested) structured[t] = prf(st[t].tp, st[t].fp, st[t].fn);

  // ---- aggregates ----
  const microSem = prf(
    SEM_CATS.reduce((a, c) => a + sem[c].tp, 0),
    SEM_CATS.reduce((a, c) => a + sem[c].fp, 0),
    SEM_CATS.reduce((a, c) => a + sem[c].fn, 0)
  );
  const microStruct = prf(
    [...tested].reduce((a, t) => a + st[t].tp, 0),
    [...tested].reduce((a, t) => a + st[t].fp, 0),
    [...tested].reduce((a, t) => a + st[t].fn, 0)
  );

  return { semantic, structured, benignFPs, baitFPs, microSem, microStruct };
}

function failures(r) {
  const out = [];
  for (const c of SEM_CATS) {
    const m = r.semantic[c];
    if (m.tp + m.fn > 0 && m.recall < FLOORS.semanticRecall) out.push(`${c} recall ${m.recall.toFixed(2)} < ${FLOORS.semanticRecall}`);
    if (m.tp + m.fp > 0 && m.precision < FLOORS.semanticPrecision) out.push(`${c} precision ${m.precision.toFixed(2)} < ${FLOORS.semanticPrecision}`);
  }
  if (r.benignFPs.length > FLOORS.semanticBenignFP) out.push(`benign false positives: ${r.benignFPs.length} > ${FLOORS.semanticBenignFP}`);
  for (const t of Object.keys(r.structured)) {
    const m = r.structured[t];
    if (m.tp + m.fn > 0 && m.recall < FLOORS.structuredRecall) out.push(`${t} recall ${m.recall.toFixed(2)} < ${FLOORS.structuredRecall}`);
  }
  if (r.baitFPs.length > FLOORS.structuredBaitFP) out.push(`structured bait false positives: ${r.baitFPs.length} > ${FLOORS.structuredBaitFP}`);
  return out;
}

function pct(x) { return (100 * x).toFixed(1).padStart(5); }
function report(r) {
  const line = (name, m) => `  ${name.padEnd(22)} P ${pct(m.precision)}%  R ${pct(m.recall)}%  F1 ${pct(m.f1)}%   (tp ${m.tp} fp ${m.fp} fn ${m.fn})`;
  const L = [];
  L.push('SEMANTIC (held-out, paraphrased — measures generalization)');
  for (const c of SEM_CATS) L.push(line(c, r.semantic[c]));
  L.push(line('— micro avg', r.microSem));
  L.push('');
  L.push('STRUCTURED PII (true positives + false-positive bait)');
  for (const t of Object.keys(r.structured)) L.push(line(t, r.structured[t]));
  L.push(line('— micro avg', r.microStruct));
  L.push('');
  L.push(`benign prompts firing a category (want 0): ${r.benignFPs.length}`);
  for (const b of r.benignFPs) L.push(`   ✗ [${b.fired.join(',')}]  ${b.text.slice(0, 88)}`);
  L.push(`ordinary ids firing a PII type (want 0): ${r.baitFPs.length}`);
  for (const b of r.baitFPs) L.push(`   ✗ [${b.fired.join(',')}]  ${b.text.slice(0, 88)}`);
  return L.join('\n');
}

function summaryJson(r) {
  return {
    semantic: r.semantic,
    structured: r.structured,
    microSem: r.microSem,
    microStruct: r.microStruct,
    benignFPs: r.benignFPs.length,
    baitFPs: r.baitFPs.length,
  };
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  const runEvaluate = deps.evaluate || evaluate;
  const r = runEvaluate();
  const f = failures(r);
  if (argv.includes('--json')) {
    io.log(JSON.stringify(summaryJson(r), null, 2));
  } else {
    io.log(report(r));
    io.log('\n' + (f.length ? 'FLOORS UNMET:\n  - ' + f.join('\n  - ') : 'All floors met.'));
  }
  if (argv.includes('--ci') && f.length) setExitCode(1);
  return { result: r, failures: f };
}

if (require.main === module) main();

module.exports = { evaluate, failures, main, report, summaryJson, FLOORS, SEM_CATS };
