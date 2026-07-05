'use strict';
/**
 * Meta-invariants over the held-out eval corpus (test/fixtures/semantic-eval.json).
 * These guard the corpus itself — composition minima, label validity, no
 * duplicates, and that checksum bait genuinely fails its validator — so the
 * precision/recall numbers in test/eval.test.js are measured over a real corpus,
 * not a tiny or self-contradicting one.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const D = require('../detection-engine/detect');
const { SEM_CATS, corpusCounts } = require('../scripts/eval-detect');

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'semantic-eval.json'), 'utf8'));
const norm = (s) => s.replace(/\s+/g, ' ').trim().toLowerCase();

test('corpus — composition minima (>=500 total, per-category floors)', () => {
  const c = corpusCounts(fixture);
  assert.ok(c.total >= 500, `total ${c.total} should be >= 500`);
  assert.ok(c.benign >= 100, `benign ${c.benign} should be >= 100`);
  assert.ok(c.bait >= 50, `bait ${c.bait} should be >= 50`);

  const perCat = {};
  for (const cat of SEM_CATS) perCat[cat] = 0;
  for (const e of fixture.semantic) for (const l of e.labels || []) perCat[l] = (perCat[l] || 0) + 1;
  for (const cat of SEM_CATS) assert.ok(perCat[cat] >= 30, `${cat} has ${perCat[cat]} positives, want >= 30`);

  const perType = {};
  for (const e of fixture.structured) for (const t of e.types || []) perType[t] = (perType[t] || 0) + 1;
  for (const t of Object.keys(perType)) assert.ok(perType[t] >= 3, `${t} has ${perType[t]} positives, want >= 3`);
});

test('corpus — every label is a known category / detector id', () => {
  const catSet = new Set(SEM_CATS);
  for (const e of fixture.semantic) {
    for (const l of e.labels || []) assert.ok(catSet.has(l), `semantic label ${l} not in SEM_CATS`);
  }
  const ids = new Set(D.listDetectors().map((d) => d.id));
  for (const e of fixture.structured) {
    for (const t of e.types || []) assert.ok(ids.has(t), `structured type ${t} is not a known detector id`);
  }
});

test('corpus — no duplicate normalized texts', () => {
  const seen = new Map();
  for (const e of [...fixture.semantic, ...fixture.structured]) {
    const n = norm(e.text);
    assert.ok(!seen.has(n), `duplicate text: ${e.text.slice(0, 60)}`);
    seen.set(n, true);
  }
});

test('corpus — decontaminated: no trainer-verbatim entries', () => {
  const trainer = norm(fs.readFileSync(path.join(__dirname, '..', 'scripts', 'train-semantic.js'), 'utf8'));
  for (const e of fixture.semantic) {
    const n = norm(e.text);
    // A full labeled positive must not appear verbatim in the trainer templates.
    if ((e.labels || []).length && n.length > 40) {
      assert.ok(!trainer.includes(n), `trainer-contaminated fixture: ${e.text.slice(0, 60)}`);
    }
  }
});

test('corpus — bait fires no tested structured type, and checksum bait fails its validator', () => {
  const tested = new Set();
  for (const e of fixture.structured) for (const t of e.types || []) tested.add(t);
  for (const e of fixture.structured) {
    if ((e.types || []).length) continue; // bait only
    const fired = D.analyze(e.text).findings.map((f) => f.type).filter((t) => tested.has(t));
    assert.deepStrictEqual(fired, [], `bait fired ${fired.join(',')}: ${e.text.slice(0, 60)}`);
    // Any 13-19 digit run in bait must NOT be a Luhn-valid card network (no
    // accidentally-valid card hiding in the false-positive bucket).
    for (const m of e.text.matchAll(/\b(?:\d[ -]?){13,19}\b/g)) {
      const digits = m[0].replace(/[ -]/g, '');
      assert.ok(!(D.luhnValid(digits) && D.cardNetwork(digits)), `bait contains a valid card: ${digits}`);
    }
  }
});
