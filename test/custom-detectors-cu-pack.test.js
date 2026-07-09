'use strict';
/**
 * Guards the shipped credit-union core-banking detector pack
 * (config/custom-detectors.json).
 *
 * The eval harness (scripts/eval-detect.js) calls analyze(text) with NO opts, so
 * it never loads config/custom-detectors.json — the benign-FP=0 floor there does
 * NOT exercise a shipped pack. This test deliberately loads the pack and enforces
 * benign-FP=0 with it enabled, which is otherwise unguarded.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const D = require('../detection-engine/detect');

const PACK_PATH = path.join(__dirname, '..', 'config', 'custom-detectors.json');
const FIXTURE = path.join(__dirname, 'fixtures', 'semantic-eval.json');

function loadPack() {
  return JSON.parse(fs.readFileSync(PACK_PATH, 'utf8'));
}

function enabledConfig() {
  return { detectors: (loadPack().detectors || []).map((d) => ({ ...d, enabled: true })) };
}

test('CU core-banking pack ships disabled by default (default runtime loads nothing)', () => {
  const raw = loadPack();
  assert.ok(Array.isArray(raw.detectors) && raw.detectors.length >= 4, 'pack ships vendor detectors');
  for (const d of raw.detectors) assert.strictEqual(d.enabled, false, `${d.id} must ship disabled`);
  // With the on-disk (disabled) config, the engine normalizes to an empty set,
  // so the default detector inventory and eval floors are unaffected.
  assert.strictEqual(D.normalizeCustomDetectors(raw).length, 0, 'disabled detectors do not load');
});

test('CU core-banking pack, when ENABLED, holds benign-FP=0 on the held-out corpus', () => {
  const config = enabledConfig();
  const ids = new Set(D.normalizeCustomDetectors(config).map((d) => d.id));
  assert.ok(ids.size >= 4, 'enabling the pack loads the vendor detectors');

  const data = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  const benign = [
    ...data.semantic.filter((e) => !(e.labels || []).length).map((e) => e.text),
    ...data.structured.filter((e) => !(e.types || []).length).map((e) => e.text),
  ];
  const fps = [];
  for (const text of benign) {
    const hits = D.analyze(text, { customDetectors: config }).findings.filter((f) => ids.has(f.type));
    if (hits.length) fps.push({ text: text.slice(0, 90), fired: hits.map((h) => h.type) });
  }
  assert.deepStrictEqual(fps, [], `enabled pack fired on benign text: ${JSON.stringify(fps.slice(0, 4))}`);
});

test('CU core-banking detectors fire on their own vendor-context positives', () => {
  const opts = { customDetectors: enabledConfig() };
  const cases = [
    ['JACK_HENRY_MEMBER_ACCOUNT', 'Symitar Episys account suffix 1234567-01 for the member'],
    ['CORELATION_KEYSTONE_SERIAL', 'Corelation KeyStone person serial 4567890 pulled today'],
    ['FISERV_CORE_ACCOUNT', 'Fiserv DNA core account 987654321 balance inquiry'],
    ['FINASTRA_CORE_ACCOUNT', 'Finastra fusion core account 5551234 transfer'],
  ];
  for (const [id, text] of cases) {
    const fired = D.analyze(text, opts).findings.some((f) => f.type === id);
    assert.ok(fired, `${id} should fire on: ${text}`);
  }
});

test('CU pack respects engine invariants (all valid, ReDoS-safe, context-gated)', () => {
  const config = enabledConfig();
  const normalized = D.normalizeCustomDetectors(config);
  // Every shipped detector survived normalization (safe regex, valid id, not a
  // built-in override); none was silently dropped.
  assert.strictEqual(normalized.length, config.detectors.length, 'all detectors are engine-valid');
  // Context-gating is author discipline the engine does not force — every
  // shipped detector must carry it so it cannot fire on a bare numeric run.
  for (const d of normalized) assert.ok(d.ctx, `${d.id} must be context-gated`);
});
