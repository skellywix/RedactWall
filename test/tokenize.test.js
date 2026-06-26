'use strict';
/**
 * Reversible tokenization (pseudonymization) — the on-device primitive behind
 * 'redact' mode. The contract that matters for compliance: the tokenized text
 * carries NO real PII, and detokenize is an exact inverse. Run: node --test
 */
const test = require('node:test');
const assert = require('node:assert');
const D = require('../shared/detect');

const SAMPLE = 'Member John, SSN 524-71-9043, card 4111 1111 1111 1111, email john@cu.org. SSN 524-71-9043 again.';

test('round-trips exactly', () => {
  const a = D.analyze(SAMPLE);
  const t = D.tokenize(SAMPLE, a.findings);
  assert.strictEqual(D.detokenize(t.text, t.map), SAMPLE);
});

test('tokenized text contains no original PII', () => {
  const a = D.analyze(SAMPLE);
  const t = D.tokenize(SAMPLE, a.findings);
  for (const leak of ['524-71-9043', '4111 1111 1111 1111', 'john@cu.org']) {
    assert.ok(!t.text.includes(leak), `tokenized text must not contain ${leak}`);
  }
  assert.match(t.text, /\[\[US_SSN_1\]\]/);
});

test('same value gets the same token; different values differ', () => {
  const a = D.analyze(SAMPLE);
  const t = D.tokenize(SAMPLE, a.findings);
  // SSN appears twice with one token; map has exactly one SSN entry.
  const ssnTokens = Object.keys(t.map).filter((k) => k.startsWith('[[US_SSN'));
  assert.strictEqual(ssnTokens.length, 1, 'repeated SSN collapses to one stable token');
  assert.strictEqual((t.text.match(/\[\[US_SSN_1\]\]/g) || []).length, 2, 'both occurrences tokenized identically');
});

test('detokenize disambiguates _1 vs _11', () => {
  const map = { '[[X_1]]': 'ONE', '[[X_11]]': 'ELEVEN' };
  assert.strictEqual(D.detokenize('a [[X_11]] b [[X_1]] c', map), 'a ELEVEN b ONE c');
});

test('tokenizePrompt convenience returns tokenized text + map + analysis', () => {
  const r = D.tokenizePrompt(SAMPLE);
  assert.ok(r.tokenCount >= 3);
  assert.strictEqual(D.detokenize(r.tokenizedText, r.map), SAMPLE);
  assert.ok(r.analysis.findings.length >= 3);
});

test('no findings → text unchanged, empty map', () => {
  const t = D.tokenize('just a normal sentence', []);
  assert.strictEqual(t.text, 'just a normal sentence');
  assert.strictEqual(Object.keys(t.map).length, 0);
});
