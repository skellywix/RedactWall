'use strict';
/**
 * Regression tests for the engine audit fixes (detection-engine/detect.js).
 *
 * Each test below fails on the pre-fix engine and passes after. The two HIGH
 * findings are called out; the medium/low fixes are guarded here too so they
 * cannot silently regress.
 */
const test = require('node:test');
const assert = require('node:assert');
const D = require('../detection-engine/detect');

const hasType = (res, t) => res.findings.some((f) => f.type === t);

// ---------------------------------------------------------------------------
// HIGH — detectStructured zero-length-match infinite loop.
// A custom detector whose regex can match the empty string used to spin the
// per-keystroke hot path forever. It must now be rejected at normalize time,
// and analyze() must return promptly regardless.
// ---------------------------------------------------------------------------
test('HIGH: empty-matchable custom detector is rejected and never hangs analyze', () => {
  const packs = [
    { id: 'ACME_ID', pattern: '(ACME)?[0-9]*' },
    { id: 'ALLCAPS', pattern: '[A-Z]*' },
  ];
  assert.strictEqual(D.normalizeCustomDetectors(packs).length, 0, 'empty-matchable patterns dropped');

  const started = Date.now();
  const res = D.analyze('hello world', { customDetectors: packs });
  assert.ok(Array.isArray(res.findings), 'analyze returned a result');
  assert.ok(Date.now() - started < 2000, 'analyze did not hang');
});

test('HIGH: a well-formed custom detector still fires (no over-correction)', () => {
  const packs = [{ id: 'X_TICKET', pattern: 'TCK-[0-9]{4}' }];
  assert.strictEqual(D.normalizeCustomDetectors(packs).length, 1);
  assert.ok(hasType(D.analyze('ref TCK-1234 open', { customDetectors: packs }), 'X_TICKET'));
});

// ---------------------------------------------------------------------------
// HIGH — US_DRIVERS_LICENSE over-broad regex.
// Bare words after "license" (no digit) must not fire, the value must be the
// id (group 1) not the whole "license <word>" span, and real DL numbers with a
// filler word ("license number A1B2C3D4") must still be caught.
// ---------------------------------------------------------------------------
test('HIGH: ordinary "license <word>" does not fire US_DRIVERS_LICENSE', () => {
  for (const s of [
    'please review this license agreement before signing',
    'license renewal is due next month',
    'the software license terms changed',
  ]) {
    assert.ok(!hasType(D.analyze(s), 'US_DRIVERS_LICENSE'), s);
  }
});

test('HIGH: real driver license numbers fire with the id as the value', () => {
  const cases = [
    ["Verify driver's license # D4821736 against the scan.", 'D4821736'],
    ['DL# D1234567 for the loan applicant', 'D1234567'],
    ['license number A1B2C3D4 recorded at account opening', 'A1B2C3D4'],
  ];
  for (const [text, value] of cases) {
    const f = D.analyze(text).findings.find((x) => x.type === 'US_DRIVERS_LICENSE');
    assert.ok(f, 'fired for: ' + text);
    assert.strictEqual(f.value, value, 'value is the id span for: ' + text);
  }
});

// ---------------------------------------------------------------------------
// MEDIUM/LOW guards for the remaining audit fixes.
// ---------------------------------------------------------------------------
test('IBAN followed by a plain word is still detected (no greedy swallow)', () => {
  const f = D.analyze('Wire to DE89370400440532013000 ASAP').findings
    .find((x) => x.type === 'IBAN');
  assert.ok(f, 'IBAN detected before trailing word');
  assert.strictEqual(f.value, 'DE89370400440532013000');
  assert.ok(hasType(D.analyze('IBAN GB82 WEST 1234 5698 7654 32 now'), 'IBAN'), 'spaced IBAN still detected');
});

test('overlapping-alternation custom regex is rejected (ReDoS guard)', () => {
  assert.strictEqual(D.normalizeCustomDetectors([{ id: 'RD_ONE', pattern: '([0-9]|\\d)+X' }]).length, 0);
});

test('EDM matches a high-entropy number written with separators', () => {
  const salt = 'unit-salt-0123456789abcdef0123456789';
  const cfg = {
    formatVersion: 2,
    algorithm: 'sha256',
    valuePolicy: 'offline-random-id-v1',
    salt,
    minLen: 20,
    maxWords: 1,
    fingerprints: [D.edmFingerprint('123456789012345678901234567890', salt)],
  };
  assert.ok(hasType(D.analyze('order 1234567890-1234567890-1234567890 shipped', { exactMatch: cfg }), 'EXACT_MATCH'));
});

test('compressed IPv6 addresses are detected', () => {
  assert.ok(hasType(D.analyze('host at 2001:db8::1 today'), 'IPV6_ADDRESS'), '2001:db8::1');
  assert.ok(hasType(D.analyze('link-local fe80::1 on eth0'), 'IPV6_ADDRESS'), 'fe80::1');
  assert.ok(hasType(D.analyze('gw 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up'), 'IPV6_ADDRESS'), 'full form still works');
});

test('ITIN with a middle group in the 50-65 range is detected', () => {
  assert.ok(hasType(D.analyze('Applicant ITIN 900-50-1234 on the W-7'), 'US_ITIN'), 'group 50');
  assert.ok(hasType(D.analyze('tin 912-70-1234 on file'), 'US_ITIN'), 'group 70 unaffected');
});

test('capitalized titles trigger PERSON_NAME', () => {
  const names = D.analyze('Dr. Jane Doe met Mr. John Smith').findings
    .filter((f) => f.type === 'PERSON_NAME').map((f) => f.value);
  assert.ok(names.includes('Jane Doe'), 'Dr. Jane Doe');
  assert.ok(names.includes('John Smith'), 'Mr. John Smith');
});

test('classifySemantic still classifies correctly after featurization reuse', () => {
  const res = D.analyze('function foo(x){ return x*2; } const y = foo(3);');
  assert.ok(res.categories.some((c) => c.category === 'SOURCE_CODE'), 'source code still detected');
  // Public _lrProb signature preserved.
  assert.strictEqual(typeof D._lrProb('some text', 'SOURCE_CODE'), 'number');
});
