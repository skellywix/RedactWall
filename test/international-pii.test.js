'use strict';
/** Checksum-validated, context-anchored international government identifiers. */
const test = require('node:test');
const assert = require('node:assert');
const D = require('../detection-engine/detect');

function types(text) {
  return D.analyze(text).findings.map((f) => f.type);
}

test('UK National Insurance number is detected with context', () => {
  assert.ok(types('Employee national insurance number AB 12 34 56 C is on file.').includes('UK_NINO'));
});

test('UK NHS number requires a valid mod-11 check digit', () => {
  assert.ok(D.nhsValid('9434765919'));
  assert.ok(!D.nhsValid('9434765918'));
  assert.ok(types('Patient NHS number 943 476 5919 verified.').includes('UK_NHS_NUMBER'));
});

test('Canadian SIN validates via Luhn and needs context', () => {
  assert.ok(D.sinValid('046454286'));
  assert.ok(!D.sinValid('046454287'));
  assert.ok(types('Her SIN is 046-454-286 for payroll.').includes('CANADA_SIN'));
});

test('Australian TFN validates via weighted mod-11', () => {
  assert.ok(D.tfnValid('123456782'));
  assert.ok(types('Tax file number 123 456 782 for the ATO form.').includes('AUSTRALIA_TFN'));
});

test('India Aadhaar validates via Verhoeff checksum', () => {
  assert.ok(D.aadhaarValid('234123412346'));
  assert.ok(!D.aadhaarValid('234123412347'));
  assert.ok(types('Aadhaar number 2341 2341 2346 for KYC.').includes('INDIA_AADHAAR'));
});

test('context-free lookalikes do NOT fire international detectors', () => {
  assert.ok(!types('Batch label AB 12 34 56 C printed for the pallet.').includes('UK_NINO'));
  assert.ok(!types('Conference room booking code 046 454 286 all afternoon.').includes('CANADA_SIN'));
});
