'use strict';
/**
 * Detection precision/recall fixture for the shared engine.
 *
 *   node --test            # run everything
 *
 * Three buckets:
 *   1. TRUE POSITIVES — sensitive data that must be caught.
 *   2. FALSE-POSITIVE BAIT — ordinary ids that must NOT hard-block. This is the
 *      bucket that protects admin trust; a tool that cries wolf gets turned off.
 *   3. SEMANTIC GAPS — paraphrased confidential meaning the heuristic misses
 *      today, tracked as `todo` so they become the target for the real model.
 */
const test = require('node:test');
const assert = require('node:assert');
const D = require('../shared/detect');

const find = (text) => D.analyze(text);
const hasType = (text, t) => find(text).findings.some((f) => f.type === t);
const hasCat = (text, c) => find(text).categories.some((x) => x.category === c);

// ---------------------------------------------------------------------------
test('true positives — structured PII is caught', () => {
  assert.ok(hasType('Member SSN is 123-45-6789 on file', 'US_SSN'), 'dashed SSN');
  assert.ok(hasType('ssn 123 45 6789', 'US_SSN'), 'space-separated SSN');
  assert.ok(hasType('social security number 123456789', 'US_SSN'), 'bare SSN with context');
  assert.ok(hasType('card 4111 1111 1111 1111 exp 09/27', 'CREDIT_CARD'), 'Visa with separators');
  assert.ok(hasType('card on file 4111111111111111', 'CREDIT_CARD'), 'bare Visa with context');
  assert.ok(hasType('amex 378282246310005', 'CREDIT_CARD'), 'Amex (15-digit)');
  assert.ok(hasType('ABA routing number 011000015', 'ROUTING_NUMBER'), 'routing with context');
  assert.ok(hasType('bank account number 123456789012 is in the loan file', 'BANK_ACCOUNT'), 'bank account with context');
  assert.ok(hasType('ACH debit account 000123456789 at First Bank', 'BANK_ACCOUNT'), 'ACH account with context');
  assert.ok(hasType('here is the key AKIAIOSFODNN7EXAMPLE', 'SECRET_KEY'), 'AWS access key id');
  assert.ok(hasType('-----BEGIN RSA PRIVATE KEY-----', 'PRIVATE_KEY'), 'private key header');
  assert.ok(hasType('fake record marker PS-CANARY-DEMO2026ABCDEF should never leave', 'CANARY_TOKEN'), 'planted canary token');
  assert.ok(hasType('email me at jane.doe@example.com', 'EMAIL_ADDRESS'), 'email');
});

test('true positives — hard-stop entities reach critical severity', () => {
  assert.strictEqual(find('SSN 123-45-6789').maxSeverityLabel, 'critical');
  assert.strictEqual(find('card 4111 1111 1111 1111').maxSeverityLabel, 'critical');
});

test('semantic — literal confidential markers are caught', () => {
  assert.ok(hasCat('CONFIDENTIAL — internal only, do not share externally', 'CONFIDENTIAL_BUSINESS'));
  assert.ok(hasCat('function foo(){ const x = 1; return x; } class A {}', 'SOURCE_CODE'));
});

// ---------------------------------------------------------------------------
test('false-positive bait — ordinary 9-digit ids are NOT SSNs', () => {
  assert.ok(!hasType('Your order number is 122105155 ships Tuesday', 'US_SSN'), 'order number');
  assert.ok(!hasType('reference 271234567 attached to the ticket', 'US_SSN'), 'reference number');
  assert.ok(!hasType('confirmation 480152637 for your records', 'US_SSN'), 'confirmation number');
});

test('false-positive bait — bare 9-digit ids are NOT routing numbers', () => {
  assert.ok(!hasType('Your order number is 122105155 ships Tuesday', 'ROUTING_NUMBER'));
  assert.ok(!hasType('reference 271234567 attached', 'ROUTING_NUMBER'));
});

test('false-positive bait — ordinary account language is NOT a bank account number', () => {
  assert.ok(!hasType('support account 122105155 was updated today', 'BANK_ACCOUNT'));
  assert.ok(!hasType('account holder phone 415-555-0182 is preferred', 'BANK_ACCOUNT'));
});

test('false-positive bait — canary discussion is NOT a canary token', () => {
  assert.ok(!hasType('we should add a canary token to the demo playbook', 'CANARY_TOKEN'));
  assert.ok(!hasType('PS-CANARY is the prefix format, not a live marker', 'CANARY_TOKEN'));
});

test('false-positive bait — random 16-digit ids are NOT credit cards', () => {
  assert.ok(!hasType('transaction id 4929939187355598 posted', 'CREDIT_CARD'), 'Luhn-passing id, no context');
  assert.ok(!hasType('ticket 6011000000000004 escalated', 'CREDIT_CARD'), 'valid BIN but no separators/context');
});

test('false-positive rate on random ids stays low', () => {
  const N = 100000;
  let ssn = 0, cc = 0, rt = 0;
  for (let i = 0; i < N; i++) {
    const d9 = String(Math.floor(100000000 + Math.random() * 900000000));
    const a9 = find('order ref ' + d9);
    if (a9.findings.some((f) => f.type === 'US_SSN')) ssn++;
    if (a9.findings.some((f) => f.type === 'ROUTING_NUMBER')) rt++;
    let d16 = ''; for (let k = 0; k < 16; k++) d16 += Math.floor(Math.random() * 10);
    if (find('txn ' + d16).findings.some((f) => f.type === 'CREDIT_CARD')) cc++;
  }
  assert.ok(ssn / N < 0.001, `SSN FP rate ${(100 * ssn / N).toFixed(3)}% should be < 0.1%`);
  assert.ok(rt / N < 0.001, `ROUTING FP rate ${(100 * rt / N).toFixed(3)}% should be < 0.1%`);
  assert.ok(cc / N < 0.005, `CREDIT_CARD FP rate ${(100 * cc / N).toFixed(3)}% should be < 0.5%`);
});

// ---------------------------------------------------------------------------
// SEMANTIC MODEL — the compact on-device classifier (shared/detect.js, trained
// by scripts/train-semantic.js) catches paraphrased meaning the keyword
// heuristic misses, while keeping zero false positives on benign prompts.
test('semantic — paraphrased vendor switch (model)', () => {
  assert.ok(hasCat("Between us, we're thinking about switching away from Acme next quarter. Keep this internal.", 'CONFIDENTIAL_BUSINESS'));
});
test('semantic — layoff euphemism before a merger (model)', () => {
  assert.ok(hasCat('We plan to reduce headcount by 15% in the northeast before the deal closes. Not public yet.', 'CONFIDENTIAL_BUSINESS'));
});
test('semantic — source code without keyword tokens (model)', () => {
  assert.ok(hasCat('for i in range(10):\n    total += prices[i] * 1.07\n    log(total)', 'SOURCE_CODE'));
});

// Novel phrasings NOT used verbatim in training — proves generalization, not memorization.
test('semantic — generalizes to unseen confidential phrasings', () => {
  assert.ok(hasCat('Quietly, leadership wants to drop our current processor before renewal — do not forward.', 'CONFIDENTIAL_BUSINESS'));
  assert.ok(hasCat('We may trim about a fifth of the support org ahead of the transaction; still under wraps.', 'CONFIDENTIAL_BUSINESS'));
});
test('semantic — generalizes to unseen code', () => {
  assert.ok(hasCat('total = 0\nfor row in rows:\n    total = total + row[2]\n', 'SOURCE_CODE'));
});

// The bucket that protects admin trust: ordinary business prompts must NOT be
// flagged as confidential/code by the model.
test('semantic — no false positives on benign business prompts', () => {
  const benign = [
    'Help me write a Python function to parse CSV files for our reporting tool.',
    'Summarize this email thread about our Q3 roadmap into 3 bullet points.',
    'What are best practices for NCUA examination preparation this year?',
    'Draft a payoff letter for a member who closed their auto loan.',
    'What documents do I need to open a business checking account?',
    'Explain the difference between APR and APY in simple terms.',
  ];
  for (const t of benign) {
    assert.strictEqual(find(t).categories.length, 0, 'benign prompt should have no semantic category: ' + t);
  }
});
