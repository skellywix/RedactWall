'use strict';
/** Canary fire drill should prove detection without leaking the planted token. */
const test = require('node:test');
const assert = require('node:assert');
const drill = require('../scripts/fire-drill');

test('canary fire drill token and prompt use detector-compatible shape', () => {
  const token = drill.makeCanaryToken('demo');
  assert.match(token, /^PS-CANARY-[A-Z0-9_-]{12,40}$/);
  assert.ok(drill.makePrompt(token).includes(token));
});

test('fire drill accepts block or redact responses that mask canary findings', () => {
  const token = drill.makeCanaryToken('pass');
  const result = drill.assertFireDrillResponse({
    id: 'q_1',
    decision: 'block',
    status: 'pending',
    riskScore: 80,
    findings: [{ type: 'CANARY_TOKEN', masked: '[CANARY_TOKEN]' }],
  }, token);
  assert.deepStrictEqual(result.findings, ['CANARY_TOKEN']);
  assert.strictEqual(result.decision, 'block');
});

test('fire drill fails when canary is missing', () => {
  const token = drill.makeCanaryToken('missing');
  assert.throws(() => drill.assertFireDrillResponse({
    decision: 'block',
    findings: [{ type: 'US_SSN', masked: '***' }],
  }, token), /CANARY_TOKEN was not detected/);
});

test('fire drill fails if the raw canary appears in response JSON', () => {
  const token = drill.makeCanaryToken('leak');
  assert.throws(() => drill.assertFireDrillResponse({
    decision: 'redact',
    status: 'redacted',
    tokenizedPrompt: `unsafe ${token}`,
    findings: [{ type: 'CANARY_TOKEN', masked: '[CANARY_TOKEN]' }],
  }, token), /raw canary token appeared/);
});
