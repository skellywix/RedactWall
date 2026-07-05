// @tier smoke
'use strict';
/**
 * Detector: alwaysBlock regression through the real API. These entity types
 * must be withheld (status "pending") even when the org enforcement mode is
 * "warn" - hard-stop entities override the mode. A merely-sensitive prompt
 * without a hard-stop entity is only warned in the same policy, proving the
 * block came from alwaysBlock and not from the mode.
 */
const test = require('node:test');
const assert = require('node:assert');

const support = require('../support/app');
support.bootEnv({
  policy: {
    enforcementMode: 'warn',
    blockMinSeverity: 2,
    blockRiskScore: 20,
    storeRawForApproval: false,
    rawRetentionDays: 30,
    alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'SECRET_KEY', 'PRIVATE_KEY'],
  },
});
const app = support.requireApp();

const ALWAYS_BLOCK_SAMPLES = [
  ['US_SSN', 'Synthetic member SSN 123-45-6789 for this review.'],
  ['CREDIT_CARD', 'Synthetic dispute for card 4111 1111 1111 1111 exp 09/27.'],
  ['BANK_ACCOUNT', 'Synthetic bank account number 123456789012 on file.'],
  ['ROUTING_NUMBER', 'Synthetic ACH routing number 021000021 for the transfer.'],
  ['IBAN', 'Synthetic wire to IBAN DE89 3704 0044 0532 0130 00 please.'],
  ['US_PASSPORT', 'Synthetic traveler passport 123456789 for the visa letter.'],
  ['SECRET_KEY', 'Synthetic AWS key AKIA1234567890ABCDEF found in config.'],
  ['PRIVATE_KEY', 'Synthetic key material -----BEGIN RSA PRIVATE KEY----- MIIEow=='],
];

test('every alwaysBlock entity type is withheld by POST /api/v1/gate even in warn mode', async () => support.withServer(app, async (port) => {
  for (const [type, prompt] of ALWAYS_BLOCK_SAMPLES) {
    const res = await support.gate(port, {
      prompt,
      user: 'jane.doe@example.com',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    });
    assert.strictEqual(res.status, 200, type);
    const body = await res.json();
    assert.strictEqual(body.decision, 'block', `${type} must decide block, got ${body.decision}`);
    assert.strictEqual(body.status, 'pending', `${type} must be withheld pending approval, got ${body.status}`);
    assert.strictEqual(body.mode, 'block', `${type} must hard-stop despite warn mode`);
    assert.ok(body.findings.some((f) => f.type === type), `${type} finding missing: ${JSON.stringify(body.findings.map((f) => f.type))}`);
    assert.ok(!body.receipt, `${type}: a held prompt must not get a safe-to-send receipt`);
  }
}));

test('a sensitive prompt without a hard-stop entity is only warned in warn mode', async () => support.withServer(app, async (port) => {
  const res = await support.gate(port, {
    prompt: 'Contact synthetic member at jane.doe@example.com or 415-555-0182 about the branch survey.',
    user: 'jane.doe@example.com',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.notStrictEqual(body.status, 'pending', `non-hard-stop content must not be withheld (got ${body.status})`);
}));
