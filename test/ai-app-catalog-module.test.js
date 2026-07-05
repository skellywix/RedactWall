'use strict';
/** AI app risk catalog: reviewed risk attributes keyed by normalized host. */
const test = require('node:test');
const assert = require('node:assert');
const { CATALOG, riskAttributes, TIER_LABEL } = require('../server/ai-app-catalog');

test('every catalog entry has the attributes buyers ask about', () => {
  assert.ok(CATALOG.length > 0);
  for (const entry of CATALOG) {
    assert.strictEqual(typeof entry.host, 'string');
    assert.strictEqual(typeof entry.provider, 'string');
    assert.ok(['US', 'EU', 'CN'].includes(entry.region), `unexpected region ${entry.region}`);
    assert.ok(entry.riskTier >= 1 && entry.riskTier <= 4);
    assert.strictEqual(typeof entry.trainsOnData, 'string');
  }
});

test('riskAttributes resolves a known destination with derived flags', () => {
  const attrs = riskAttributes('chatgpt.com');
  assert.strictEqual(attrs.provider, 'OpenAI');
  assert.strictEqual(attrs.region, 'US');
  assert.strictEqual(attrs.personalTier, true);
  assert.strictEqual(attrs.riskTier, 3);
  assert.strictEqual(attrs.riskTierLabel, TIER_LABEL[3]);
  assert.ok(attrs.flags.includes('trains_on_data'));
  assert.ok(attrs.flags.includes('personal_account_tier'));
  assert.ok(!attrs.flags.some((f) => f.startsWith('data_residency_')), 'US region adds no residency flag');
});

test('riskAttributes adds a data-residency flag for non-US operators', () => {
  const attrs = riskAttributes('chat.deepseek.com');
  assert.strictEqual(attrs.region, 'CN');
  assert.strictEqual(attrs.riskTier, 4);
  assert.strictEqual(attrs.riskTierLabel, 'high');
  assert.ok(attrs.flags.includes('data_residency_cn'));
});

test('riskAttributes normalizes host input (scheme, www, path, case)', () => {
  const base = riskAttributes('claude.ai');
  assert.deepStrictEqual(riskAttributes('https://www.Claude.ai/chat'), base);
  assert.deepStrictEqual(riskAttributes('  CLAUDE.AI  '), base);
});

test('opt-in training providers do not carry the trains_on_data flag', () => {
  const attrs = riskAttributes('claude.ai');
  assert.strictEqual(attrs.trainsOnData, 'opt_in');
  assert.ok(!attrs.flags.includes('trains_on_data'));
});

test('riskAttributes returns null for unknown or empty destinations', () => {
  assert.strictEqual(riskAttributes('example.test'), null);
  assert.strictEqual(riskAttributes(''), null);
  assert.strictEqual(riskAttributes(null), null);
});
