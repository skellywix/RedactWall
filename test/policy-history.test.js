'use strict';
/** Policy governance diffs must be examiner-readable without exposing audit detail text. */
const test = require('node:test');
const assert = require('node:assert');
const policy = require('../server/policy');
const evidence = require('../server/evidence');

test('destination policy matches hosts, URLs, labels, and wildcards', () => {
  assert.strictEqual(policy.destinationMatches('https://www.chatgpt.com/c/abc', ['chatgpt.com']), true);
  assert.strictEqual(policy.destinationMatches('chat.deepseek.com', ['*.deepseek.com']), true);
  assert.strictEqual(policy.destinationMatches('deepseek.com', ['*.deepseek.com']), false);
  assert.strictEqual(policy.destinationMatches('Desktop AI', ['desktop-ai']), true);
  assert.strictEqual(policy.destinationBlocked('poe.com', { blockedDestinations: ['poe.com'] }), true);
  assert.strictEqual(policy.fileUploadBlocked('https://chatgpt.com/c/abc', { blockedFileUploadDestinations: ['chatgpt.com'] }), true);
});

test('policy change detail records normalized before-after changes', () => {
  const before = {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 25,
    alwaysBlock: ['US_SSN', 'CREDIT_CARD'],
    scanner: { ignoreExtensions: ['.log', '.tmp'], maxFileBytes: 1024 },
  };
  const after = {
    ...before,
    enforcementMode: 'redact',
    alwaysBlock: ['CREDIT_CARD', 'US_SSN'],
    scanner: { ignoreExtensions: ['.tmp', '.log'], maxFileBytes: 2048 },
  };

  const detail = JSON.parse(policy.policyChangeDetail(before, after, { templateId: 'redact_first' }));
  assert.strictEqual(detail.type, 'policy_change');
  assert.strictEqual(detail.templateId, 'redact_first');
  assert.deepStrictEqual(detail.changed.map((c) => c.field), ['enforcementMode', 'scanner']);
  assert.deepStrictEqual(detail.changed[0], { field: 'enforcementMode', before: 'block', after: 'redact' });
  assert.strictEqual(detail.changed[1].before.maxFileBytes, 1024);
  assert.strictEqual(detail.changed[1].after.maxFileBytes, 2048);
});

test('evidence exports parsed policy changes but not raw audit detail text', () => {
  const detail = policy.policyChangeDetail(
    { enforcementMode: 'block', blockRiskScore: 25, rawRetentionDays: 30 },
    { enforcementMode: 'justify', blockRiskScore: 40, rawRetentionDays: 14 },
  );
  const entry = evidence.safeAuditEntry({
    id: 'a_policy',
    ts: '2026-06-26T12:00:00.000Z',
    action: 'POLICY_UPDATED',
    actor: 'admin',
    detail,
    prevHash: '0'.repeat(64),
    hash: '1'.repeat(64),
  });

  assert.ok(entry.detailHash);
  assert.deepStrictEqual(entry.policyChange.changed, [
    { field: 'enforcementMode', before: 'block', after: 'justify' },
    { field: 'blockRiskScore', before: 25, after: 40 },
    { field: 'rawRetentionDays', before: 30, after: 14 },
  ]);
  assert.ok(!JSON.stringify(entry).includes('"type":"policy_change"'));
});

test('evidence ignores arbitrary policy audit detail shapes', () => {
  const entry = evidence.safeAuditEntry({
    id: 'a_policy',
    ts: '2026-06-26T12:00:00.000Z',
    action: 'POLICY_UPDATED',
    actor: 'admin',
    detail: '{"type":"policy_change","changed":[{"field":"rawPrompt","before":"member SSN 524-71-9043","after":"still bad"}]}',
    prevHash: '0'.repeat(64),
    hash: '1'.repeat(64),
  });

  assert.ok(entry.policyChange);
  assert.deepStrictEqual(entry.policyChange.changed, []);
  assert.ok(!JSON.stringify(entry).includes('524-71-9043'));
});
