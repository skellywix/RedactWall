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
  assert.strictEqual(policy.destinationAllowed('chatgpt.com', { allowedDestinations: ['chatgpt.com'] }), true);
  assert.strictEqual(policy.destinationBlocked('chatgpt.com', { blockedDestinations: ['*'], allowedDestinations: ['chatgpt.com'] }), false);
  assert.strictEqual(policy.unapprovedAiDestination('notebooklm.google.com', { blockUnapprovedAiDestinations: true }), true);
  assert.strictEqual(policy.destinationBlocked('notebooklm.google.com', { blockUnapprovedAiDestinations: true }), true);
  assert.strictEqual(policy.destinationBlocked('notebooklm.google.com', { blockUnapprovedAiDestinations: true, allowedDestinations: ['notebooklm.google.com'] }), false);
  assert.strictEqual(policy.destinationBlockReason('notebooklm.google.com', { blockUnapprovedAiDestinations: true }), 'Unapproved AI destination blocked by policy');
  assert.strictEqual(policy.fileUploadBlocked('chatgpt.com', { blockedFileUploadDestinations: ['*'], allowedDestinations: ['chatgpt.com'] }), false);
  assert.strictEqual(policy.fileUploadBlocked('https://chatgpt.com/c/abc', { blockedFileUploadDestinations: ['chatgpt.com'] }), true);
});

test('destination review moves normalized destinations between policy lists', () => {
  const current = {
    governedDestinations: ['poe.com', 'chatgpt.com'],
    allowedDestinations: ['chatgpt.com'],
    blockedDestinations: ['poe.com'],
    blockedFileUploadDestinations: ['poe.com'],
  };

  const allowed = policy.reviewDestination(current, 'https://www.Poe.com/chat', 'allow');
  assert.strictEqual(allowed.destination, 'poe.com');
  assert.strictEqual(allowed.decision, 'allow');
  assert.deepStrictEqual(allowed.policy.governedDestinations, ['chatgpt.com']);
  assert.deepStrictEqual(allowed.policy.allowedDestinations, ['chatgpt.com', 'poe.com']);
  assert.deepStrictEqual(allowed.policy.blockedDestinations, []);
  assert.deepStrictEqual(allowed.policy.blockedFileUploadDestinations, []);

  const blocked = policy.reviewDestination(allowed.policy, 'poe.com', 'block');
  assert.deepStrictEqual(blocked.policy.allowedDestinations, ['chatgpt.com']);
  assert.deepStrictEqual(blocked.policy.blockedDestinations, ['poe.com']);

  const governed = policy.reviewDestination(blocked.policy, 'poe.com', 'govern');
  assert.deepStrictEqual(governed.policy.blockedDestinations, []);
  assert.ok(governed.policy.governedDestinations.includes('poe.com'));
  assert.throws(() => policy.reviewDestination(current, '', 'allow'), /destination required/);
  assert.throws(() => policy.reviewDestination(current, 'poe.com', 'ignore'), /unknown destination decision/);
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
    {
      enforcementMode: 'block',
      blockRiskScore: 25,
    rawRetentionDays: 30,
    blockedDestinations: [],
    blockedFileUploadDestinations: [],
    requiredSensors: ['browser_extension', 'endpoint_agent'],
    desiredSensorVersions: { browser_extension: '0.2.9' },
  },
  {
    enforcementMode: 'justify',
    blockRiskScore: 40,
    rawRetentionDays: 14,
    blockedDestinations: ['poe.com'],
    blockedFileUploadDestinations: ['chatgpt.com'],
    requiredSensors: ['browser_extension', 'endpoint_agent', 'mcp_guard'],
    desiredSensorVersions: { browser_extension: '0.3.0', endpoint_agent: '0.3.0' },
  },
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
    { field: 'blockedDestinations', before: [], after: ['poe.com'] },
    { field: 'blockedFileUploadDestinations', before: [], after: ['chatgpt.com'] },
    { field: 'requiredSensors', before: ['browser_extension', 'endpoint_agent'], after: ['browser_extension', 'endpoint_agent', 'mcp_guard'] },
    { field: 'desiredSensorVersions', before: { browser_extension: '0.2.9' }, after: { browser_extension: '0.3.0', endpoint_agent: '0.3.0' } },
  ]);
  assert.ok(!JSON.stringify(entry).includes('"type":"policy_change"'));
});

test('evidence exports destination-review policy changes', () => {
  const detail = policy.policyChangeDetail(
    { governedDestinations: ['poe.com'], allowedDestinations: [], blockedDestinations: [] },
    { governedDestinations: [], allowedDestinations: ['poe.com'], blockedDestinations: [] },
    { reason: 'Approved pilot for vendor comparison' },
  );
  const entry = evidence.safeAuditEntry({
    id: 'a_destination',
    ts: '2026-06-26T12:00:00.000Z',
    action: 'DESTINATION_REVIEWED',
    actor: 'admin',
    detail,
    prevHash: '0'.repeat(64),
    hash: '1'.repeat(64),
  });

  assert.strictEqual(entry.policyChange.reason, 'Approved pilot for vendor comparison');
  assert.deepStrictEqual(entry.policyChange.changed, [
    { field: 'governedDestinations', before: ['poe.com'], after: [] },
    { field: 'allowedDestinations', before: [], after: ['poe.com'] },
  ]);
  assert.ok(entry.detailHash);
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
