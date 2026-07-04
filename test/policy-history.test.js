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
  assert.strictEqual(policy.destinationMatches('chat.openai.com', ['*openai.com']), true);
  assert.strictEqual(policy.destinationMatches('openai.com', ['*openai.com']), true);
  assert.strictEqual(policy.destinationMatches('Desktop AI', ['desktop-ai']), true);
  assert.strictEqual(policy.normalizeDestination('www.bad host%%%/prompt#frag'), 'bad-host%%%');
  assert.strictEqual(policy.destinationBlocked('poe.com', { blockedDestinations: ['poe.com'] }), true);
  assert.strictEqual(policy.destinationAllowed('chatgpt.com', { allowedDestinations: ['chatgpt.com'] }), true);
  assert.strictEqual(policy.destinationBlocked('chatgpt.com', { blockedDestinations: ['*'], allowedDestinations: ['chatgpt.com'] }), false);
  assert.strictEqual(policy.unapprovedAiDestination('notebooklm.google.com', { blockUnapprovedAiDestinations: true }), true);
  assert.strictEqual(policy.destinationBlocked('notebooklm.google.com', { blockUnapprovedAiDestinations: true }), true);
  assert.strictEqual(policy.destinationBlocked('notebooklm.google.com', { blockUnapprovedAiDestinations: true, allowedDestinations: ['notebooklm.google.com'] }), false);
  assert.strictEqual(policy.destinationBlockReason('notebooklm.google.com', { blockUnapprovedAiDestinations: true }), 'Unapproved AI destination blocked by policy');
  assert.strictEqual(policy.destinationBlockReason('internal-ai.example', { blockedDestinations: [] }), 'Destination blocked by policy');
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

test('policy normalizes customer approval routing rules for audit and runtime', () => {
  const rules = policy.normalizeApprovalRoutingRules([
    {
      id: 'Member_Services',
      detectors: ['member_id', 'MEMBER_ID'],
      destinations: ['ChatGPT.com'],
      assignedGroup: 'Member_Services',
      assignedRole: 'approver',
      slaMinutes: 120.2,
      reason: 'member_services',
    },
    {
      id: 'member_services',
      detectors: ['US_SSN'],
      assignedGroup: 'compliance',
      assignedRole: 'approver',
      slaMinutes: 60,
    },
    {
      id: 'catch_all',
      assignedGroup: 'security',
      assignedRole: 'security_admin',
      slaMinutes: 60,
    },
    {
      id: 'member_524_71_9043',
      detectors: ['MEMBER_ID'],
      assignedGroup: 'compliance',
      assignedRole: 'approver',
      slaMinutes: 60,
    },
    {
      id: 'bad rule',
      assignedGroup: 'member services',
      assignedRole: 'owner',
      slaMinutes: 5,
    },
  ]);

  assert.deepStrictEqual(rules, [{
    id: 'member_services',
    enabled: true,
    assignedGroup: 'member_services',
    assignedRole: 'approver',
    slaMinutes: 120,
    reason: 'member_services',
    detectors: ['MEMBER_ID'],
    destinations: ['ChatGPT.com'],
  }]);

  const detail = JSON.parse(policy.policyChangeDetail(
    { approvalRoutingRules: [] },
    { approvalRoutingRules: rules },
  ));
  assert.deepStrictEqual(detail.changed, [{
    field: 'approvalRoutingRules',
    before: [],
    after: rules,
  }]);
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

test('evidence exports scoped-policy metadata without raw prompt bodies', () => {
  const safe = evidence.safeQuery({
    id: 'q_scoped',
    createdAt: '2026-06-28T12:00:00.000Z',
    status: 'allowed',
    mode: 'block',
    user: 'counsel@example.test',
    destination: 'claude.ai',
    riskScore: 20,
    maxSeverity: 2,
    maxSeverityLabel: 'medium',
    redactedPrompt: '[REDACTED:LEGAL_CONTRACT]',
    policyScopeIds: ['legal_contract_review'],
    policyExceptionId: 'legal_vendor_24h',
    _rawPrompt: 'member SSN 524-71-9043',
  });

  assert.deepStrictEqual(safe.policyScopeIds, ['legal_contract_review']);
  assert.strictEqual(safe.policyExceptionId, 'legal_vendor_24h');
  assert.ok(!JSON.stringify(safe).includes('524-71-9043'));
});

test('evidence exports scoped policy changes', () => {
  const scope = [{
    id: 'legal_contract_review',
    groups: ['promptwall legal'],
    categories: ['LEGAL_CONTRACT'],
    destinations: ['claude.ai'],
    enforcementMode: 'block',
    blockMinSeverity: 2,
  }];
  const detail = policy.policyChangeDetail(
    { policyScopes: [], policyExceptions: [] },
    {
      policyScopes: scope,
      policyExceptions: [{
        id: 'legal_vendor_24h',
        users: ['counsel@example.test'],
        categories: ['LEGAL_CONTRACT'],
        expiresAt: '2030-01-01T00:00:00.000Z',
      }],
    },
  );
  const entry = evidence.safeAuditEntry({
    id: 'a_scope',
    ts: '2026-06-28T12:00:00.000Z',
    action: 'POLICY_UPDATED',
    actor: 'admin',
    detail,
    prevHash: '0'.repeat(64),
    hash: '1'.repeat(64),
  });

  assert.deepStrictEqual(entry.policyChange.changed.map((item) => item.field), ['policyScopes', 'policyExceptions']);
  assert.deepStrictEqual(entry.policyChange.changed[0].after, scope);
});

test('evidence exports sanitized exception review state', () => {
  const pack = evidence.buildEvidencePack({
    generatedAt: '2026-06-28T12:00:00.000Z',
    version: '0.0.0-test',
    queryLimit: 500,
    auditLimit: 500,
    policy: { policyExceptions: [] },
    stats: {},
    auditIntegrity: { ok: true, count: 0 },
    coverage: {},
    detectors: [],
    queries: [],
    audit: [],
    policyExceptionReview: {
      generatedAt: '2026-06-28T12:00:00.000Z',
      reviewWindowDays: 7,
      total: 1,
      active: 1,
      disabled: 0,
      expired: 0,
      reviewDue: 1,
      expiringSoon: 0,
      items: [{
        id: 'legal_vendor_24h',
        enabled: true,
        action: 'allow',
        expiresAt: '2026-06-29T12:00:00.000Z',
        ownerGroup: 'legal',
        reviewerRole: 'security_admin',
        reviewAfter: '2026-06-28T00:00:00.000Z',
        status: 'review_due',
        user: 'counsel@example.test',
      }],
    },
  });

  assert.deepStrictEqual(pack.policyExceptionReview.items, [{
    id: 'legal_vendor_24h',
    enabled: true,
    action: 'allow',
    expiresAt: '2026-06-29T12:00:00.000Z',
    ownerGroup: 'legal',
    reviewerRole: 'security_admin',
    reviewAfter: '2026-06-28T00:00:00.000Z',
    status: 'review_due',
  }]);
  assert.ok(!JSON.stringify(pack.policyExceptionReview).includes('counsel@example.test'));
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
