'use strict';
/** Scoped policy and exceptions must be metadata-only and fail closed. */
const test = require('node:test');
const assert = require('node:assert');
const policy = require('../server/policy');

function categoryAnalysis(category, overrides = {}) {
  return {
    findings: [],
    categories: [{ category, score: 0.9 }],
    entityCounts: { [category]: 1 },
    riskScore: 20,
    maxSeverity: 2,
    maxSeverityLabel: 'medium',
    ...overrides,
  };
}

test('policy scopes tighten enforcement for matching SCIM groups and destinations', () => {
  const verdict = policy.evaluate(categoryAnalysis('CONFIDENTIAL_BUSINESS'), {
    enforcementMode: 'warn',
    blockMinSeverity: 4,
    blockRiskScore: 90,
    alwaysBlock: ['US_SSN'],
    policyScopes: [{
      id: 'engineering_ai',
      groups: ['RedactWall Engineers'],
      destinations: ['chatgpt.com'],
      categories: ['CONFIDENTIAL_BUSINESS'],
      enforcementMode: 'block',
      blockMinSeverity: 2,
      blockRiskScore: 10,
      alwaysBlockAdd: ['SECRET_KEY'],
      reason: 'engineering_ai',
    }],
  }, {
    user: 'engineer@example.test',
    groups: ['RedactWall Engineers'],
    destination: 'https://chatgpt.com/c/unit',
    source: 'browser_extension',
    channel: 'submit',
  });

  assert.strictEqual(verdict.decision, 'block');
  assert.deepStrictEqual(verdict.policyScopeIds, ['engineering_ai']);
  assert.strictEqual(verdict.policy.enforcementMode, 'block');
  assert.strictEqual(verdict.policy.blockMinSeverity, 2);
  assert.strictEqual(verdict.policy.blockRiskScore, 10);
  assert.ok(verdict.policy.alwaysBlock.includes('SECRET_KEY'));
  assert.ok(verdict.reasons.some((reason) => reason.includes('Policy scope matched: engineering_ai')));
});

test('a matched scope does not block a sub-threshold finding on its own', () => {
  // Regression: a scope match used to push an unconditional block reason, so any
  // low-severity finding from a scoped user was force-blocked even when neither
  // the global nor the scope-tightened thresholds were crossed.
  const analysis = {
    findings: [{ type: 'IP_ADDRESS', severity: 1, score: 0.3 }],
    categories: [],
    entityCounts: { IP_ADDRESS: 1 },
    riskScore: 7,
    maxSeverity: 1,
    maxSeverityLabel: 'low',
  };
  const verdict = policy.evaluate(analysis, {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 25,
    alwaysBlock: ['US_SSN'],
    policyScopes: [{
      id: 'contractor_scope',
      groups: ['contractors'],
      alwaysBlockAdd: ['SOURCE_CODE'],
      reason: 'contractor_scope',
    }],
  }, {
    user: 'contractor@example.test',
    groups: ['contractors'],
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
  });

  assert.strictEqual(verdict.decision, 'allow', 'sub-threshold finding is not blocked by scope match alone');
  assert.deepStrictEqual(verdict.policyScopeIds, ['contractor_scope'], 'scope telemetry is still carried for allowed decisions');
  assert.ok(!verdict.reasons.some((reason) => reason.includes('Policy scope matched')),
    'no scope block reason is appended without another blocking reason');
});

test('policy scopes cannot weaken global enforcement or hard stops', () => {
  const verdict = policy.evaluate(categoryAnalysis('LEGAL_CONTRACT'), {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 25,
    alwaysBlock: ['US_SSN'],
    policyScopes: [{
      id: 'soft_legal',
      groups: ['Legal'],
      categories: ['LEGAL_CONTRACT'],
      enforcementMode: 'warn',
      blockMinSeverity: 4,
      blockRiskScore: 90,
    }],
  }, {
    groups: ['Legal'],
    destination: 'claude.ai',
  });

  assert.strictEqual(verdict.decision, 'block');
  assert.strictEqual(verdict.policy.enforcementMode, 'block');
  assert.strictEqual(verdict.policy.blockMinSeverity, 2);
  assert.strictEqual(verdict.policy.blockRiskScore, 25);
});

test('active time-bound exceptions allow matching non-hard-stop content', () => {
  const verdict = policy.evaluate(categoryAnalysis('LEGAL_CONTRACT'), {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 10,
    alwaysBlock: ['US_SSN'],
    policyExceptions: [{
      id: 'legal_vendor_24h',
      users: ['counsel@example.test'],
      destinations: ['claude.ai'],
      categories: ['LEGAL_CONTRACT'],
      expiresAt: '2030-01-01T00:00:00.000Z',
      ownerGroup: 'legal',
      reviewerRole: 'security_admin',
      reviewAfter: '2029-12-15T00:00:00.000Z',
      reason: 'approved_vendor_review',
    }],
  }, {
    user: 'counsel@example.test',
    destination: 'https://claude.ai/chat/unit',
  }, { now: new Date('2026-06-28T12:00:00.000Z') });

  assert.strictEqual(verdict.decision, 'allow');
  assert.strictEqual(verdict.policyExceptionId, 'legal_vendor_24h');
  assert.deepStrictEqual(verdict.reasons, ['Time-bound exception matched: legal_vendor_24h']);
});

test('expired exceptions and hard-stop findings fail closed', () => {
  const expired = policy.evaluate(categoryAnalysis('LEGAL_CONTRACT'), {
    enforcementMode: 'block',
    blockMinSeverity: 2,
    blockRiskScore: 10,
    alwaysBlock: ['US_SSN'],
    policyExceptions: [{
      id: 'expired_legal',
      users: ['counsel@example.test'],
      categories: ['LEGAL_CONTRACT'],
      expiresAt: '2026-01-01T00:00:00.000Z',
    }],
  }, {
    user: 'counsel@example.test',
  }, { now: new Date('2026-06-28T12:00:00.000Z') });
  assert.strictEqual(expired.decision, 'block');
  assert.strictEqual(expired.policyExceptionId, undefined);

  const hardStop = policy.evaluate({
    findings: [{ type: 'US_SSN', severity: 4, score: 1, masked: '***' }],
    categories: [],
    entityCounts: { US_SSN: 1 },
    riskScore: 90,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
  }, {
    enforcementMode: 'block',
    blockMinSeverity: 4,
    blockRiskScore: 90,
    alwaysBlock: ['US_SSN'],
    policyExceptions: [{
      id: 'no_ssn_bypass',
      users: ['counsel@example.test'],
      detectors: ['US_SSN'],
      expiresAt: '2030-01-01T00:00:00.000Z',
    }],
  }, {
    user: 'counsel@example.test',
  }, { now: new Date('2026-06-28T12:00:00.000Z') });
  assert.strictEqual(hardStop.decision, 'block');
  assert.strictEqual(hardStop.policyExceptionId, undefined);
  assert.ok(hardStop.reasons.some((reason) => reason.includes('Hard-stop entity present: US_SSN')));
});

test('policy scope and exception normalization rejects malformed or sensitive identifiers', () => {
  assert.deepStrictEqual(policy.normalizePolicyScopes([
    { id: 'bad 524-71-9043', groups: ['Legal'], enforcementMode: 'block' },
    { id: 'sensitive_matcher', groups: ['524-71-9043'], enforcementMode: 'block' },
    { id: 'no_matcher', enforcementMode: 'block' },
    { id: 'good_scope', groups: ['Legal'], enforcementMode: 'block' },
  ]), [{
    id: 'good_scope',
    enabled: true,
    groups: ['legal'],
    enforcementMode: 'block',
  }]);

  assert.deepStrictEqual(policy.normalizePolicyExceptions([
    { id: 'bad_exception', users: ['counsel@example.test'], expiresAt: 'not-a-date' },
    { id: 'sensitive_matcher', users: ['524-71-9043'], expiresAt: '2030-01-01T00:00:00.000Z' },
    { id: 'good_exception', users: ['counsel@example.test'], expiresAt: '2030-01-01T00:00:00.000Z', ownerGroup: 'Legal', reviewerRole: 'approver', reviewAfter: '2029-12-15T00:00:00.000Z' },
    { id: 'late_review', users: ['counsel@example.test'], expiresAt: '2030-01-01T00:00:00.000Z', reviewAfter: '2030-01-02T00:00:00.000Z' },
  ]), [{
    id: 'good_exception',
    enabled: true,
    action: 'allow',
    expiresAt: '2030-01-01T00:00:00.000Z',
    users: ['counsel@example.test'],
    ownerGroup: 'legal',
    reviewerRole: 'approver',
    reviewAfter: '2029-12-15T00:00:00.000Z',
  }, {
    id: 'late_review',
    enabled: true,
    action: 'allow',
    expiresAt: '2030-01-01T00:00:00.000Z',
    users: ['counsel@example.test'],
  }]);
});

test('policy exception review summarizes ownership and expiry state without content', () => {
  const review = policy.policyExceptionReview({
    policyExceptions: [{
      id: 'legal_vendor_24h',
      enabled: true,
      action: 'allow',
      expiresAt: '2026-06-29T12:00:00.000Z',
      ownerGroup: 'legal',
      reviewerRole: 'security_admin',
      reviewAfter: '2026-06-28T00:00:00.000Z',
      users: ['counsel@example.test'],
    }, {
      id: 'expired_vendor',
      enabled: true,
      action: 'allow',
      expiresAt: '2026-06-01T00:00:00.000Z',
      users: ['counsel@example.test'],
    }, {
      id: 'vendor_expiring',
      enabled: true,
      action: 'allow',
      expiresAt: '2026-06-30T00:00:00.000Z',
      users: ['vendor@example.test'],
    }, {
      id: 'vendor_active',
      enabled: true,
      action: 'allow',
      expiresAt: '2026-07-31T00:00:00.000Z',
      users: ['active@example.test'],
    }],
  }, { now: new Date('2026-06-28T12:00:00.000Z') });

  assert.strictEqual(review.total, 4);
  assert.strictEqual(review.active, 3);
  assert.strictEqual(review.reviewDue, 1);
  assert.strictEqual(review.expired, 1);
  assert.strictEqual(review.expiringSoon, 1);
  assert.strictEqual(review.items.find((item) => item.id === 'vendor_expiring').status, 'expiring_soon');
  assert.strictEqual(review.items.find((item) => item.id === 'vendor_active').status, 'active');
  assert.deepStrictEqual(review.items[0], {
    id: 'legal_vendor_24h',
    enabled: true,
    action: 'allow',
    expiresAt: '2026-06-29T12:00:00.000Z',
    ownerGroup: 'legal',
    reviewerRole: 'security_admin',
    reviewAfter: '2026-06-28T00:00:00.000Z',
    status: 'review_due',
  });
  assert.ok(!JSON.stringify(review).includes('counsel@example.test'));
  assert.ok(!JSON.stringify(review).includes('vendor@example.test'));
});

test('accountTypes scope tightens for personal accounts and leaves corporate untouched (N4)', () => {
  const base = {
    enforcementMode: 'warn', blockMinSeverity: 4, blockRiskScore: 90, alwaysBlock: ['US_SSN'],
    policyScopes: [{ id: 'personal_strict', accountTypes: ['personal'], enforcementMode: 'block', blockMinSeverity: 1, reason: 'personal_strict' }],
  };
  const personal = policy.evaluate(categoryAnalysis('CONFIDENTIAL_BUSINESS'), base, { accountType: 'personal' });
  assert.strictEqual(personal.decision, 'block');
  assert.deepStrictEqual(personal.policyScopeIds, ['personal_strict']);

  const corporate = policy.evaluate(categoryAnalysis('CONFIDENTIAL_BUSINESS'), base, { accountType: 'corporate' });
  assert.deepStrictEqual(corporate.policyScopeIds, []);
});

test('personalAccountBlocked only fires on personal + block action (N4)', () => {
  const pol = policy.normalizePolicy({ corporateAiAccounts: { orgEmailDomains: ['examplecu.org'], personalAccountAction: 'block' } });
  assert.strictEqual(pol.corporateAiAccounts.orgEmailDomains[0], 'examplecu.org');
  assert.strictEqual(policy.personalAccountBlocked('personal', pol), true);
  assert.strictEqual(policy.personalAccountBlocked('unknown', pol), false);
  assert.strictEqual(policy.personalAccountBlocked('corporate', pol), false);
  const coach = policy.normalizePolicy({ corporateAiAccounts: { personalAccountAction: 'coach' } });
  assert.strictEqual(policy.personalAccountBlocked('personal', coach), false);
});
