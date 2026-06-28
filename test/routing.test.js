'use strict';
/** Approval routing rules must be deterministic and metadata-only. */
const test = require('node:test');
const assert = require('node:assert');
const routing = require('../server/routing');

const NOW = new Date('2026-06-28T06:00:00.000Z');

test('routes source code and credentials to security with short SLAs', () => {
  const sourceCode = routing.routeDecision({
    status: 'pending',
    source: 'browser_extension',
    channel: 'submit',
    categories: ['SOURCE_CODE'],
    findings: [],
    entityCounts: { SOURCE_CODE: 1 },
    riskScore: 28,
    maxSeverity: 3,
    redactedPrompt: 'function leak() { return secret; }',
  }, { now: NOW });

  assert.strictEqual(sourceCode.assignedRole, 'security_admin');
  assert.strictEqual(sourceCode.assignedGroup, 'security');
  assert.strictEqual(sourceCode.workflowReason, 'detector:SOURCE_CODE');
  assert.strictEqual(sourceCode.slaDueAt, '2026-06-28T07:00:00.000Z');

  const credentials = routing.routeDecision({
    status: 'pending',
    findings: [{ type: 'SECRET_KEY', masked: 'sk***' }],
    categories: [],
    entityCounts: { SECRET_KEY: 1 },
    riskScore: 80,
    maxSeverity: 4,
  }, { now: NOW });

  assert.strictEqual(credentials.assignedRole, 'security_admin');
  assert.strictEqual(credentials.assignedGroup, 'security');
  assert.strictEqual(credentials.slaDueAt, '2026-06-28T06:30:00.000Z');
});

test('routes member, health, and legal work to the right review groups', () => {
  const member = routing.routeDecision({
    status: 'pending',
    findings: [{ type: 'MEMBER_ID', masked: '**** 3456' }],
    categories: [],
    entityCounts: { MEMBER_ID: 1 },
    riskScore: 24,
    maxSeverity: 3,
  }, { now: NOW });
  assert.strictEqual(member.assignedRole, 'approver');
  assert.strictEqual(member.assignedGroup, 'compliance');
  assert.strictEqual(member.workflowReason, 'detector:MEMBER_ID');
  assert.strictEqual(member.slaDueAt, '2026-06-28T10:00:00.000Z');

  const health = routing.routeDecision({
    status: 'pending',
    findings: [],
    categories: ['HEALTH_RECORD'],
    entityCounts: { HEALTH_RECORD: 1 },
    riskScore: 18,
    maxSeverity: 3,
  }, { now: NOW });
  assert.strictEqual(health.assignedGroup, 'privacy');
  assert.strictEqual(health.workflowReason, 'detector:HEALTH_RECORD');

  const legal = routing.routeDecision({
    status: 'pending',
    findings: [],
    categories: ['LEGAL_CONTRACT'],
    entityCounts: { LEGAL_CONTRACT: 1 },
    riskScore: 18,
    maxSeverity: 3,
  }, { now: NOW });
  assert.strictEqual(legal.assignedGroup, 'legal');
  assert.strictEqual(legal.slaDueAt, '2026-06-28T14:00:00.000Z');
});

test('customer approval routing rules override default owners using metadata only', () => {
  const rule = {
    id: 'engineering_source_code',
    categories: ['SOURCE_CODE'],
    sources: ['browser_extension'],
    destinations: ['chatgpt.com'],
    assignedGroup: 'engineering',
    assignedRole: 'approver',
    slaMinutes: 90,
    reason: 'engineering_review',
  };
  const routed = routing.routeDecision({
    status: 'pending',
    destination: 'https://chatgpt.com/c/unit',
    source: 'browser_extension',
    channel: 'submit',
    findings: [],
    categories: ['SOURCE_CODE'],
    entityCounts: { SOURCE_CODE: 1 },
    riskScore: 28,
    maxSeverity: 3,
    redactedPrompt: 'function leak() { return secret; }',
  }, { now: NOW, policy: { approvalRoutingRules: [rule] } });

  assert.strictEqual(routed.assignedRole, 'approver');
  assert.strictEqual(routed.assignedGroup, 'engineering');
  assert.strictEqual(routed.workflowReason, 'rule:engineering_source_code:engineering_review');
  assert.strictEqual(routed.slaDueAt, '2026-06-28T07:30:00.000Z');
  assert.ok(!JSON.stringify(routed).includes('function leak'));
});

test('customer routing rules cannot soften critical-risk ownership', () => {
  const routed = routing.routeDecision({
    status: 'pending',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
    findings: [{ type: 'SOURCE_CODE', masked: 'redacted' }],
    categories: [],
    entityCounts: { SOURCE_CODE: 1 },
    riskScore: 90,
    maxSeverity: 4,
  }, {
    now: NOW,
    policy: {
      approvalRoutingRules: [{
        id: 'soft_source_code',
        detectors: ['SOURCE_CODE'],
        assignedGroup: 'engineering',
        assignedRole: 'approver',
        slaMinutes: 240,
      }],
    },
  });

  assert.strictEqual(routed.assignedRole, 'security_admin');
  assert.strictEqual(routed.assignedGroup, 'security');
  assert.strictEqual(routed.workflowReason, 'rule:soft_source_code+critical');
  assert.strictEqual(routed.slaDueAt, '2026-06-28T07:00:00.000Z');
});

test('disabled or nonmatching routing rules fall back to deterministic defaults', () => {
  assert.strictEqual(routing.ruleMatches({
    id: 'catch_all',
    assignedGroup: 'security',
    assignedRole: 'security_admin',
    slaMinutes: 60,
  }, {}, { detectorLabels: [], categoryLabels: [], source: '', channel: '', riskScore: 0, maxSeverity: 0 }), false);

  const routed = routing.routeDecision({
    status: 'pending',
    destination: 'claude.ai',
    source: 'browser_extension',
    channel: 'submit',
    findings: [{ type: 'MEMBER_ID', masked: '**** 7788' }],
    categories: [],
    entityCounts: { MEMBER_ID: 1 },
    riskScore: 24,
    maxSeverity: 3,
  }, {
    now: NOW,
    policy: {
      approvalRoutingRules: [
        {
          id: 'disabled_member_rule',
          enabled: false,
          detectors: ['MEMBER_ID'],
          assignedGroup: 'member_services',
          assignedRole: 'approver',
          slaMinutes: 60,
        },
        {
          id: 'chatgpt_only_member_rule',
          detectors: ['MEMBER_ID'],
          destinations: ['chatgpt.com'],
          assignedGroup: 'member_services',
          assignedRole: 'approver',
          slaMinutes: 60,
        },
      ],
    },
  });

  assert.strictEqual(routed.assignedRole, 'approver');
  assert.strictEqual(routed.assignedGroup, 'compliance');
  assert.strictEqual(routed.workflowReason, 'detector:MEMBER_ID');
  assert.strictEqual(routed.slaDueAt, '2026-06-28T10:00:00.000Z');
});

test('withWorkflow only annotates routeable records and omits raw content', () => {
  const allowed = routing.withWorkflow({
    status: 'allowed',
    redactedPrompt: 'Clean prompt',
  }, { now: NOW });
  assert.strictEqual(allowed.assignedGroup, undefined);

  const routed = routing.withWorkflow({
    status: 'pending',
    source: 'endpoint_agent',
    channel: 'file_upload',
    redactedPrompt: 'Member SSN [US_SSN]',
    _rawPrompt: 'sealed raw prompt with 524-71-9043',
    findings: [{ type: 'US_SSN', masked: '**** 9043' }],
    categories: [],
    entityCounts: { US_SSN: 1 },
  }, { now: NOW });

  assert.strictEqual(routed.assignedGroup, 'compliance');
  const workflow = routing.publicWorkflow(routed);
  const wire = JSON.stringify(workflow);
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member SSN'));
  assert.deepStrictEqual(Object.keys(workflow).sort(), [
    'assignedGroup',
    'assignedRole',
    'escalatedAt',
    'escalationReason',
    'notificationAttemptCount',
    'notificationChannels',
    'notificationLastAttemptAt',
    'notificationStatus',
    'slaDueAt',
    'workflowReason',
  ].sort());
});
