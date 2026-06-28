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
    'notificationStatus',
    'slaDueAt',
    'workflowReason',
  ].sort());
});
