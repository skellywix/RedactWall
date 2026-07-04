'use strict';
/** Policy impact preview must be useful without returning prompt content. */
const test = require('node:test');
const assert = require('node:assert');
const impact = require('../server/policy-impact');

test('policy impact compares current and proposed outcomes from metadata only', () => {
  const rows = [{
    status: 'allowed',
    user: 'member-services@example.test',
    destination: 'chatgpt.com',
    source: 'browser_extension_524-71-9043',
    channel: 'submit',
    redactedPrompt: 'Member SSN 524-71-9043 should never return in preview',
    findings: [{ type: 'US_SSN', severity: 4, score: 1, masked: '***-**-9043' }],
    categories: [],
    riskScore: 10,
    maxSeverity: 1,
    maxSeverityLabel: 'low',
  }, {
    status: 'allowed',
    user: 'agent@example.test',
    destination: 'sharepoint.export.list',
    source: 'mcp_guard',
    channel: 'mcp_tool',
    redactedPrompt: 'SharePoint export preview is excluded',
    findings: [],
    categories: [],
    riskScore: 0,
    maxSeverity: 0,
  }];
  const currentPolicy = {
    enforcementMode: 'warn',
    blockMinSeverity: 4,
    blockRiskScore: 90,
    alwaysBlock: [],
    governedDestinations: ['chatgpt.com'],
    blockedDestinations: [],
    blockUnapprovedAiDestinations: false,
    mcpApprovalRequiredTools: [],
  };
  const proposedPolicy = {
    ...currentPolicy,
    enforcementMode: 'block',
    blockRiskScore: 5,
    mcpApprovalRequiredTools: ['sharepoint.export.*'],
  };

  const report = impact.buildPolicyImpact({ rows, currentPolicy, proposedPolicy, now: new Date('2026-07-04T12:00:00.000Z') });
  assert.strictEqual(report.summary.sampleSize, 2);
  assert.strictEqual(report.summary.changed, 2);
  assert.strictEqual(report.summary.newlyBlocked, 1);
  assert.strictEqual(report.summary.proposed.blocked, 1);
  assert.strictEqual(report.summary.proposed.approval_required, 1);
  assert.strictEqual(report.privacy.promptBodiesIncluded, false);
  assert.strictEqual(JSON.stringify(report).includes('524-71-9043'), false);
  assert.strictEqual(JSON.stringify(report).includes('SharePoint export preview'), false);
  assert.ok(report.topDeltas.destinations.some((item) => item.label === 'chatgpt.com'));
  assert.ok(report.topDeltas.categories.some((item) => item.label === 'US_SSN'));
});
