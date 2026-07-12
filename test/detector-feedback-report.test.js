'use strict';

const test = require('node:test');
const assert = require('node:assert');
const feedback = require('../server/detector-feedback');
const roles = require('../server/roles');

function candidate(id, assignedRole, assignedUser, detectorId, assignedGroup = '') {
  return {
    id,
    createdAt: `2026-07-11T00:00:0${id === 'owned' ? '0' : '1'}.000Z`,
    status: 'pending',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
    findings: [{ type: detectorId }],
    riskScore: id === 'owned' ? 90 : 80,
    maxSeverity: 4,
    assignedRole,
    assignedUser,
    assignedGroup,
    redactedPrompt: `Synthetic [${detectorId}]`,
    _rawPrompt: 'synthetic raw value must never leave the server',
  };
}

test('detector feedback candidates carry requester-specific authority without prompt bodies', () => {
  const rows = [
    candidate('owned', 'approver', ' PRIVATE-REVIEWER ', 'US_SSN', 'PRIVATE-REVIEW-GROUP'),
    candidate('forbidden', 'security_admin', null, 'SECRET_KEY'),
  ];
  const approver = { role: 'approver', user: 'private-reviewer' };
  const report = feedback.report({
    rows,
    canFeedback: (query) => roles.canDecideQuery(approver, query),
  });

  assert.strictEqual(report.reviewQueue.find((item) => item.queryId === 'owned').canFeedback, true);
  assert.strictEqual(report.reviewQueue.find((item) => item.queryId === 'forbidden').canFeedback, false);
  const serialized = JSON.stringify(report);
  assert.strictEqual(serialized.includes('synthetic raw value'), false);
  assert.strictEqual(serialized.includes('PRIVATE-REVIEWER'), false);
  assert.strictEqual(serialized.includes('PRIVATE-REVIEW-GROUP'), false);

  const adminReport = feedback.report({
    rows,
    canFeedback: (query) => roles.canDecideQuery({ role: 'security_admin', user: 'admin' }, query),
  });
  assert.ok(adminReport.reviewQueue.every((item) => item.canFeedback === true));

  const contextFreeReport = feedback.report({ rows });
  assert.ok(contextFreeReport.reviewQueue.every((item) => !Object.prototype.hasOwnProperty.call(item, 'canFeedback')));
});

test('requester-owned candidates are not crowded out by higher-risk forbidden rows', () => {
  const rows = Array.from({ length: 11 }, (_, index) => candidate(
    `forbidden-${index}`,
    'security_admin',
    '',
    'SECRET_KEY',
  ));
  rows.push({ ...candidate('owned', 'approver', 'reviewer', 'US_SSN'), riskScore: 1 });
  const report = feedback.report({
    rows,
    canFeedback: (query) => roles.canDecideQuery({ role: 'approver', user: 'reviewer' }, query),
  });

  assert.strictEqual(report.reviewQueue.length, 10);
  assert.strictEqual(report.reviewQueue[0].queryId, 'owned');
  assert.strictEqual(report.reviewQueue[0].canFeedback, true);
});
