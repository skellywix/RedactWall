'use strict';
/** Approval notification adapters must stay sanitized. */
const test = require('node:test');
const assert = require('node:assert');
const notifiers = require('../server/notifiers');

function sampleQuery(overrides = {}) {
  return {
    id: 'q_notify',
    createdAt: '2026-06-28T06:00:00.000Z',
    status: 'pending',
    user: 'member-services@example.test',
    orgId: 'cu-demo',
    source: 'browser_extension',
    channel: 'submit',
    sensor: {
      name: 'browser_extension',
      version: '0.3.0',
      platform: 'chrome_mv3',
      ingestKey: 'ps_ingest_should_not_leave',
    },
    destination: 'chatgpt.com',
    redactedPrompt: 'Member Jane has SSN [US_SSN]',
    _rawPrompt: 'sealed raw 524-71-9043',
    _tokenVault: 'sealed-vault',
    _releaseTokenHash: 'release-secret-hash',
    decisionNote: 'contains SSN 524-71-9043',
    findings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '**** 9043', value: '524-71-9043' }],
    categories: [],
    reasons: ['Hard-stop entity present: US_SSN'],
    riskScore: 74,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    assignedRole: 'approver',
    assignedGroup: 'compliance',
    workflowReason: 'detector:US_SSN',
    slaDueAt: '2026-06-28T10:00:00.000Z',
    escalatedAt: null,
    notificationStatus: 'not_configured',
    ...overrides,
  };
}

test('sanitized approval notification omits prompt text, secrets, and raw finding values', () => {
  const payload = notifiers.sanitizedApprovalNotification(sampleQuery());
  const wire = JSON.stringify(payload);

  assert.strictEqual(payload.eventType, 'promptwall.approval_workflow');
  assert.strictEqual(payload.action, 'APPROVAL_ROUTED');
  assert.deepStrictEqual(payload.labels, ['US_SSN']);
  assert.strictEqual(payload.workflow.assignedGroup, 'compliance');
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member Jane'));
  assert.ok(!wire.includes('sealed raw'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('release-secret-hash'));
  assert.ok(!wire.includes('contains SSN'));
  assert.ok(!wire.includes('ps_ingest_should_not_leave'));
});

test('approval notification is disabled without configured channels', async () => {
  const result = await notifiers.emitApprovalNotification(sampleQuery(), { env: {} });
  assert.deepStrictEqual(result, { sent: false, reason: 'disabled', channels: [], results: [] });
});

test('generic, Slack, and Teams adapters send sanitized payloads', async () => {
  const requests = [];
  const env = {
    APPROVAL_NOTIFY_WEBHOOK_URL: 'https://notify.example.test/hook',
    APPROVAL_NOTIFY_WEBHOOK_TOKEN: 'unit-token',
    APPROVAL_SLACK_WEBHOOK_URL: 'https://hooks.slack.example.test/unit',
    APPROVAL_TEAMS_WEBHOOK_URL: 'https://teams.example.test/unit',
  };

  const result = await notifiers.emitApprovalNotification(sampleQuery(), {
    env,
    fetch: async (url, opts) => {
      requests.push({ url, opts });
      return { ok: true, status: 202 };
    },
  });

  assert.strictEqual(result.sent, true);
  assert.strictEqual(result.status, 'sent');
  assert.deepStrictEqual(result.channels, ['webhook', 'slack', 'teams']);
  assert.strictEqual(requests.length, 3);
  assert.strictEqual(requests[0].opts.headers.Authorization, 'Bearer unit-token');
  assert.ok(requests[1].opts.body.includes('PromptWall approval routed'));
  assert.ok(requests[2].opts.body.includes('MessageCard'));
  const wire = requests.map((request) => request.opts.body).join('\n');
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member Jane'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.match(wire, /US_SSN/);
});

test('delivery status distinguishes sent, partial, failed, and disabled', () => {
  assert.strictEqual(notifiers.deliveryStatus({ reason: 'disabled' }), 'not_configured');
  assert.strictEqual(notifiers.deliveryStatus({ results: [{ sent: true }] }), 'sent');
  assert.strictEqual(notifiers.deliveryStatus({ results: [{ sent: true }, { sent: false }] }), 'partial');
  assert.strictEqual(notifiers.deliveryStatus({ results: [{ sent: false }] }), 'failed');
});
