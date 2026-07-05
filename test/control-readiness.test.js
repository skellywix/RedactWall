'use strict';

const test = require('node:test');
const assert = require('node:assert');
const readiness = require('../server/control-readiness');
const coverage = require('../server/coverage');
const alerts = require('../server/alerts');

const rows = [
  {
    id: 'q_proxy_hold',
    createdAt: '2026-07-03T10:00:00.000Z',
    status: 'pending',
    user: 'analyst@example.test',
    destination: 'chatgpt.com',
    source: 'proxy',
    channel: 'submit',
    sensor: { name: 'proxy', version: '1.0.0', platform: 'squid_icap' },
    findings: [{ type: 'US_SSN', severity: 4, score: 0.98, masked: '***-**-9043' }],
    riskScore: 90,
    maxSeverity: 4,
    redactedPrompt: 'Member [US_SSN]',
    _rawPrompt: 'Member SSN 524-71-9043',
  },
  {
    id: 'q_desktop_upload',
    createdAt: '2026-07-03T10:05:00.000Z',
    status: 'file_upload_blocked',
    user: 'ops@example.test',
    destination: 'claude.ai',
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
    decisionNote: 'endpoint_agent/file_upload; native handoff evt_desktop_1',
    findings: [{ type: 'SECRET_KEY', severity: 4, score: 0.92, masked: 'sk-***' }],
    riskScore: 80,
    maxSeverity: 4,
  },
  {
    id: 'q_endpoint_health',
    createdAt: '2026-07-03T10:06:00.000Z',
    status: 'sensor_heartbeat',
    user: 'ops@example.test',
    destination: 'endpoint-install',
    source: 'endpoint_agent',
    channel: 'sensor_health',
    sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
    installChecks: [
      { id: 'endpoint_env_file', ok: true, detail: 'found' },
      { id: 'ai_tool_inventory', ok: true, detail: 'detected:1' },
      { id: 'ai_tool_cursor', ok: true, detail: 'detected' },
    ],
  },
  {
    id: 'q_mcp_redacted',
    createdAt: '2026-07-03T10:07:00.000Z',
    status: 'redacted',
    user: 'agent@example.test',
    destination: 'sharepoint.fetchDoc',
    source: 'mcp_guard',
    channel: 'mcp_doc',
    sensor: { name: 'mcp_guard', version: '0.3.0', platform: 'node' },
    findings: [{ type: 'US_SSN', severity: 4, score: 0.95, masked: '***-**-9043' }],
    categories: [],
    entityCounts: { US_SSN: 1 },
    riskScore: 82,
    maxSeverity: 4,
  },
];

const policy = {
  requiredSensors: ['browser_extension', 'endpoint_agent', 'mcp_guard', 'proxy'],
  desiredSensorVersions: { endpoint_agent: '0.3.0', proxy: '1.0.0' },
  governedDestinations: ['chatgpt.com', 'claude.ai'],
  blockedDestinations: ['shadowai.example'],
  blockedFileUploadDestinations: ['claude.ai'],
  blockedBrowserActions: [{ id: 'block_chatgpt_paste', action: 'paste', destinations: ['chatgpt.com'] }],
  blockUnapprovedAiDestinations: true,
  responseScanMode: 'redact',
  mcpAllowedTools: ['sharepoint.fetch*', 'drive.read*'],
  mcpBlockedTools: ['*.delete*'],
  approvalRoutingRules: [{
    id: 'critical_dlp',
    enabled: true,
    assignedGroup: 'security',
    assignedRole: 'security_admin',
    slaMinutes: 30,
    minSeverity: 3,
  }],
};

test('competitive hardening readiness scores gateway, asset discovery, and MCP without prompt bodies', () => {
  const coverageReport = coverage.summarize(rows, policy);
  const report = readiness.summarize({
    rows,
    policy,
    coverageReport,
    auditIntegrity: { ok: true, count: 12 },
    env: {
      SIEM_WEBHOOK_URL: 'https://siem.example.test/events',
      REDACTWALL_APPROVAL_SLACK_WEBHOOK_URL: 'https://hooks.slack.example.test/services/abc',
    },
  });

  assert.strictEqual(report.areas.length, 3);
  assert.strictEqual(report.summary.ready, 3);
  assert.ok(report.score >= 90);
  assert.strictEqual(report.mission.state, 'ready');
  assert.strictEqual(report.mission.progress.open, 0);
  assert.strictEqual(report.mission.progress.percent, 100);
  assert.strictEqual(report.mission.current, null);
  assert.strictEqual(report.mission.proofLedger.total, 16);
  assert.strictEqual(report.mission.proofLedger.verified, 16);
  assert.strictEqual(report.mission.proofLedger.missing, 0);
  assert.strictEqual(report.mission.proofLedger.current, null);
  assert.strictEqual(report.mission.lanes.length, 3);
  assert.ok(report.areas.some((area) => area.id === 'ai_gateway_enforcement' && area.state === 'ready'));
  const gateway = report.areas.find((area) => area.id === 'ai_gateway_enforcement');
  assert.ok(gateway.evidence.some((item) => /Bedrock/.test(item)));
  assert.strictEqual(gateway.proofs.find((proof) => proof.id === 'gateway_provider_runtime_coverage').status, 'verified');
  assert.ok(gateway.playbook.some((step) => step.id === 'gateway_provider_runtime_coverage' && step.status === 'done'));
  assert.ok(report.areas.some((area) => area.id === 'ai_asset_discovery' && area.state === 'ready'));
  assert.ok(report.areas.some((area) => area.id === 'mcp_agent_gateway' && area.state === 'ready'));
  for (const area of report.areas) {
    assert.ok(area.playbook.length >= 4);
    assert.ok(area.playbook.every((step) => step.status === 'done'));
    assert.ok(area.playbook.every((step) => step.command && step.validation));
    assert.ok(area.proofs.length >= 5);
    assert.strictEqual(area.proofLedger.missing, 0);
    assert.ok(area.proofs.every((proof) => proof.status === 'verified'));
  }
  assert.ok(!JSON.stringify(report).includes('524-71-9043'));
  assert.ok(!JSON.stringify(report).includes('Member SSN'));
});

test('readiness calls out monitor-only proxy and missing MCP governance', () => {
  const monitorOnlyRows = [{
    id: 'q_proxy_observed',
    createdAt: '2026-07-03T10:00:00.000Z',
    status: 'proxy_observed',
    user: 'analyst@example.test',
    destination: 'chatgpt.com',
    source: 'proxy',
    channel: 'submit',
  }];
  const report = readiness.summarize({
    rows: monitorOnlyRows,
    policy: { ...policy, requiredSensors: ['proxy'], approvalRoutingRules: [] },
    coverageReport: coverage.summarize(monitorOnlyRows, { ...policy, requiredSensors: ['proxy'] }),
    auditIntegrity: { ok: false, count: 0 },
    env: {},
  });

  const gateway = report.areas.find((area) => area.id === 'ai_gateway_enforcement');
  const mcp = report.areas.find((area) => area.id === 'mcp_agent_gateway');
  assert.strictEqual(gateway.state, 'attention');
  assert.ok(gateway.gaps.some((gap) => /monitor-only/i.test(gap)));
  assert.strictEqual(gateway.playbook.find((step) => step.status === 'next').id, 'gateway_inline_enforcement');
  assert.strictEqual(gateway.proofs.find((proof) => proof.id === 'gateway_inline_control').status, 'attention');
  assert.notStrictEqual(mcp.state, 'ready');
  assert.ok(mcp.gaps.some((gap) => /MCP guard/.test(gap)));
  assert.strictEqual(mcp.playbook.find((step) => step.status === 'next').id, 'mcp_required_sensor');
  assert.strictEqual(mcp.proofs.find((proof) => proof.id === 'mcp_activity_observed').status, 'missing');
  assert.strictEqual(report.mission.state, 'blocked');
  assert.strictEqual(report.mission.current.areaId, 'ai_gateway_enforcement');
  assert.strictEqual(report.mission.current.label, 'Record block, redact, or hold evidence');
  assert.match(report.mission.current.command, /icap:bridge/);
  assert.ok(report.mission.progress.open > 0);
  assert.ok(report.mission.proofLedger.missing > 0);
  assert.strictEqual(report.mission.proofLedger.current.areaId, 'ai_gateway_enforcement');
  assert.strictEqual(report.mission.proofLedger.current.label, 'Inline block, redact, or hold proven');
  assert.ok(report.mission.lanes.some((lane) => lane.id === 'mcp_agent_gateway' && lane.nextStep === 'Require MCP guard'));
  assert.strictEqual(report.nextActions[0].action, 'Record block, redact, or hold evidence');
  assert.match(report.nextActions[0].detail, /monitor-only/i);
});

test('posture SIEM alert is sanitized and can be emitted through HTTPS', async () => {
  const posture = {
    generatedAt: '2026-07-03T12:00:00.000Z',
    windowDays: 7,
    summary: {
      events: 3,
      sensitiveEvents: 2,
      blocked: 2,
      redacted: 0,
      pending: 1,
      controlRate: 100,
    },
    aiInventory: {
      summary: {
        sanctioned: 1,
        unsanctioned: 0,
        shadow: 1,
        localTools: 1,
        unapprovedLocalTools: 1,
        activeDestinations: 2,
        totalEvents: 4,
      },
      apps: [{ name: 'do-not-send-destination.example', state: 'shadow' }],
    },
    actionQueue: [
      { id: 'a1', severity: 'critical', category: 'Shadow AI', label: 'do-not-send-action-label', command: 'do-not-send-command', workflowStatus: 'resolved', workflowProofState: 'proof_pending' },
      { id: 'a2', severity: 'warning', category: 'Current mission', label: 'Next step', workflowStatus: 'assigned', workflowOwner: 'do-not-send-owner' },
    ],
    hardening: {
      score: 91,
      state: 'ready',
      summary: { ready: 3, attention: 0, blocked: 0, total: 3 },
      mission: {
        state: 'attention',
        progress: { percent: 60, open: 2 },
        proofLedger: { verified: 3, attention: 1, missing: 2, total: 6, percent: 50 },
        current: {
          areaLabel: 'AI Gateway Enforcement',
          label: 'Next step',
          command: 'do-not-send-to-soc',
        },
      },
      areas: [{
        id: 'ai_gateway_enforcement',
        label: 'AI Gateway Enforcement',
        score: 93,
        state: 'ready',
        status: 'online',
        owner: 'network security',
        source: 'proxy',
        evidence: ['Proxy event controlled'],
        gaps: [],
        proofLedger: { verified: 1, attention: 0, missing: 1, total: 2 },
        proofs: [
          { id: 'verified', label: 'Verified proof', status: 'verified', detail: 'safe detail' },
          { id: 'missing', label: 'Missing proof', status: 'missing', detail: 'do-not-send-to-soc' },
        ],
        playbook: [
          { id: 'done_step', label: 'Done step', status: 'done', command: 'secret-command', validation: 'proved' },
          { id: 'next_step', label: 'Next step', status: 'next', command: 'do-not-send-to-soc', validation: 'proved' },
        ],
      }],
    },
    rawPrompt: 'Member SSN 524-71-9043',
  };
  const payload = alerts.sanitizedPostureAlert(posture);
  assert.strictEqual(payload.eventType, 'redactwall.posture_snapshot');
  assert.strictEqual(payload.hardening.areas[0].gapCount, 0);
  assert.strictEqual(payload.hardening.areas[0].playbookDone, 1);
  assert.strictEqual(payload.hardening.areas[0].playbookTodo, 1);
  assert.strictEqual(payload.hardening.areas[0].nextStep, 'Next step');
  assert.strictEqual(payload.hardening.mission.progressPercent, 60);
  assert.strictEqual(payload.hardening.mission.openSteps, 2);
  assert.deepStrictEqual(payload.hardening.mission.proofLedger, {
    verified: 3,
    attention: 1,
    missing: 2,
    total: 6,
    percent: 50,
  });
  assert.strictEqual(payload.hardening.mission.currentArea, 'AI Gateway Enforcement');
  assert.strictEqual(payload.hardening.mission.currentStep, 'Next step');
  assert.strictEqual(payload.hardening.areas[0].proofVerified, 1);
  assert.strictEqual(payload.hardening.areas[0].proofMissing, 1);
  assert.deepStrictEqual(payload.aiInventory, {
    sanctioned: 1,
    unsanctioned: 0,
    shadow: 1,
    localTools: 1,
    unapprovedLocalTools: 1,
    activeDestinations: 2,
    totalEvents: 4,
    highRiskAssets: 0,
  });
  assert.strictEqual(payload.actionQueue.total, 2);
  assert.strictEqual(payload.actionQueue.bySeverity.critical, 1);
  assert.strictEqual(payload.actionQueue.byCategory['Shadow AI'], 1);
  assert.strictEqual(payload.actionQueue.byWorkflow.resolved, 1);
  assert.strictEqual(payload.actionQueue.byWorkflow.assigned, 1);
  assert.strictEqual(payload.actionQueue.proofPending, 1);
  assert.ok(!JSON.stringify(payload).includes('524-71-9043'));
  assert.ok(!JSON.stringify(payload).includes('do-not-send-to-soc'));
  assert.ok(!JSON.stringify(payload).includes('do-not-send-destination'));
  assert.ok(!JSON.stringify(payload).includes('do-not-send-command'));
  assert.ok(!JSON.stringify(payload).includes('do-not-send-action-label'));
  assert.ok(!JSON.stringify(payload).includes('do-not-send-owner'));

  const requests = [];
  const result = await alerts.emitPostureAlert(posture, {
    url: 'https://siem.example.test/posture',
    token: 'secret-token',
    fetch: async (url, opts) => {
      requests.push({ url, opts });
      return { ok: true, status: 202 };
    },
  });
  assert.deepStrictEqual(result, { sent: true, status: 202 });
  assert.strictEqual(requests[0].url, 'https://siem.example.test/posture');
  assert.strictEqual(requests[0].opts.headers.Authorization, 'Bearer secret-token');
  assert.ok(!requests[0].opts.body.includes('secret-token'));
  assert.ok(!requests[0].opts.body.includes('524-71-9043'));
});
