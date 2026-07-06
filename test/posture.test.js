'use strict';

const test = require('node:test');
const assert = require('node:assert');
const posture = require('../server/posture');
const coverage = require('../server/coverage');

const policy = {
  blockRiskScore: 40,
  governedDestinations: ['chatgpt.com', 'claude.ai'],
  blockedFileUploadDestinations: ['claude.ai'],
  blockedBrowserActions: [{ id: 'block_chatgpt_paste', action: 'paste', destinations: ['chatgpt.com'] }],
  blockUnapprovedAiDestinations: true,
  responseScanMode: 'redact',
  mcpAllowedTools: ['sharepoint.fetch*', 'drive.read*'],
  mcpBlockedTools: ['*.delete*'],
  requiredSensors: ['browser_extension', 'endpoint_agent', 'mcp_guard'],
  desiredSensorVersions: {
    browser_extension: '0.3.0',
    endpoint_agent: '0.3.0',
    mcp_guard: '0.3.0',
  },
};

const rows = [
  {
    id: 'q_pending',
    createdAt: '2026-07-02T10:00:00.000Z',
    status: 'pending',
    user: 'analyst@example.test',
    orgId: 'cu-lending',
    destination: 'https://chatgpt.com/c/1',
    source: 'browser_extension',
    channel: 'submit',
    sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
    redactedPrompt: 'Member [US_SSN] needs loan review',
    _rawPrompt: 'Member SSN 524-71-9043 needs loan review',
    findings: [{ type: 'US_SSN', severity: 4, score: 0.98, masked: '***-**-9043' }],
    categories: ['PII'],
    entityCounts: { US_SSN: 1 },
    riskScore: 92,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    assignedGroup: 'member_services',
    slaDueAt: '2026-07-02T10:30:00.000Z',
  },
  {
    id: 'q_file',
    createdAt: '2026-07-02T11:00:00.000Z',
    status: 'file_upload_blocked',
    user: 'ops@example.test',
    orgId: 'cu-operations',
    destination: 'claude.ai',
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
    findings: [{ type: 'SECRET_KEY', severity: 4, score: 0.95, masked: 'sk-***' }],
    categories: ['CREDENTIALS'],
    entityCounts: { SECRET_KEY: 1 },
    riskScore: 82,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    assignedGroup: 'security',
  },
  {
    id: 'q_shadow',
    createdAt: '2026-07-01T09:00:00.000Z',
    status: 'destination_blocked',
    user: 'ops@example.test',
    orgId: 'cu-operations',
    destination: 'notebooklm.google.com',
    source: 'browser_extension',
    channel: 'shadow_ai',
    sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
  },
  {
    id: 'q_response',
    createdAt: '2026-06-30T12:00:00.000Z',
    status: 'response_redacted',
    user: 'analyst@example.test',
    orgId: 'cu-lending',
    destination: 'chatgpt.com',
    source: 'mcp_guard',
    channel: 'ai_response',
    sensor: { name: 'mcp_guard', version: '0.3.0', platform: 'node' },
    findings: [{ type: 'CONFIDENTIAL_BUSINESS', severity: 3, score: 0.78, masked: 'confidential strategy' }],
    categories: ['CONFIDENTIAL_BUSINESS'],
    entityCounts: { CONFIDENTIAL_BUSINESS: 1 },
    riskScore: 65,
    maxSeverity: 3,
    maxSeverityLabel: 'high',
    assignedGroup: 'member_services',
  },
  {
    id: 'q_mcp_doc',
    createdAt: '2026-07-02T11:30:00.000Z',
    status: 'redacted',
    user: 'claude-desktop',
    orgId: 'cu-lending',
    destination: 'sharepoint.fetchMember',
    source: 'mcp_guard',
    channel: 'mcp_doc',
    sensor: { name: 'mcp_guard', version: '0.3.0', platform: 'node' },
    findings: [{ type: 'US_SSN', severity: 4, score: 0.97, masked: '***-**-1188' }],
    categories: ['PII'],
    entityCounts: { US_SSN: 1 },
    riskScore: 72,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    assignedGroup: 'security',
  },
  {
    id: 'q_mcp_tool_block',
    createdAt: '2026-07-02T11:35:00.000Z',
    status: 'action_blocked',
    user: 'cursor-agent',
    orgId: 'cu-operations',
    destination: 'sharepoint.deleteMember',
    source: 'mcp_guard',
    channel: 'mcp_tool',
    sensor: { name: 'mcp_guard', version: '0.3.0', platform: 'node' },
    note: 'MCP tool blocked by policy',
  },
  {
    id: 'q_injection',
    createdAt: '2026-07-02T11:45:00.000Z',
    status: 'injection_blocked',
    user: 'analyst@example.test',
    orgId: 'cu-lending',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
    sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
    findings: [],
    categories: [],
    entityCounts: {},
    riskScore: 88,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    reasons: ['Hidden prompt injection characters detected'],
    assignedGroup: 'security',
  },
  {
    id: 'q_heartbeat',
    createdAt: '2026-07-02T12:00:00.000Z',
    status: 'sensor_heartbeat',
    user: 'tech@example.test',
    orgId: 'cu-operations',
    destination: 'endpoint-install',
    source: 'endpoint_agent',
    channel: 'sensor_health',
    sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
    installChecks: [{ id: 'endpoint_env_file', ok: true, detail: 'found' }],
  },
  {
    id: 'q_mcp_heartbeat',
    createdAt: '2026-07-02T12:05:00.000Z',
    status: 'sensor_heartbeat',
    user: 'mcp-tech@example.test',
    orgId: 'cu-operations',
    destination: 'mcp-install',
    source: 'mcp_guard',
    channel: 'sensor_health',
    sensor: { name: 'mcp_guard', version: '0.3.0', platform: 'node' },
    installChecks: [
      { id: 'mcp_connector_registry', ok: true, detail: 'shipped:6/6 profiles:6 next:none' },
      { id: 'mcp_connector_profile_microsoft365', ok: true, detail: 'stage:shipped status:runtime_present scopes:2' },
      { id: 'mcp_connector_profile_google_drive', ok: true, detail: 'stage:shipped status:runtime_present scopes:1' },
      { id: 'mcp_connector_profile_slack', ok: true, detail: 'stage:shipped status:runtime_present scopes:3' },
      { id: 'mcp_connector_profile_teams', ok: true, detail: 'stage:shipped status:runtime_present scopes:2' },
      { id: 'mcp_connector_profile_jira_confluence', ok: true, detail: 'stage:shipped status:runtime_present scopes:2' },
      { id: 'mcp_connector_profile_database_readonly', ok: true, detail: 'stage:shipped status:runtime_present scopes:1' },
    ],
  },
];

test('posture summarizes live AI security objectives without prompt bodies', () => {
  const coverageReport = coverage.summarize(rows, policy);
  const report = posture.summarize({
    rows,
    policy,
    coverageReport,
    auditIntegrity: { ok: true, count: 8 },
    actionStates: {
      'mission:ai_gateway_enforcement:gateway_required_sensor': {
        status: 'assigned',
        owner: 'network_security',
        actor: 'admin',
        note: 'dashboard_linkage',
        updatedAt: '2026-07-03T00:05:00.000Z',
      },
      'inventory:ai-app-notebooklm-google-com': {
        status: 'resolved',
        owner: 'security_operations',
        actor: 'admin',
        note: 'destination_reviewed',
        updatedAt: '2026-07-03T00:10:00.000Z',
      },
    },
    now: '2026-07-03T00:00:00.000Z',
    identityGroups: {
      'analyst@example.test': ['RedactWall Lending'],
      'ops@example.test': ['RedactWall Operations'],
    },
    detectorFeedbackReport: {
      summary: { total: 2, valid: 1, noisy: 1, missed: 0, reviewCandidates: 3, privacy: 'metadata only; prompt bodies excluded' },
      detectors: [{ detectorId: 'US_SSN', total: 2, valid: 1, falsePositive: 1, tooSensitive: 0, missed: 0 }],
      reviewQueue: [{ queryId: 'q_pending', detectorId: 'US_SSN' }],
    },
    env: {
      SIEM_WEBHOOK_URL: 'https://siem.example.test/events',
      REDACTWALL_APPROVAL_TEAMS_WEBHOOK_URL: 'https://teams.example.test/webhook',
    },
  });

  assert.strictEqual(report.summary.events, 7);
  assert.strictEqual(report.summary.sensitiveEvents, 7);
  assert.strictEqual(report.summary.blocked, 5);
  assert.strictEqual(report.summary.redacted, 2);
  assert.strictEqual(report.summary.controlRate, 100);
  assert.ok(report.metrics.some((item) => item.id === 'controlled-sensitive' && item.value === 100));
  assert.ok(report.objectives.some((item) => item.id === 'prevent_sensitive_ai_egress' && item.state === 'covered'));
  assert.ok(report.objectives.some((item) => item.id === 'harden_ai_gateway_enforcement'));
  assert.ok(report.objectives.some((item) => item.id === 'harden_ai_asset_discovery'));
  assert.ok(report.objectives.some((item) => item.id === 'harden_mcp_agent_gateway'));
  assert.strictEqual(report.hardening.summary.total, 3);
  assert.ok(report.hardening.areas.some((item) => item.id === 'ai_gateway_enforcement'));
  assert.ok(report.hardening.areas.some((item) => item.id === 'ai_asset_discovery'));
  assert.ok(report.hardening.areas.some((item) => item.id === 'mcp_agent_gateway'));
  assert.ok(report.competitiveReadiness && report.competitiveReadiness.summary.score > 0);
  assert.strictEqual(report.competitiveReadiness.summary.privacy, 'metadata only; prompt bodies excluded');
  assert.ok(report.competitiveReadiness.matrix.some((item) => item.id === 'real_time_dlp' && item.score >= 90));
  assert.ok(report.competitiveReadiness.matrix.some((item) => item.id === 'behavior_anomaly_baselines'));
  assert.ok(report.competitiveReadiness.matrix.some((item) => item.id === 'agent_mcp_governance'));
  assert.ok(report.competitiveReadiness.matrix.some((item) => item.id === 'desktop_file_flow'));
  assert.ok(report.competitiveReadiness.matrix.some((item) => item.id === 'soc_compliance_handoff'));
  assert.ok(report.competitiveReadiness.nextGaps.every((item, index) => item.priority === index + 1));
  assert.ok(report.competitiveFocus && report.competitiveFocus.summary.score > 0);
  assert.strictEqual(report.competitiveFocus.summary.total, 3);
  assert.strictEqual(report.competitiveFocus.summary.privacy, 'metadata only; prompt bodies excluded');
  assert.ok(report.competitiveFocus.lanes.some((item) => item.id === 'continuous_shadow_ai_discovery' && item.marketBar));
  assert.ok(report.competitiveFocus.lanes.some((item) => item.id === 'mcp_saas_connector_coverage' && item.marketBar));
  // Operator console must not surface competitor names or go-to-market strategy.
  assert.ok(report.competitiveFocus.lanes.every((item) => !('competitors' in item)));
  assert.ok(!/beat|top-three|nightfall|strac|prompt security|check point/i.test(report.competitiveFocus.summary.objective));
  assert.ok(report.competitiveFocus.lanes.some((item) => item.id === 'mcp_saas_connector_coverage' && item.evidence.some((proof) => /shipped connector profile/.test(proof))));
  assert.ok(report.competitiveFocus.lanes.some((item) => item.id === 'mcp_saas_connector_coverage' && item.evidence.some((proof) => /connector registry proof/.test(proof))));
  assert.ok(report.competitiveFocus.lanes.some((item) => item.id === 'detection_quality_proof' && item.evidence.some((proof) => /reviewed detector/.test(proof))));
  assert.ok(report.competitiveFocus.lanes.some((item) => item.id === 'detection_quality_proof' && item.evidence.some((proof) => /Held-out eval floors met/.test(proof))));
  assert.ok(report.competitiveFocus.playbook.every((item, index) => item.priority === index + 1));
  assert.strictEqual(report.detectionQuality.summary.floorsMet, true);
  assert.ok(report.detectionQuality.summary.score >= 90);
  assert.strictEqual(report.detectionQuality.summary.privacy, 'held-out synthetic fixture only; prompt bodies excluded');
  assert.strictEqual(report.decisionQuality.summary.privacy, 'metadata only; prompt bodies excluded');
  assert.strictEqual(report.decisionQuality.summary.pendingReviews, 1);
  assert.strictEqual(report.decisionQuality.summary.escalatedReviews, 1);
  assert.ok(report.decisionQuality.cards.some((item) => item.id === 'approval_sla' && item.state === 'blocked'));
  assert.ok(report.decisionQuality.cards.some((item) => item.id === 'sensitive_control_quality' && item.score === 100));
  assert.ok(report.decisionQuality.hotspots.some((item) => item.kind === 'destination' && item.label === 'chatgpt.com'));
  assert.ok(report.behaviorBaselines && report.behaviorBaselines.summary.anomalies > 0);
  assert.strictEqual(report.behaviorBaselines.privacy, 'metadata only; prompt bodies excluded');
  assert.ok(report.behaviorBaselines.summary.activeEvents > 0);
  assert.strictEqual(report.behaviorBaselines.summary.recentWindowHours, 24);
  assert.ok(report.behaviorBaselines.dimensions.some((item) => item.kind === 'user' && item.label === 'analyst@example.test'));
  assert.ok(report.behaviorBaselines.playbook.every((item, index) => item.priority === index + 1));
  assert.strictEqual(report.aiInventory.summary.sanctioned, 2);
  assert.strictEqual(report.aiInventory.summary.shadow, 1);
  assert.ok(report.aiInventory.summary.highRiskAssets >= 3);
  assert.strictEqual(report.aiInventory.summary.mcpTools >= 2, true);
  assert.ok(report.aiInventory.apps.some((item) => item.name === 'notebooklm.google.com' && item.state === 'shadow'));
  assert.ok(report.aiInventory.apps.some((item) => item.name === 'notebooklm.google.com' && item.riskLevel === 'critical'));
  assert.ok(report.aiInventory.apps.some((item) => item.name === 'chatgpt.com' && item.state === 'sanctioned'));
  assert.ok(report.aiInventory.tools.some((item) => item.kind === 'MCP tool' && item.name === 'sharepoint.fetchMember' && item.state === 'allowed_registry'));
  assert.ok(report.controlGraph.summary.nodes >= 10);
  assert.ok(report.controlGraph.summary.edges >= 6);
  assert.ok(report.controlGraph.summary.highRiskAssets >= 3);
  assert.strictEqual(report.controlGraph.summary.privacy, 'prompt bodies excluded');
  assert.ok(report.controlGraph.lanes.some((lane) => lane.id === 'people' && lane.count > 0));
  assert.ok(report.controlGraph.lanes.some((lane) => lane.id === 'assets' && lane.attention > 0));
  assert.ok(report.controlGraph.nodes.some((node) => node.kind === 'user' && node.label === 'analyst@example.test'));
  assert.ok(report.controlGraph.nodes.some((node) => node.lane === 'assets' && node.label === 'notebooklm.google.com' && node.status === 'error'));
  assert.ok(report.controlGraph.nodes.some((node) => node.lane === 'controls' && node.label === 'AI response'));
  assert.ok(report.controlGraph.edges.some((edge) => edge.source === 'mcp_guard' && edge.controlled > 0));
  assert.strictEqual(report.agenticMcp.summary.events, 3);
  assert.strictEqual(report.agenticMcp.summary.activeAgents, 3);
  assert.strictEqual(report.agenticMcp.summary.blocked, 1);
  assert.strictEqual(report.agenticMcp.summary.redacted, 2);
  assert.strictEqual(report.agenticMcp.summary.privacy, 'prompt bodies excluded');
  assert.strictEqual(report.agenticMcp.connectorRegistry.summary.installProof, true);
  assert.strictEqual(report.agenticMcp.connectorRegistry.summary.shipped, 6);
  assert.strictEqual(report.agenticMcp.connectorRegistry.summary.shippedRuntimePresent, 6);
  assert.strictEqual(report.agenticMcp.connectorRegistry.summary.profileTemplates, 0);
  assert.strictEqual(report.agenticMcp.connectorRegistry.summary.nextConnector, 'none');
  assert.ok(report.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'microsoft365' && item.stage === 'shipped' && item.runtimePresent));
  assert.ok(report.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'google_drive' && item.stage === 'shipped' && item.runtimePresent));
  assert.ok(report.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'slack' && item.stage === 'shipped' && item.runtimePresent));
  assert.ok(report.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'teams' && item.stage === 'shipped' && item.runtimePresent));
  assert.ok(report.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'jira_confluence' && item.stage === 'shipped' && item.runtimePresent));
  assert.ok(report.agenticMcp.connectorRegistry.profiles.some((item) => item.id === 'database_readonly' && item.stage === 'shipped' && item.runtimePresent));
  assert.strictEqual(report.agenticMcp.policy.allowed.count, 2);
  assert.strictEqual(report.agenticMcp.policy.blocked.count, 1);
  assert.ok(report.agenticMcp.agents.some((item) => item.name === 'claude-desktop' && item.tools === 1));
  assert.ok(report.agenticMcp.tools.some((item) => item.name === 'sharepoint.fetchMember' && item.state === 'allowed_registry'));
  assert.ok(report.agenticMcp.tools.some((item) => item.name === 'sharepoint.deleteMember' && item.state === 'blocked'));
  assert.strictEqual(report.threatGuardrails.summary.events, 7);
  assert.strictEqual(report.threatGuardrails.summary.detections, 8);
  assert.strictEqual(report.threatGuardrails.summary.promptInjection, 1);
  assert.strictEqual(report.threatGuardrails.summary.sensitiveDisclosure, 4);
  assert.strictEqual(report.threatGuardrails.summary.unsafeOutput, 1);
  assert.strictEqual(report.threatGuardrails.summary.agentActions, 1);
  assert.strictEqual(report.threatGuardrails.summary.shadowAi, 1);
  assert.strictEqual(report.threatGuardrails.summary.privacy, 'prompt bodies excluded');
  assert.ok(report.threatGuardrails.rules.some((item) => item.id === 'prompt_injection' && item.framework === 'OWASP LLM01' && item.status === 'error'));
  assert.ok(report.threatGuardrails.rules.some((item) => item.id === 'unsafe_output' && item.framework === 'OWASP LLM05'));
  assert.ok(report.threatGuardrails.rules.some((item) => item.id === 'excessive_agency' && item.framework === 'OWASP LLM06'));
  assert.ok(report.threatGuardrails.controls.some((item) => item.id === 'response_scanning' && item.state === 'ready'));
  assert.ok(report.threatGuardrails.recent.some((item) => item.id === 'q_injection' && item.threats.includes('Prompt injection')));
  assert.ok(report.events.some((item) => item.id === 'q_mcp_tool_block' && item.title === 'MCP tool blocked'));
  assert.strictEqual(report.segments.summary.total >= 6, true);
  assert.strictEqual(report.segments.summary.selectedId, 'all');
  assert.strictEqual(report.segments.summary.privacy, 'metadata only; prompt bodies excluded');
  assert.strictEqual(report.segments.summary.ownerViews, 5);
  assert.ok(report.segments.views.some((item) => item.id === 'owner:lending' && item.segmentId === 'group:redactwall-lending' && item.reviewerRole === 'approver'));
  assert.ok(report.segments.views.some((item) => item.id === 'owner:it' && item.reviewerRole === 'operator'));
  assert.ok(report.segments.matrix.some((item) => item.type === 'owner' && item.label === 'Lending' && item.ownerGroup === 'Lending'));
  assert.ok(report.segments.matrix.some((item) => item.id === 'org:cu-lending' && item.events === 4 && item.controlRate === 100));
  assert.ok(report.segments.matrix.some((item) => item.id === 'group:redactwall-lending' && item.events === 3));
  assert.ok(report.segments.matrix.some((item) => item.id === 'workflow:member-services' && item.sensitive === 2));
  assert.ok(report.segments.filters.some((item) => item.id === 'source:browser'));
  assert.ok(report.actionQueue.some((item) => item.category === 'Current mission' && item.label === 'Require the proxy sensor'));
  assert.ok(report.actionQueue.some((item) => item.category === 'Behavior baseline'));
  assert.ok(report.actionQueue.some((item) => item.category === 'Shadow AI' && /notebooklm\.google\.com/.test(item.detail)));
  assert.ok(report.actionQueue.some((item) => item.category === 'Current mission' && item.workflowStatus === 'assigned' && item.workflowOwner === 'network_security'));
  assert.ok(report.actionQueue.some((item) => item.category === 'Shadow AI' && item.workflowStatus === 'resolved' && item.workflowProofState === 'proof_pending'));
  assert.ok(report.actionQueue.every((item, index) => item.priority === index + 1));
  assert.ok(report.objectives.some((item) => item.id === 'close_shadow_ai_gaps' && item.state === 'attention'));
  assert.ok(report.objectives.some((item) => item.id === 'examiner_ready_evidence' && item.state === 'covered'));
  assert.ok(report.surfaces.some((item) => item.id === 'surface-browser_extension' && item.status === 'online'));
  assert.ok(report.surfaces.some((item) => item.id === 'surface-ai_asset_discovery'));
  assert.ok(report.surfaces.some((item) => item.id === 'surface-mcp_agent_gateway'));
  assert.ok(report.surfaces.some((item) => item.id === 'surface-shadow-ai' && item.status === 'warning'));
  assert.ok(report.events.some((item) => item.id === 'q_pending' && item.severity === 'critical'));
  assert.strictEqual(report.trend.length, 7);
  assert.ok(report.trend.some((item) => item.date === '2026-07-02' && item.blocked === 4 && item.redacted === 1));
  assert.ok(report.controls.some((item) => item.label === 'File upload' && item.blocked === 1));
  assert.ok(report.controls.some((item) => item.label === 'AI response' && item.redacted === 1));
  assert.ok(report.controls.some((item) => item.label === 'MCP tool data' && item.blocked === 1 && item.redacted === 1));
  assert.ok(!JSON.stringify(report).includes('524-71-9043'));
  assert.ok(!JSON.stringify(report).includes('Member SSN'));
  assert.ok(!JSON.stringify(report.detectionQuality).includes('Leadership has decided'));

  const lending = posture.summarize({
    rows,
    policy,
    auditIntegrity: { ok: true, count: 8 },
    segmentId: 'group:redactwall-lending',
    identityGroups: {
      'analyst@example.test': ['RedactWall Lending'],
      'ops@example.test': ['RedactWall Operations'],
    },
    now: '2026-07-03T00:00:00.000Z',
    env: {},
  });
  assert.strictEqual(lending.segments.active.id, 'group:redactwall-lending');
  assert.strictEqual(lending.segments.active.label, 'RedactWall Lending');
  assert.strictEqual(lending.summary.events, 3);
  assert.strictEqual(lending.summary.blocked, 2);
  assert.strictEqual(lending.summary.redacted, 1);
  assert.strictEqual(lending.summary.controlRate, 100);
  assert.ok(lending.events.every((item) => ['q_pending', 'q_response', 'q_injection'].includes(item.id)));
  assert.ok(lending.segments.matrix.some((item) => item.id === 'group:redactwall-operations'));
  assert.ok(!JSON.stringify(lending).includes('524-71-9043'));
  assert.ok(!JSON.stringify(lending).includes('Member SSN'));
});

test('posture covers low-risk, coaching, shadow-only, and missing-sensor edge states', () => {
  const report = posture.summarize({
    rows: [
      {
        id: 'q_allowed_info',
        createdAt: '2026-07-03T10:00:00.000Z',
        status: 'allowed',
        user: 'analyst@example.test',
        destination: 'chatgpt.com',
        source: 'api',
        channel: 'submit',
      },
      {
        id: 'q_shadow_only',
        createdAt: '2026-07-03T10:01:00.000Z',
        status: 'shadow_ai',
        user: 'analyst@example.test',
        destination: 'unknown-ai.example',
        source: 'proxy',
        channel: 'shadow_ai',
      },
      {
        id: 'q_warned',
        createdAt: '2026-07-03T10:02:00.000Z',
        status: 'warned',
        user: 'analyst@example.test',
        destination: 'chatgpt.com',
        source: 'browser_extension',
        channel: 'paste',
      },
      {
        id: 'q_custom',
        createdAt: '2026-07-03T10:03:00.000Z',
        status: 'custom_event',
        user: 'analyst@example.test',
        destination: 'internal.example',
        source: 'custom_sensor',
        channel: 'observe',
        categories: [{ category: 'CUSTOM_CATEGORY' }],
      },
    ],
    policy: {
      blockUnapprovedAiDestinations: false,
      responseScanMode: 'allow',
    },
    coverageReport: {
      score: 0,
      totals: {},
      sensors: [],
    },
    auditIntegrity: { ok: false, count: 0 },
    now: '2026-07-03T11:00:00.000Z',
    env: {},
  });

  assert.strictEqual(posture.statusDecision('warned'), 'coached');
  assert.strictEqual(posture.statusDecision('custom_event'), 'custom_event');
  assert.ok(report.events.some((item) => item.id === 'q_allowed_info' && item.severity === 'info' && item.status === 'online'));
  assert.ok(report.events.some((item) => item.id === 'q_shadow_only' && item.confidence === 84 && item.status === 'warning'));
  assert.ok(report.events.some((item) => item.id === 'q_custom' && item.relatedMetric === 'custom_event'));
  assert.ok(report.trend.some((item) => item.date === '2026-07-03' && item.coached === 1 && item.shadow === 1 && item.allowed === 1));
  assert.ok(report.controls.some((item) => item.label === 'User coaching' && item.coached === 1));
  assert.ok(report.controls.some((item) => item.label === 'Shadow AI' && item.shadow === 1));
  assert.ok(report.surfaces.some((item) => item.id === 'surface-browser_extension' && item.status === 'offline'));
  assert.strictEqual(report.aiInventory.summary.sanctioned, 0);
  assert.strictEqual(report.aiInventory.apps.length, 0);
  assert.ok(report.controlGraph.nodes.some((item) => item.lane === 'assets' && item.label === 'unknown-ai.example'));
  assert.ok(report.controlGraph.edges.some((item) => item.source === 'proxy'));
  assert.ok(report.actionQueue.length > 0);
  assert.ok(report.objectives.some((item) => item.id === 'examiner_ready_evidence' && item.state === 'attention'));
  assert.ok(report.objectives.some((item) => item.id === 'govern_ai_actions' && item.state === 'attention'));
  assert.ok(report.hardening.areas.some((item) => item.id === 'mcp_agent_gateway' && item.state !== 'ready'));
  assert.ok(report.competitiveReadiness.matrix.some((item) => item.id === 'shadow_ai_governance' && item.gaps.length));
  assert.ok(report.competitiveReadiness.matrix.some((item) => item.id === 'agent_mcp_governance' && item.state === 'gap'));
  assert.ok(report.competitiveFocus.lanes.some((item) => item.id === 'detection_quality_proof' && item.gaps.includes('Review detector candidates as valid, noisy, too sensitive, or missed')));
  assert.strictEqual(report.agenticMcp.connectorRegistry.summary.installProof, false);
  assert.ok(report.competitiveFocus.lanes.some((item) => item.id === 'mcp_saas_connector_coverage' && item.gaps.includes('Run MCP install check with connector registry heartbeat proof')));

  const heartbeatOnly = posture.summarize({
    rows: [{
      id: 'hb_endpoint',
      createdAt: '2026-07-03T10:00:00.000Z',
      status: 'sensor_heartbeat',
      user: 'tech@example.test',
      destination: 'endpoint-install',
      source: 'endpoint_agent',
      channel: 'heartbeat',
    }],
    policy: {},
    coverageReport: { score: 0, totals: {}, sensors: [] },
    auditIntegrity: { ok: true, count: 1 },
    now: '2026-07-03T11:00:00.000Z',
    env: {},
  });
  assert.strictEqual(heartbeatOnly.behaviorBaselines.summary.activeEvents, 0);
  assert.strictEqual(heartbeatOnly.behaviorBaselines.summary.score, 0);
  assert.strictEqual(heartbeatOnly.behaviorBaselines.summary.state, 'gap');
  assert.ok(heartbeatOnly.competitiveReadiness.matrix.some((item) => (
    item.id === 'behavior_anomaly_baselines'
    && item.gaps.includes('Run live sensor traffic before behavioral baselines can learn normal activity')
  )));
});

test('posture leak map attributes sanitized flows to identity segments', () => {
  const coverageReport = coverage.summarize(rows, policy);
  const report = posture.summarize({
    rows,
    policy,
    coverageReport,
    auditIntegrity: { ok: true, count: 8 },
    now: '2026-07-03T00:00:00.000Z',
    identityGroups: {
      'analyst@example.test': ['RedactWall Lending'],
      'ops@example.test': ['RedactWall Operations'],
    },
    env: {},
  });
  const map = report.leakMap;
  assert.ok(map && Array.isArray(map.segments) && Array.isArray(map.edges));
  assert.ok(map.segments.some((item) => item.label === 'RedactWall Lending'));
  assert.ok(map.segments.some((item) => item.label === 'RedactWall Operations'));
  assert.ok(map.destinations.some((item) => item.id === 'chatgpt.com'));
  const lendingEdge = map.edges.find((item) => item.from === 'group:redactwall-lending' && item.to === 'chatgpt.com');
  assert.ok(lendingEdge, 'lending -> chatgpt edge missing');
  assert.strictEqual(lendingEdge.via, 'browser_extension');
  assert.ok(lendingEdge.pending >= 1);
  assert.ok(lendingEdge.categories.some((item) => item.label === 'US_SSN'));
  assert.ok(map.channels.some((item) => item.id === 'browser_extension' && item.events > 0));
  assert.ok(map.categories.some((item) => item.label === 'US_SSN'));
  assert.strictEqual(map.summary.privacy, 'prompt bodies excluded');
  assert.ok(map.summary.controlRate >= 0 && map.summary.controlRate <= 100);
  const serialized = JSON.stringify(map);
  assert.strictEqual(serialized.includes('524-71-9043'), false);
  assert.strictEqual(serialized.includes('rawPrompt'), false);
});

test('posture leak map flags uncontrolled and shadow flows per segment', () => {
  const map = posture.leakMapGraph({
    rows: [
      {
        id: 'q_uncontrolled',
        createdAt: '2026-07-02T11:00:00.000Z',
        status: 'allowed',
        user: 'support@example.test',
        destination: 'chatgpt.com',
        source: 'browser_extension',
        channel: 'submit',
        findings: [{ type: 'US_SSN', severity: 4, score: 0.9, masked: '***' }],
        riskScore: 88,
        maxSeverity: 4,
      },
      {
        id: 'q_shadow_flow',
        createdAt: '2026-07-01T09:00:00.000Z',
        status: 'shadow_ai',
        user: 'support@example.test',
        destination: 'unknown-ai.example',
        source: 'proxy',
        channel: 'shadow_ai',
      },
      {
        id: 'q_heartbeat',
        status: 'sensor_heartbeat',
        destination: 'endpoint-install',
        source: 'endpoint_agent',
      },
    ],
    identityGroups: { 'support@example.test': ['Customer Support'] },
    inventory: { apps: [{ name: 'chatgpt.com', state: 'sanctioned' }] },
  });
  const support = map.segments.find((item) => item.label === 'Customer Support');
  assert.ok(support, 'customer support segment missing');
  assert.strictEqual(support.uncontrolled, 1);
  assert.strictEqual(support.shadow, 1);
  assert.strictEqual(support.status, 'error');
  const shadowDest = map.destinations.find((item) => item.id === 'unknown-ai.example');
  assert.ok(shadowDest && shadowDest.state === 'shadow');
  const riskyEdge = map.edges.find((item) => item.to === 'chatgpt.com');
  assert.ok(riskyEdge && riskyEdge.uncontrolled === 1 && riskyEdge.status === 'error');
  assert.strictEqual(map.edges.some((item) => item.to === 'endpoint-install'), false);
});

test('posture leak map degrades to an empty graph without activity', () => {
  const empty = posture.leakMapGraph({ rows: [], identityGroups: {}, inventory: {} });
  assert.deepStrictEqual(empty.segments, []);
  assert.deepStrictEqual(empty.edges, []);
  assert.strictEqual(empty.summary.events, 0);
  assert.strictEqual(empty.summary.controlRate, 100);
  assert.strictEqual(empty.summary.status, 'idle');
  assert.strictEqual(empty.summary.privacy, 'prompt bodies excluded');
});
