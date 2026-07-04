'use strict';
/** Examiner evidence export must not leak prompt bodies or audit details. */
const test = require('node:test');
const assert = require('node:assert');
const evidence = require('../server/evidence');

test('evidence pack omits raw prompt, redacted prompt body, token vault, and audit detail text', () => {
  const pack = evidence.buildEvidencePack({
    version: '0.3.0',
    generatedAt: '2026-06-26T12:00:00.000Z',
    queryLimit: 1,
    auditLimit: 1,
    report: {
      id: 'quarterly-examiner-pack',
      generatedBy: 'compliance',
      periodStart: '2026-04-01T00:00:00.000Z',
      periodEnd: '2026-06-30T23:59:59.999Z',
      scheduled: true,
      schedule: {
        id: 'quarterly',
        cadence: 'quarterly',
        nextRunAt: '2026-09-30T23:00:00.000Z',
        retentionDays: 730,
        secret: 'schedule-secret-should-not-export',
      },
    },
    policy: { enforcementMode: 'block' },
    stats: { total: 1 },
    auditIntegrity: { ok: true, count: 1 },
    coverage: {
      score: 82,
      rawPrompt: 'coverage should not export Member John Carter',
      totals: {
        events: 1,
        blocked: 1,
        requiredSensors: 3,
        activeRequiredSensors: 1,
        activeSensorVersionGaps: 1,
        activeSensorHealthWarnings: 1,
        endpointAiInventoryReports: 1,
        endpointAiToolDetections: 2,
        endpointAiToolUnapproved: 1,
        discoveryFeeds: 1,
        freshDiscoveryFeeds: 1,
        staleDiscoveryFeeds: 0,
        lastDiscoveryAt: '2026-06-26T12:00:00.000Z',
      },
      sensors: [{
        source: 'browser_extension',
        label: 'Browser extension',
        required: true,
        events: 1,
        latestVersion: '0.2.9',
        desiredVersion: '0.3.0',
        versions: [{ version: '0.2.9', events: 1, lastSeen: '2026-06-26T12:00:00.000Z' }],
        versionHealth: 'outdated',
        installHealth: {
          at: '2026-06-26T12:00:00.000Z',
          state: 'attention',
          failedChecks: ['managed_identity'],
          aiToolInventory: {
            detected: 2,
            reported: 2,
            unapproved: 1,
            truncated: false,
            state: 'attention',
            tools: [
              { id: 'cursor', label: 'Cursor', approved: true, state: 'approved', detail: 'detected', rawPath: 'C:\\secret\\Cursor.exe' },
              { id: 'claude_desktop', label: 'Claude Desktop', approved: false, state: 'unapproved', detail: 'unapproved detected', rawArgs: '--profile secret' },
            ],
          },
          checks: [
            { id: 'endpoint_env_file', ok: true, detail: 'found', secret: 'check-secret-should-not-export' },
            { id: 'managed_identity', ok: false, detail: 'missing managed identity' },
          ],
        },
        secret: 'coverage-secret-should-not-export',
      }],
      fleet: [{
        source: 'browser_extension',
        label: 'Browser extension',
        user: 'jdoe',
        orgId: 'cu-acme',
        required: true,
        state: 'attention',
        events: 1,
        latestVersion: '0.2.9',
        desiredVersion: '0.3.0',
        versionHealth: 'outdated',
        platforms: ['chrome_mv3'],
        installHealth: {
          at: '2026-06-26T12:00:00.000Z',
          state: 'attention',
          failedChecks: ['managed_identity'],
          checks: [
            { id: 'managed_identity', ok: false, detail: 'missing managed identity', secret: 'fleet-check-secret-should-not-export' },
          ],
        },
        secret: 'fleet-secret-should-not-export',
      }],
      endpointAiTools: [
        {
          id: 'claude_desktop',
          label: 'Claude Desktop',
          approved: false,
          state: 'unapproved',
          detail: 'unapproved detected',
          user: 'jdoe',
          orgId: 'cu-acme',
          lastSeen: '2026-06-26T12:00:00.000Z',
          platforms: ['win32'],
          processArgs: '--profile secret',
        },
        {
          id: 'cursor',
          label: 'Cursor',
          approved: true,
          state: 'approved',
          detail: 'detected',
          user: 'jdoe',
          orgId: 'cu-acme',
          lastSeen: '2026-06-26T12:00:00.000Z',
          platforms: ['win32'],
          localPath: 'C:\\secret\\Cursor.exe',
        },
      ],
      endpointFileFlowProfiles: [
        {
          id: 'lending',
          state: 'covered',
          detail: 'configured directory',
          user: 'jdoe',
          orgId: 'cu-acme',
          lastSeen: '2026-06-26T12:00:00.000Z',
          platforms: ['win32'],
          localPath: 'C:\\secret\\lending-drop',
        },
        {
          id: 'call_center',
          state: 'attention',
          detail: 'missing directory',
          user: 'jdoe',
          orgId: 'cu-acme',
          lastSeen: '2026-06-26T12:00:00.000Z',
          platforms: ['win32'],
          watchedDirectory: 'C:\\secret\\call-center-drop',
        },
      ],
      discoveryFeeds: [{
        source: 'zscaler',
        state: 'fresh',
        observations: 7,
        destinations: 1,
        users: 1,
        categories: ['chatbot'],
        lastSeen: '2026-06-26T12:00:00.000Z',
        ageHours: 1,
        privacy: 'host-only destinations; prompt bodies and URL paths omitted',
        rawPrompt: '[AI discovery import] member SSN 524-71-9043',
      }],
    },
    backup: {
      ok: true,
      file: 'C:\\secret\\backups\\sentinel-2026-06-26.db',
      bytes: 4096,
      backupSha256: '2'.repeat(64),
      manifestOk: true,
      auditIntegrity: { ok: true, count: 1 },
      sourceIntegrity: { ok: true, count: 1 },
      manifest: {
        backupFile: 'sentinel-2026-06-26.db',
        secret: 'backup-secret-should-not-export',
      },
    },
    restoreDrill: {
      ok: true,
      file: 'C:\\secret\\restore\\restored-sentinel.db',
      backupSha256: '3'.repeat(64),
      manifestOk: true,
      auditIntegrity: { ok: true, count: 1 },
      secret: 'restore-secret-should-not-export',
    },
    detectors: [{ id: 'US_SSN', severity: 4 }],
    queries: [{
      id: 'q_1',
      createdAt: '2026-06-26T12:00:00.000Z',
      status: 'pending',
      mode: 'block',
      user: 'jdoe',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
      sensor: {
        name: 'browser_extension',
        version: '0.3.0',
        platform: 'chrome_mv3',
        secret: 'ps_ingest_should_not_export',
      },
      redactedPrompt: 'Member John Carter has SSN [US_SSN]',
      _rawPrompt: 'Member John Carter has SSN 524-71-9043',
      _tokenVault: 'sealed-vault',
      decisionNote: 'contains member SSN 524-71-9043',
      retentionPurgedAt: '2026-06-27T12:00:00.000Z',
      retentionPurgedFields: ['rawPrompt'],
      assignedRole: 'approver',
      assignedGroup: 'compliance',
      workflowReason: 'detector:US_SSN',
      slaDueAt: '2026-06-26T16:00:00.000Z',
      escalatedAt: null,
      escalationReason: null,
      notificationStatus: 'not_configured',
      notificationLastAttemptAt: null,
      notificationAttemptCount: 0,
      notificationChannels: [],
      installChecks: [
        { id: 'endpoint_env_file', ok: true, detail: 'found', secret: 'query-check-secret-should-not-export' },
      ],
      findings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '**** 9043', value: '524-71-9043' }],
      categories: [],
      reasons: ['Hard-stop entity present: US_SSN'],
      riskScore: 34,
      maxSeverity: 4,
      maxSeverityLabel: 'critical',
    }],
    audit: [{
      id: 'a_1',
      ts: '2026-06-26T12:00:00.000Z',
      action: 'BLOCKED',
      queryId: 'q_1',
      actor: 'jdoe',
      detail: 'browser_extension/submit: member SSN 524-71-9043',
      prevHash: '0'.repeat(64),
      hash: '1'.repeat(64),
    }],
  });

  const wire = JSON.stringify(pack);
  assert.strictEqual(pack.schemaVersion, 2);
  assert.strictEqual(pack.report.scheduled, true);
  assert.strictEqual(pack.report.schedule.cadence, 'quarterly');
  assert.strictEqual(pack.scope.rawPromptBodiesIncluded, false);
  assert.strictEqual(pack.scope.auditDetailsIncluded, false);
  assert.strictEqual(pack.scope.backupEvidenceIncluded, true);
  assert.strictEqual(pack.scope.restoreDrillEvidenceIncluded, true);
  assert.strictEqual(pack.backup.ok, true);
  assert.strictEqual(pack.backup.backupFile, 'sentinel-2026-06-26.db');
  assert.strictEqual(pack.restoreDrill.restoredFile, 'restored-sentinel.db');
  assert.ok(pack.controlMappings.some((item) => item.id === 'backup_recoverability' && item.state === 'covered'));
  assert.ok(pack.queries[0].promptHash);
  assert.ok(pack.audit[0].detailHash);
  assert.strictEqual(pack.coverage.score, 82);
  assert.strictEqual(pack.coverage.totals.requiredSensors, 3);
  assert.strictEqual(pack.coverage.totals.activeSensorHealthWarnings, 1);
  assert.strictEqual(pack.coverage.totals.endpointAiToolDetections, 2);
  assert.strictEqual(pack.coverage.totals.endpointAiToolUnapproved, 1);
  assert.strictEqual(pack.coverage.totals.discoveryFeeds, 1);
  assert.strictEqual(pack.coverage.totals.freshDiscoveryFeeds, 1);
  assert.strictEqual(pack.coverage.discoveryFeeds[0].source, 'zscaler');
  assert.strictEqual(pack.coverage.discoveryFeeds[0].privacy, 'host-only destinations; prompt bodies and URL paths omitted');
  assert.strictEqual(pack.coverage.sensors[0].required, true);
  assert.strictEqual(pack.coverage.sensors[0].desiredVersion, '0.3.0');
  assert.strictEqual(pack.coverage.sensors[0].installHealth.state, 'attention');
  assert.deepStrictEqual(pack.coverage.sensors[0].installHealth.failedChecks, ['managed_identity']);
  assert.deepStrictEqual(pack.coverage.sensors[0].installHealth.aiToolInventory.tools.map((tool) => [tool.id, tool.state]), [
    ['cursor', 'approved'],
    ['claude_desktop', 'unapproved'],
  ]);
  assert.deepStrictEqual(pack.coverage.endpointAiTools.map((tool) => [tool.id, tool.state, tool.user]), [
    ['claude_desktop', 'unapproved', 'jdoe'],
    ['cursor', 'approved', 'jdoe'],
  ]);
  assert.deepStrictEqual(pack.coverage.endpointFileFlowProfiles.map((profile) => [profile.id, profile.state, profile.user]), [
    ['lending', 'covered', 'jdoe'],
    ['call_center', 'attention', 'jdoe'],
  ]);
  assert.strictEqual(pack.coverage.fleet[0].user, 'jdoe');
  assert.strictEqual(pack.coverage.fleet[0].orgId, 'cu-acme');
  assert.strictEqual(pack.coverage.fleet[0].state, 'attention');
  assert.deepStrictEqual(pack.coverage.fleet[0].installHealth.failedChecks, ['managed_identity']);
  assert.strictEqual(pack.lineage.byUser[0].key, 'jdoe');
  assert.strictEqual(pack.lineage.byDestination[0].key, 'chatgpt.com');
  assert.strictEqual(pack.lineage.bySensor[0].key, 'browser_extension');
  assert.strictEqual(pack.lineage.byCategory[0].key, 'US_SSN');
  assert.strictEqual(pack.lineage.byDecision[0].key, 'blocked');
  assert.strictEqual(pack.queries[0].retentionPurgedAt, '2026-06-27T12:00:00.000Z');
  assert.deepStrictEqual(pack.queries[0].retentionPurgedFields, ['rawPrompt']);
  assert.deepStrictEqual(pack.queries[0].workflow, {
    assignedRole: 'approver',
    assignedGroup: 'compliance',
    workflowReason: 'detector:US_SSN',
    slaDueAt: '2026-06-26T16:00:00.000Z',
    escalatedAt: null,
    escalationReason: null,
    notificationStatus: 'not_configured',
    notificationLastAttemptAt: null,
    notificationAttemptCount: 0,
    notificationChannels: [],
  });
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member John Carter'));
  assert.ok(!wire.includes('coverage-secret-should-not-export'));
  assert.ok(!wire.includes('check-secret-should-not-export'));
  assert.ok(!wire.includes('query-check-secret-should-not-export'));
  assert.ok(!wire.includes('fleet-secret-should-not-export'));
  assert.ok(!wire.includes('fleet-check-secret-should-not-export'));
  assert.ok(!wire.includes('schedule-secret-should-not-export'));
  assert.ok(!wire.includes('backup-secret-should-not-export'));
  assert.ok(!wire.includes('restore-secret-should-not-export'));
  assert.ok(!wire.includes('C:\\secret'));
  assert.ok(!wire.includes('--profile secret'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('contains member SSN'));
  assert.ok(!wire.includes('ps_ingest_should_not_export'));
  assert.deepStrictEqual(pack.queries[0].sensor, { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' });
  assert.deepStrictEqual(pack.queries[0].installChecks, [{ id: 'endpoint_env_file', ok: true, detail: 'found' }]);
  assert.ok(wire.includes('**** 9043'));
});

test('evidence pack keeps exported rows bounded while lineage summarizes full history', () => {
  const recent = {
    id: 'q_recent',
    createdAt: '2026-06-26T12:02:00.000Z',
    status: 'allowed',
    user: 'recent@example.test',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
    findings: [],
    categories: [],
    riskScore: 0,
    redactedPrompt: 'recent safe prompt',
  };
  const olderSecret = '524-71-9043';
  const older = {
    id: 'q_older',
    createdAt: '2026-06-26T12:01:00.000Z',
    status: 'destination_blocked',
    user: 'older@example.test',
    destination: 'claude.ai',
    source: 'endpoint_agent',
    channel: 'file_upload',
    findings: [{ type: 'US_SSN', severity: 4, score: 1, masked: '***-**-9043', value: olderSecret }],
    categories: [],
    riskScore: 40,
    redactedPrompt: 'Older member SSN ***-**-9043',
  };

  const pack = evidence.buildEvidencePack({
    version: '0.3.0',
    generatedAt: '2026-06-26T12:03:00.000Z',
    queryLimit: 1,
    auditLimit: 1,
    summaryRowsIncluded: 2,
    summariesUseFullHistory: true,
    policy: {},
    stats: { total: 2 },
    auditIntegrity: { ok: true, count: 2 },
    coverage: { totals: { events: 2 } },
    queries: [recent],
    lineageQueries: [recent, older],
    audit: [],
  });

  assert.strictEqual(pack.queries.length, 1);
  assert.strictEqual(pack.queries[0].id, 'q_recent');
  assert.strictEqual(pack.scope.summaryRowsIncluded, 2);
  assert.strictEqual(pack.scope.summariesUseFullHistory, true);
  assert.ok(pack.lineage.byUser.some((item) => item.key === 'older@example.test'));
  assert.ok(pack.lineage.byDestination.some((item) => item.key === 'claude.ai'));
  assert.ok(pack.lineage.byCategory.some((item) => item.key === 'US_SSN'));
  const wire = JSON.stringify(pack);
  assert.ok(!wire.includes(olderSecret));
  assert.ok(!wire.includes('Older member SSN'));
});

test('lineage groups user, destination, sensor, category, and decision without prompt text', () => {
  const lineage = evidence.buildLineage([
    {
      id: 'q_1',
      createdAt: '2026-06-26T12:00:00.000Z',
      status: 'redacted',
      user: 'analyst@example.test',
      destination: 'claude.ai',
      source: 'browser_extension',
      channel: 'submit',
      findings: [{ type: 'CREDIT_CARD', severity: 4, score: 1, masked: '**** 1111', value: '4111 1111 1111 1111' }],
      categories: [],
      riskScore: 40,
      redactedPrompt: 'Card **** 1111',
    },
    {
      id: 'q_2',
      createdAt: '2026-06-26T12:01:00.000Z',
      status: 'destination_blocked',
      user: 'analyst@example.test',
      destination: 'poe.com',
      source: 'endpoint_agent',
      channel: 'file_upload',
      findings: [],
      categories: ['CONFIDENTIAL_BUSINESS', { category: 'LEGAL_CONTRACT' }],
      riskScore: 0,
      redactedPrompt: '[destination blocked] poe.com',
    },
  ]);

  const wire = JSON.stringify(lineage);
  assert.deepStrictEqual(lineage.byDecision.map((item) => item.key).sort(), ['blocked', 'redacted']);
  assert.strictEqual(lineage.byUser[0].key, 'analyst@example.test');
  assert.strictEqual(lineage.byUser[0].events, 2);
  assert.ok(lineage.byCategory.some((item) => item.key === 'CREDIT_CARD'));
  assert.ok(lineage.byCategory.some((item) => item.key === 'CONFIDENTIAL_BUSINESS'));
  assert.ok(lineage.byCategory.some((item) => item.key === 'LEGAL_CONTRACT'));
  assert.ok(!wire.includes('4111 1111 1111 1111'));
  assert.ok(!wire.includes('Card **** 1111'));
});

test('lineage classifies response scan policy outcomes without response text', () => {
  const lineage = evidence.buildLineage([
    {
      status: 'response_redacted',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'mcp_guard',
      channel: 'ai_response',
      categories: ['CONFIDENTIAL_BUSINESS'],
      riskScore: 24,
      maxSeverity: 2,
      redactedPrompt: '[AI response] [REDACTED: CONFIDENTIAL_BUSINESS]',
    },
    {
      status: 'response_blocked',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'mcp_guard',
      channel: 'ai_response',
      findings: [{ type: 'US_SSN', severity: 4, score: 1, masked: '**** 9043', value: '524-71-9043' }],
      riskScore: 40,
      maxSeverity: 4,
      redactedPrompt: '[AI response] SSN **** 9043',
    },
  ]);

  const decisions = Object.fromEntries(lineage.byDecision.map((item) => [item.key, item.events]));
  assert.strictEqual(decisions.redacted, 1);
  assert.strictEqual(decisions.blocked, 1);
  const wire = JSON.stringify(lineage);
  assert.ok(!wire.includes('524-71-9043'));
});

test('lineage classifies browser action blocks without clipboard text', () => {
  const lineage = evidence.buildLineage([{
    status: 'action_blocked',
    user: 'analyst@example.test',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'paste',
    redactedPrompt: '[browser action blocked] paste chatgpt.com',
  }]);

  assert.deepStrictEqual(lineage.byDecision.map((item) => item.key), ['blocked']);
  assert.strictEqual(lineage.byChannel[0].key, 'paste');
  assert.strictEqual(lineage.byDestination[0].key, 'chatgpt.com');
  assert.ok(!JSON.stringify(lineage).includes('524-71-9043'));
});

test('posture evidence sanitizer bounds undefined, array, and object values', () => {
  const posture = evidence.safePosture({
    generatedAt: '2026-06-28T12:00:00.000Z',
    windowDays: 30,
    summary: {
      covered: true,
      missing: undefined,
    },
    metrics: [{
      id: 'metric_1',
      label: 'Metric',
      value: [{ nested: 'ok', secret: 'value that should be bounded' }],
      trend: { direction: 'up', secret: 'hidden-ish metadata' },
      status: 'covered',
    }],
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
      apps: [{
        id: 'ai-app-chatgpt-com',
        name: 'chatgpt.com',
        kind: 'AI app',
        state: 'sanctioned',
        events: 3,
        detail: '3 events / 1 blocked / 1 user',
      }],
      tools: [{
        id: 'cursor',
        name: 'Cursor',
        kind: 'Endpoint tool',
        state: 'local_unapproved',
        detail: 'Unapproved local AI tool',
      }],
    },
    threatGuardrails: {
      summary: {
        events: 3,
        detections: 4,
        activeRules: 2,
        promptInjection: 1,
        unsafeOutput: 1,
        privacy: 'prompt bodies excluded',
      },
      rules: [{
        id: 'prompt_injection',
        label: 'Prompt injection',
        framework: 'OWASP LLM01',
        atlas: 'MITRE ATLAS: prompt injection',
        control: 'Browser injection sensor',
        events: 1,
        blocked: 1,
        state: 'critical',
        status: 'error',
        detail: 'Hidden instructions blocked before submission.',
        targetTab: 'activity',
      }],
      controls: [{
        id: 'response_scanning',
        label: 'Response scanning',
        state: 'ready',
        detail: 'AI response mode: redact 524-71-9043',
        targetTab: 'policy',
      }],
      recent: [{
        id: 'q_injection',
        timestamp: '2026-06-28T12:02:00.000Z',
        source: 'browser_extension',
        destination: 'chatgpt.com',
        severity: 'critical',
        status: 'error',
        decision: 'blocked',
        title: 'Prompt injection blocked',
        threats: ['Prompt injection'],
        detail: 'Browser / Prompt submit / raw content excluded',
      }],
    },
    competitiveReadiness: {
      generatedAt: '2026-06-28T12:00:00.000Z',
      summary: {
        score: 78,
        state: 'pilot_ready',
        ready: 4,
        gaps: 1,
        privacy: 'metadata only; prompt bodies excluded',
      },
      matrix: [{
        id: 'soc_compliance_handoff',
        label: 'SOC And Examiner Handoff',
        marketBar: 'SOC package, posture feed, approval workflow routing, evidence export, and audit-chain proof.',
        score: 82,
        state: 'pilot_ready',
        status: 'online',
        evidence: ['Offline SOC integration ZIP is available'],
        gaps: ['Do not export 524-71-9043 in this gap'],
        action: 'Open audit',
        targetTab: 'audit',
        source: 'siem',
        detail: 'SOC handoff is near ready',
      }],
      differentiators: ['Local-first detection and redaction before AI egress'],
      nextGaps: [{
        id: 'soc_compliance_handoff',
        priority: 1,
        label: 'SOC And Examiner Handoff',
        detail: 'Configure SIEM_WEBHOOK_URL',
        action: 'Open audit',
        targetTab: 'audit',
        score: 82,
      }],
    },
    behaviorBaselines: {
      generatedAt: '2026-06-28T12:00:00.000Z',
      privacy: 'metadata only; prompt bodies excluded',
      summary: {
        score: 66,
        state: 'warning',
        status: 'warning',
        anomalies: 1,
        critical: 0,
        warning: 1,
        baselineDays: 13,
        recentWindowHours: 24,
      },
      dimensions: [{
        id: 'user:redacted',
        kind: 'user',
        label: 'member-524-71-9043@example.test',
        title: 'User surge',
        state: 'warning',
        status: 'warning',
        score: 58,
        recentEvents: 4,
        previousEvents: 1,
        baselineDaily: 0.08,
        surgeRatio: 4,
        recentSensitive: 4,
        recentControlled: 3,
        maxRiskScore: 92,
        maxSeverity: 4,
        latestAt: '2026-06-28T12:00:00.000Z',
        detail: 'Do not export 524-71-9043 in this detail',
        action: 'Review user activity',
        targetTab: 'activity',
        source: 'behavior_baseline',
      }],
      playbook: [{
        id: 'behavior:user:redacted',
        priority: 1,
        severity: 'warning',
        label: 'Review user surge',
        detail: 'Do not export 524-71-9043 in this playbook',
        action: 'Review user activity',
        targetTab: 'activity',
        score: 58,
      }],
    },
    decisionQuality: {
      generatedAt: '2026-06-28T12:00:00.000Z',
      summary: {
        events: 8,
        sensitiveEvents: 4,
        pendingReviews: 1,
        escalatedReviews: 1,
        approved: 1,
        denied: 1,
        coachingEvents: 2,
        coachingCompleted: 1,
        overrideWatch: 1,
        riskyAllows: 1,
        controlRate: 100,
        slaHealthyRate: 50,
        privacy: 'metadata only; prompt bodies excluded',
      },
      cards: [{
        id: 'approval_sla',
        label: 'Approval SLA',
        score: 50,
        state: 'blocked',
        status: 'critical',
        value: '1/2',
        detail: 'Do not export 524-71-9043 in this detail',
        action: 'Open queue',
        targetTab: 'queue',
      }],
      hotspots: [{
        id: 'destination:chatgpt-com',
        kind: 'destination',
        label: 'chatgpt.com',
        events: 4,
        sensitive: 3,
        blocked: 1,
        redacted: 1,
        allowed: 1,
        coached: 1,
        pending: 1,
        escalated: 1,
        maxRiskScore: 92,
        lastSeen: '2026-06-28T12:00:00.000Z',
        state: 'attention',
        detail: '3 sensitive / 2 review signals',
      }],
    },
    actionQueue: [{
      id: 'mission:soc',
      priority: 1,
      severity: 'warning',
      category: 'Current mission',
      label: 'Configure SIEM posture webhook',
      detail: 'SOC Posture Feed: Configure SIEM_WEBHOOK_URL',
      owner: 'security operations',
      source: 'siem',
      action: 'Run step',
      targetTab: 'audit',
      command: 'Set SIEM_WEBHOOK_URL=https://... and SIEM_WEBHOOK_TOKEN=<token>',
      workflowStatus: 'assigned',
      workflowOwner: 'security_admin',
      workflowActor: 'admin',
      workflowNote: 'dashboard_linkage',
      workflowUpdatedAt: '2026-06-28T12:05:00.000Z',
      workflowProofState: 'assigned',
    }],
    hardening: {
      generatedAt: '2026-06-28T12:00:00.000Z',
      score: 70,
      state: 'attention',
      proofLedger: { verified: 3, attention: 1, missing: 2, total: 6, percent: 50 },
      mission: {
        state: 'attention',
        progress: { done: 1, total: 3, open: 2, percent: 33 },
        proofLedger: { verified: 3, attention: 1, missing: 2, total: 6, percent: 50 },
        current: {
          areaLabel: 'SOC Posture Feed',
          label: 'Configure SIEM posture webhook',
          command: 'Set SIEM_WEBHOOK_URL=https://... and SIEM_WEBHOOK_TOKEN=<token>',
        },
      },
      areas: [{
        id: 'soc_posture_feed',
        label: 'SOC Posture Feed',
        description: 'Security operations posture without prompt bodies',
        score: 70,
        state: 'attention',
        status: 'warning',
        evidence: ['Sanitized posture snapshot feed is available'],
        gaps: ['Configure SIEM_WEBHOOK_URL for SOC posture snapshots'],
        action: 'Open audit',
        targetTab: 'audit',
        owner: 'security operations',
        source: 'siem',
        location: 'SIEM/SOAR webhook',
        proofLedger: { verified: 1, attention: 0, missing: 1, total: 2, percent: 50 },
        proofs: [{
          id: 'soc_siem_webhook',
          label: 'SIEM/SOAR posture webhook configured',
          status: 'missing',
          detail: 'Configure SIEM_WEBHOOK_URL',
          evidenceAt: null,
          source: 'siem',
          action: 'Configure SIEM webhook',
          targetTab: 'audit',
        }],
        playbook: [{
          id: 'soc_siem_webhook',
          label: 'Configure SIEM posture webhook',
          status: 'next',
          detail: 'Send only sanitized posture metadata.',
          command: 'Set SIEM_WEBHOOK_URL=https://... and SIEM_WEBHOOK_TOKEN=<token>',
          validation: 'AI Command Center > Send SOC snapshot returns SENT.',
          targetTab: 'audit',
        }],
      }],
      nextActions: [{
        id: 'soc_posture_feed',
        label: 'SOC Posture Feed',
        action: 'Configure SIEM posture webhook',
        detail: 'Configure SIEM_WEBHOOK_URL',
        targetTab: 'audit',
        priority: 1,
      }],
    },
  });

  assert.strictEqual(posture.summary.missing, null);
  assert.deepStrictEqual(posture.metrics[0].value, [{ nested: 'ok', secret: 'value that should be bounded' }]);
  assert.deepStrictEqual(posture.metrics[0].trend, { direction: 'up', secret: 'hidden-ish metadata' });
  assert.strictEqual(posture.hardening.areas[0].id, 'soc_posture_feed');
  assert.strictEqual(posture.hardening.areas[0].proofs[0].status, 'missing');
  assert.strictEqual(posture.hardening.areas[0].proofLedger.missing, 1);
  assert.strictEqual(posture.hardening.areas[0].playbook[0].status, 'next');
  assert.match(posture.hardening.areas[0].playbook[0].command, /SIEM_WEBHOOK_URL/);
  assert.strictEqual(posture.hardening.proofLedger.missing, 2);
  assert.strictEqual(posture.hardening.mission.proofLedger.percent, 50);
  assert.strictEqual(posture.aiInventory.summary.shadow, 1);
  assert.strictEqual(posture.aiInventory.tools[0].state, 'local_unapproved');
  assert.strictEqual(posture.threatGuardrails.summary.promptInjection, 1);
  assert.strictEqual(posture.threatGuardrails.rules[0].framework, 'OWASP LLM01');
  assert.strictEqual(posture.threatGuardrails.controls[0].state, 'ready');
  assert.strictEqual(posture.threatGuardrails.controls[0].detail, '[redacted]');
  assert.deepStrictEqual(posture.threatGuardrails.recent[0].threats, ['Prompt injection']);
  assert.strictEqual(posture.competitiveReadiness.summary.score, 78);
  assert.strictEqual(posture.competitiveReadiness.matrix[0].id, 'soc_compliance_handoff');
  assert.strictEqual(posture.competitiveReadiness.matrix[0].gaps[0], '[redacted]');
  assert.strictEqual(posture.competitiveReadiness.nextGaps[0].label, 'SOC And Examiner Handoff');
  assert.strictEqual(posture.behaviorBaselines.summary.anomalies, 1);
  assert.strictEqual(posture.behaviorBaselines.privacy, 'metadata only; prompt bodies excluded');
  assert.strictEqual(posture.behaviorBaselines.dimensions[0].label, '[redacted]');
  assert.strictEqual(posture.behaviorBaselines.dimensions[0].detail, '[redacted]');
  assert.strictEqual(posture.behaviorBaselines.playbook[0].detail, '[redacted]');
  assert.strictEqual(posture.decisionQuality.summary.pendingReviews, 1);
  assert.strictEqual(posture.decisionQuality.cards[0].id, 'approval_sla');
  assert.strictEqual(posture.decisionQuality.cards[0].detail, '[redacted]');
  assert.strictEqual(posture.decisionQuality.hotspots[0].label, 'chatgpt.com');
  assert.strictEqual(posture.actionQueue[0].category, 'Current mission');
  assert.match(posture.actionQueue[0].command, /SIEM_WEBHOOK_URL/);
  assert.strictEqual(posture.actionQueue[0].workflowStatus, 'assigned');
  assert.strictEqual(posture.actionQueue[0].workflowOwner, 'security_admin');
  assert.strictEqual(posture.hardening.mission.current.label, 'Configure SIEM posture webhook');
  assert.strictEqual(posture.hardening.mission.progress.open, 2);
  assert.strictEqual(posture.hardening.nextActions[0].detail, 'Configure SIEM_WEBHOOK_URL');
  assert.ok(!JSON.stringify(posture).includes('524-71-9043'));
});

test('evidence exports browser action policy diffs without raw values', () => {
  const entry = evidence.safeAuditEntry({
    id: 'a_action_policy',
    ts: '2026-06-26T12:00:00.000Z',
    action: 'POLICY_UPDATED',
    actor: 'admin',
    detail: JSON.stringify({
      type: 'policy_change',
      changed: [{
        field: 'blockedBrowserActions',
        before: [],
        after: [{ id: 'block_paste_chatgpt', action: 'paste', destinations: ['chatgpt.com'], reason: 'clipboard_paste_blocked' }],
      }],
    }),
    prevHash: '0'.repeat(64),
    hash: '1'.repeat(64),
  });

  assert.deepStrictEqual(entry.policyChange.changed[0].field, 'blockedBrowserActions');
  assert.ok(entry.detailHash);
});

test('server exposes protected evidence export route', () => {
  const fs = require('fs');
  const path = require('path');
  const server = fs.readFileSync(path.join(__dirname, '..', 'server/app.js'), 'utf8');
  assert.match(server, /app\.get\('\/api\/export\/evidence', \.\.\.auditRead/);
  assert.match(server, /evidence\.buildEvidencePack/);
  assert.match(server, /summaryQueries = db\.listQueries\(\{ all: true \}\)/);
  assert.match(server, /coverage\.summarize\(summaryQueries, activePolicy\)/);
  assert.match(server, /lineageQueries: summaryQueries/);
});

test('evidence exports safe destination review reasons and unapproved AI policy changes', () => {
  const entry = evidence.safeAuditEntry({
    id: 'a_destination',
    ts: '2026-06-26T12:00:00.000Z',
    action: 'DESTINATION_REVIEWED',
    actor: 'admin',
    detail: JSON.stringify({
      type: 'policy_change',
      reason: 'Approved pilot for vendor comparison',
      changed: [{ field: 'blockUnapprovedAiDestinations', before: true, after: false }],
    }),
    prevHash: '0'.repeat(64),
    hash: '1'.repeat(64),
  });

  assert.strictEqual(entry.policyChange.reason, 'Approved pilot for vendor comparison');
  assert.deepStrictEqual(entry.policyChange.changed, [
    { field: 'blockUnapprovedAiDestinations', before: true, after: false },
  ]);
  assert.ok(entry.detailHash);
});
