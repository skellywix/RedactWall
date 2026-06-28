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
    policy: { enforcementMode: 'block' },
    stats: { total: 1 },
    auditIntegrity: { ok: true, count: 1 },
    coverage: {
      score: 82,
      rawPrompt: 'coverage should not export Member John Carter',
      totals: { events: 1, blocked: 1, requiredSensors: 3, activeRequiredSensors: 1, activeSensorVersionGaps: 1, activeSensorHealthWarnings: 1 },
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
  assert.strictEqual(pack.scope.rawPromptBodiesIncluded, false);
  assert.strictEqual(pack.scope.auditDetailsIncluded, false);
  assert.ok(pack.queries[0].promptHash);
  assert.ok(pack.audit[0].detailHash);
  assert.strictEqual(pack.coverage.score, 82);
  assert.strictEqual(pack.coverage.totals.requiredSensors, 3);
  assert.strictEqual(pack.coverage.totals.activeSensorHealthWarnings, 1);
  assert.strictEqual(pack.coverage.sensors[0].required, true);
  assert.strictEqual(pack.coverage.sensors[0].desiredVersion, '0.3.0');
  assert.strictEqual(pack.coverage.sensors[0].installHealth.state, 'attention');
  assert.deepStrictEqual(pack.coverage.sensors[0].installHealth.failedChecks, ['managed_identity']);
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
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('contains member SSN'));
  assert.ok(!wire.includes('ps_ingest_should_not_export'));
  assert.deepStrictEqual(pack.queries[0].sensor, { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' });
  assert.deepStrictEqual(pack.queries[0].installChecks, [{ id: 'endpoint_env_file', ok: true, detail: 'found' }]);
  assert.ok(wire.includes('**** 9043'));
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
      categories: ['CONFIDENTIAL_BUSINESS'],
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
  assert.ok(!wire.includes('4111 1111 1111 1111'));
  assert.ok(!wire.includes('Card **** 1111'));
});

test('server exposes protected evidence export route', () => {
  const fs = require('fs');
  const path = require('path');
  const server = fs.readFileSync(path.join(__dirname, '..', 'server/app.js'), 'utf8');
  assert.match(server, /app\.get\('\/api\/export\/evidence', auth\.requireAuth/);
  assert.match(server, /evidence\.buildEvidencePack/);
  assert.match(server, /coverage\.summarize/);
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
