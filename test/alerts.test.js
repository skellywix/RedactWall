'use strict';
/** Sanitized SIEM/webhook alerting. node --test */
const test = require('node:test');
const assert = require('node:assert');
const alerts = require('../server/alerts');

function sampleQuery(overrides = {}) {
  return {
    id: 'q_test',
    createdAt: '2026-06-26T12:00:00.000Z',
    status: 'pending',
    mode: 'block',
    user: 'jdoe',
    orgId: 'cu-demo',
    source: 'browser_extension',
    channel: 'submit',
    sensor: {
      name: 'browser_extension',
      version: '0.3.0',
      platform: 'chrome_mv3',
      secret: 'ps_ingest_should_not_leave',
    },
    destination: 'chatgpt.com',
    redactedPrompt: 'Member John, SSN [US_SSN]',
    _rawPrompt: 'sealed-secret',
    _tokenVault: 'sealed-vault',
    riskScore: 74,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    findings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '**** 9043', value: '524-71-9043' }],
    categories: [],
    reasons: ['Hard-stop entity present: US_SSN'],
    assignedRole: 'approver',
    assignedGroup: 'compliance',
    workflowReason: 'detector:US_SSN',
    slaDueAt: '2026-06-26T16:00:00.000Z',
    escalatedAt: null,
    notificationStatus: 'not_configured',
    ...overrides,
  };
}

function samplePostureReport(overrides = {}) {
  return {
    generatedAt: '2026-07-04T12:00:00.000Z',
    windowDays: 7,
    summary: {
      events: 12,
      sensitiveEvents: 4,
      blocked: 3,
      redacted: 1,
      pending: 2,
      controlRate: 92,
      shadowEvents: 7,
      unresolvedShadowDestinations: 1,
      activeRequiredSensors: 3,
      requiredSensors: 4,
    },
    hardening: {
      score: 81,
      state: 'attention',
      summary: { ready: 2, attention: 1, blocked: 0, total: 3 },
      mission: {
        state: 'attention',
        progress: { percent: 70, open: 2 },
        current: { areaLabel: 'SOC Posture Feed', label: 'Configure SIEM posture webhook' },
        proofLedger: { verified: 5, attention: 1, missing: 1, total: 7, percent: 71 },
      },
      areas: [{
        id: 'soc_posture_feed',
        label: 'SOC Posture Feed',
        score: 67,
        state: 'attention',
        status: 'warning',
        owner: 'security',
        source: 'soc',
        evidence: ['Sanitized posture snapshot feed is available'],
        gaps: ['Configure SIEM_WEBHOOK_URL for SOC posture snapshots', 'Do not send Member SSN 524-71-9043'],
        playbook: [{ status: 'next', label: 'Enable SIEM posture feed' }],
        proofLedger: { verified: 1, attention: 1, missing: 0, total: 2 },
      }],
    },
    aiInventory: {
      summary: {
        sanctioned: 3,
        unsanctioned: 1,
        shadow: 1,
        localTools: 2,
        unapprovedLocalTools: 1,
        activeDestinations: 5,
        totalEvents: 19,
        highRiskAssets: 2,
      },
    },
    threatGuardrails: {
      summary: {
        events: 4,
        detections: 5,
        activeRules: 3,
        promptInjection: 1,
        sensitiveDisclosure: 2,
        unsafeOutput: 1,
        agentActions: 1,
        shadowAi: 1,
        unscannedContent: 0,
      },
    },
    actionQueue: [{
      severity: 'high',
      category: 'soc',
      workflowStatus: 'open',
      workflowProofState: 'proof_pending',
      detail: 'Member John SSN 524-71-9043 must not leave',
    }],
    ...overrides,
  };
}

test('sanitized alert omits raw, redacted prompt body, vault, and finding values', () => {
  const payload = alerts.sanitizedAlert(sampleQuery(), { action: 'BLOCKED' });
  const wire = JSON.stringify(payload);
  assert.strictEqual(payload.eventType, 'redactwall.security_event');
  assert.strictEqual(payload.action, 'BLOCKED');
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('sealed-secret'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('Member John'));
  assert.ok(!wire.includes('ps_ingest_should_not_leave'));
  assert.deepStrictEqual(payload.sensor, { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' });
  assert.strictEqual(payload.findings[0].masked, '**** 9043');
  assert.deepStrictEqual(payload.workflow, {
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
});

test('alert threshold sends blocked status even below numeric threshold', () => {
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'pending', riskScore: 0, maxSeverity: 0 })), true);
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'response_flagged', riskScore: 0, maxSeverity: 0 })), true);
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'response_redacted', riskScore: 0, maxSeverity: 0 })), true);
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'response_blocked', riskScore: 0, maxSeverity: 0 })), true);
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'action_blocked', riskScore: 0, maxSeverity: 0 })), true);
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'allowed', riskScore: 0, maxSeverity: 0 })), false);
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'allowed', riskScore: 30, maxSeverity: 1 })), true);
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'allowed', riskScore: 0, maxSeverity: 0 }), { force: true }), true);
});

test('admin step-up alert metadata stays sanitized', () => {
  const payload = alerts.sanitizedAlert(sampleQuery({ status: 'approved', riskScore: 0, maxSeverity: 0 }), {
    action: 'APPROVE_FAILED',
    adminEvent: true,
    adminActor: 'admin',
    stepUpScope: 'APPROVE',
    force: true,
  });
  const wire = JSON.stringify(payload);
  assert.strictEqual(payload.adminEvent, true);
  assert.strictEqual(payload.adminActor, 'admin');
  assert.strictEqual(payload.stepUpScope, 'APPROVE');
  assert.strictEqual(payload.action, 'APPROVE_FAILED');
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('sealed-secret'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('Member John'));
});

test('sensor version gap alert metadata stays sanitized', () => {
  const payload = alerts.sanitizedAlert(sampleQuery(), {
    action: 'SENSOR_VERSION_GAP',
    force: true,
    sensorVersionGap: {
      source: 'browser_extension',
      label: 'Browser extension',
      versionHealth: 'mixed',
      latestVersion: '0.3.0',
      versions: [
        { version: '0.3.0', events: 2, lastSeen: '2026-06-26T12:00:00.000Z', secret: 'ps_ingest_should_not_leave' },
        { version: '0.2.9', events: 1, lastSeen: '2026-06-26T11:00:00.000Z' },
      ],
      platforms: ['chrome_mv3'],
      secret: 'ps_ingest_should_not_leave',
    },
  });
  const wire = JSON.stringify(payload);
  assert.strictEqual(payload.action, 'SENSOR_VERSION_GAP');
  assert.strictEqual(payload.sensorVersionGap.versionHealth, 'mixed');
  assert.deepStrictEqual(payload.sensorVersionGap.versions.map((v) => v.version), ['0.3.0', '0.2.9']);
  assert.ok(!wire.includes('ps_ingest_should_not_leave'));
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member John'));
});

test('webhook emit is disabled without url and swallows network failures', async () => {
  const disabled = await alerts.emitSecurityAlert(sampleQuery(), { url: '' });
  assert.deepStrictEqual(disabled, { sent: false, reason: 'disabled' });

  let called = false;
  const cleartext = await alerts.emitSecurityAlert(sampleQuery(), {
    url: 'http://siem.example.test/hook',
    fetch: async () => {
      called = true;
      return { ok: true, status: 202 };
    },
  });
  assert.deepStrictEqual(cleartext, { sent: false, reason: 'invalid_url' });
  assert.strictEqual(called, false);

  const credentialed = await alerts.emitSecurityAlert(sampleQuery(), {
    url: 'https://user:secret@siem.example.test/hook',
    fetch: async () => {
      called = true;
      return { ok: true, status: 202 };
    },
  });
  assert.deepStrictEqual(credentialed, { sent: false, reason: 'invalid_url' });
  assert.strictEqual(called, false);

  const failed = await alerts.emitSecurityAlert(sampleQuery(), {
    url: 'https://siem.example.test/hook',
    fetch: async () => { throw new Error('offline'); },
  });
  assert.deepStrictEqual(failed, { sent: false, reason: 'error' });

  let cancelled = false;
  const rejected = await alerts.emitSecurityAlert(sampleQuery(), {
    url: 'https://siem.example.test/hook',
    fetch: async (_url, options) => {
      assert.strictEqual(options.redirect, 'error');
      return { ok: false, status: 503, body: { cancel: async () => { cancelled = true; } } };
    },
  });
  assert.deepStrictEqual(rejected, { sent: false, reason: 'http_503' });
  assert.strictEqual(cancelled, true);
});

test('webhook emit sends authorization and sanitized json', async () => {
  let request;
  let cancelled = false;
  const sent = await alerts.emitSecurityAlert(sampleQuery(), {
    url: 'https://siem.example.test/hook#secret-fragment',
    token: 'unit-token',
    fetch: async (url, opts) => {
      request = { url, opts };
      return { ok: true, status: 202, body: { cancel: async () => { cancelled = true; } } };
    },
  });

  assert.deepStrictEqual(sent, { sent: true, status: 202 });
  assert.strictEqual(request.url, 'https://siem.example.test/hook');
  assert.strictEqual(request.opts.redirect, 'error');
  assert.strictEqual(request.opts.headers.Authorization, 'Bearer unit-token');
  assert.strictEqual(cancelled, true);
  assert.ok(!request.opts.body.includes('524-71-9043'));
  assert.match(request.opts.body, /US_SSN/);
});

test('posture snapshot payload and fingerprint stay sanitized and stable', () => {
  const payload = alerts.sanitizedPostureAlert(samplePostureReport(), {
    action: 'POSTURE_FEED',
    automatic: true,
    trigger: 'BLOCKED',
  });
  const wire = JSON.stringify(payload);
  assert.strictEqual(payload.eventType, 'redactwall.posture_snapshot');
  assert.strictEqual(payload.action, 'POSTURE_FEED');
  assert.strictEqual(payload.automatic, true);
  assert.strictEqual(payload.trigger, 'BLOCKED');
  assert.strictEqual(payload.hardening.areas[0].gapCount, 2);
  assert.strictEqual(payload.threatGuardrails.promptInjection, 1);
  assert.strictEqual(payload.threatGuardrails.unsafeOutput, 1);
  assert.strictEqual(payload.threatGuardrails.agentActions, 1);
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member John'));

  const first = alerts.postureFingerprint(samplePostureReport());
  const same = alerts.postureFingerprint(samplePostureReport({ generatedAt: '2026-07-04T12:05:00.000Z' }));
  const changed = alerts.postureFingerprint(samplePostureReport({ hardening: { ...samplePostureReport().hardening, score: 55 } }));
  assert.strictEqual(first, same);
  assert.notStrictEqual(first, changed);
});

test('automatic posture feed dedupes, rate limits, and sends sanitized snapshots', async () => {
  assert.strictEqual(alerts.postureFeedEnabled({ SIEM_POSTURE_FEED_ENABLED: 'true', SIEM_WEBHOOK_URL: 'http://siem.example.test/hook' }), false);
  assert.strictEqual(alerts.postureFeedEnabled({ SIEM_POSTURE_FEED_ENABLED: 'true', SIEM_WEBHOOK_URL: 'https://siem.example.test/hook' }), true);
  assert.deepStrictEqual(alerts.postureFeedConfig({ SIEM_POSTURE_FEED_ENABLED: 'true', SIEM_POSTURE_MIN_INTERVAL_MS: '15000' }), {
    enabled: true,
    minIntervalMs: 15000,
  });

  const state = {};
  let request;
  const sent = await alerts.emitPostureFeed(samplePostureReport(), {
    env: { SIEM_POSTURE_FEED_ENABLED: 'true' },
    url: 'https://siem.example.test/hook#fragment',
    token: 'unit-token',
    state,
    nowMs: 100000,
    trigger: 'BLOCKED',
    fetch: async (url, opts) => {
      request = { url, opts };
      return { ok: true, status: 202 };
    },
  });
  assert.strictEqual(sent.sent, true);
  assert.strictEqual(sent.attempted, true);
  assert.strictEqual(request.url, 'https://siem.example.test/hook');
  assert.strictEqual(request.opts.redirect, 'error');
  assert.strictEqual(request.opts.headers.Authorization, 'Bearer unit-token');
  const body = JSON.parse(request.opts.body);
  assert.strictEqual(body.action, 'POSTURE_FEED');
  assert.strictEqual(body.automatic, true);
  assert.strictEqual(body.trigger, 'BLOCKED');
  assert.ok(!request.opts.body.includes('524-71-9043'));

  const unchanged = await alerts.emitPostureFeed(samplePostureReport({ generatedAt: '2026-07-04T12:10:00.000Z' }), {
    env: { SIEM_POSTURE_FEED_ENABLED: 'true' },
    url: 'https://siem.example.test/hook',
    state,
    nowMs: 500000,
    fetch: async () => assert.fail('unchanged posture should not send'),
  });
  assert.strictEqual(unchanged.reason, 'unchanged');
  assert.strictEqual(unchanged.attempted, false);

  const rateLimited = await alerts.emitPostureFeed(samplePostureReport({ hardening: { ...samplePostureReport().hardening, score: 60 } }), {
    env: { SIEM_POSTURE_FEED_ENABLED: 'true', SIEM_POSTURE_MIN_INTERVAL_MS: '300000' },
    url: 'https://siem.example.test/hook',
    state,
    nowMs: 101000,
    fetch: async () => assert.fail('rate limited posture should not send'),
  });
  assert.strictEqual(rateLimited.reason, 'rate_limited');
  assert.strictEqual(rateLimited.attempted, false);

  const disabled = await alerts.emitPostureFeed(samplePostureReport(), {
    env: {},
    url: 'https://siem.example.test/hook',
    state: {},
    fetch: async () => assert.fail('disabled posture feed should not send'),
  });
  assert.strictEqual(disabled.reason, 'disabled');
});
