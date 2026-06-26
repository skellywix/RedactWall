'use strict';
/** Sanitized SIEM/webhook alerting. node --test */
const test = require('node:test');
const assert = require('node:assert');
const alerts = require('../src/alerts');

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
    ...overrides,
  };
}

test('sanitized alert omits raw, redacted prompt body, vault, and finding values', () => {
  const payload = alerts.sanitizedAlert(sampleQuery(), { action: 'BLOCKED' });
  const wire = JSON.stringify(payload);
  assert.strictEqual(payload.eventType, 'promptsentinel.security_event');
  assert.strictEqual(payload.action, 'BLOCKED');
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('sealed-secret'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('Member John'));
  assert.ok(!wire.includes('ps_ingest_should_not_leave'));
  assert.deepStrictEqual(payload.sensor, { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' });
  assert.strictEqual(payload.findings[0].masked, '**** 9043');
});

test('alert threshold sends blocked status even below numeric threshold', () => {
  assert.strictEqual(alerts.shouldAlert(sampleQuery({ status: 'pending', riskScore: 0, maxSeverity: 0 })), true);
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

  const failed = await alerts.emitSecurityAlert(sampleQuery(), {
    url: 'https://siem.example.test/hook',
    fetch: async () => { throw new Error('offline'); },
  });
  assert.deepStrictEqual(failed, { sent: false, reason: 'error' });
});

test('webhook emit sends authorization and sanitized json', async () => {
  let request;
  const sent = await alerts.emitSecurityAlert(sampleQuery(), {
    url: 'https://siem.example.test/hook',
    token: 'unit-token',
    fetch: async (url, opts) => {
      request = { url, opts };
      return { ok: true, status: 202 };
    },
  });

  assert.deepStrictEqual(sent, { sent: true, status: 202 });
  assert.strictEqual(request.url, 'https://siem.example.test/hook');
  assert.strictEqual(request.opts.headers.Authorization, 'Bearer unit-token');
  assert.ok(!request.opts.body.includes('524-71-9043'));
  assert.match(request.opts.body, /US_SSN/);
});
