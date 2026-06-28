'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const coverage = require('../server/coverage');

const serverSource = fs.readFileSync(path.join(__dirname, '..', 'server/app.js'), 'utf8');

const policy = {
  governedDestinations: ['chatgpt.com', 'claude.ai', 'copilot.microsoft.com'],
  requiredSensors: ['browser_extension', 'endpoint_agent', 'mcp_guard', 'proxy'],
  desiredSensorVersions: {
    browser_extension: '0.3.0',
    endpoint_agent: '0.3.0',
    mcp_guard: '0.3.0',
    proxy: '1.0.0',
  },
};

test('coverage summary aggregates governed apps, sensors, and shadow AI without prompt bodies', () => {
  const rows = [
    {
      id: 'q1',
      createdAt: '2026-06-26T10:00:00.000Z',
      status: 'pending',
      user: 'analyst@example.test',
      destination: 'https://chatgpt.com/c/abc',
      source: 'browser_extension',
      sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
      redactedPrompt: 'Member [US_SSN]',
      _rawPrompt: 'Member SSN 524-71-9043',
      decisionNote: 'contains synthetic member SSN 524-71-9043',
    },
    {
      id: 'q2',
      createdAt: '2026-06-26T11:00:00.000Z',
      status: 'redacted',
      user: 'analyst@example.test',
      destination: 'claude.ai',
      source: 'mcp_guard',
      sensor: { name: 'mcp_guard', version: '0.3.0', platform: 'node' },
      redactedPrompt: 'tokenized',
    },
    {
      id: 'q3',
      createdAt: '2026-06-26T12:00:00.000Z',
      status: 'destination_blocked',
      user: 'ops@example.test',
      destination: 'notebooklm.google.com',
      source: 'browser_extension',
      channel: 'shadow_ai',
      sensor: { name: 'browser_extension', version: '0.2.9', platform: 'chrome_mv3' },
      redactedPrompt: '[unapproved AI blocked] notebooklm.google.com',
    },
    {
      id: 'q4',
      createdAt: '2026-06-26T09:30:00.000Z',
      status: 'destination_blocked',
      user: 'analyst@example.test',
      destination: 'copilot.microsoft.com',
      source: 'browser_extension',
      sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
      redactedPrompt: '[destination blocked] copilot.microsoft.com',
    },
    {
      id: 'q5',
      createdAt: '2026-06-26T13:30:00.000Z',
      status: 'file_upload_blocked',
      user: 'ops@example.test',
      destination: 'claude.ai',
      source: 'endpoint_agent',
      channel: 'file_upload',
      sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
      redactedPrompt: '[file upload blocked] claude.ai',
      decisionNote: 'endpoint_agent/file_upload; native handoff evt_desktop_1',
    },
    {
      id: 'q6',
      createdAt: '2026-06-26T14:00:00.000Z',
      status: 'sensor_heartbeat',
      user: 'tech@example.test',
      destination: 'endpoint-install',
      source: 'endpoint_agent',
      channel: 'sensor_health',
      sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
      redactedPrompt: '[sensor heartbeat] endpoint_agent',
      installChecks: [
        { id: 'endpoint_env_file', ok: true, detail: 'found' },
        { id: 'handoff_secret', ok: false, detail: 'missing handoff secret' },
      ],
    },
  ];

  const report = coverage.summarize(rows, policy);
  assert.strictEqual(report.totals.events, 6);
  assert.strictEqual(report.totals.governedDestinations, 3);
  assert.strictEqual(report.totals.governedActive, 3);
  assert.strictEqual(report.totals.shadowEvents, 1);
  assert.strictEqual(report.totals.unresolvedShadowDestinations, 1);
  assert.strictEqual(report.totals.requiredSensors, 4);
  assert.strictEqual(report.totals.activeRequiredSensors, 3);
  assert.strictEqual(report.totals.activeSensorVersionGaps, 1);
  assert.strictEqual(report.totals.activeSensorHealthWarnings, 1);
  assert.strictEqual(report.governedDestinations.find((d) => d.destination === 'chatgpt.com').blocked, 1);
  assert.strictEqual(report.governedDestinations.find((d) => d.destination === 'copilot.microsoft.com').blocked, 1);
  assert.strictEqual(report.governedDestinations.find((d) => d.destination === 'claude.ai').redacted, 1);
  assert.strictEqual(report.governedDestinations.find((d) => d.destination === 'claude.ai').blocked, 1);
  assert.strictEqual(report.shadowDestinations[0].destination, 'notebooklm.google.com');
  assert.strictEqual(report.shadowDestinations[0].blocked, 1);
  assert.strictEqual(report.shadowDestinations[0].policyState, 'review');
  const browser = report.sensors.find((s) => s.source === 'browser_extension');
  assert.strictEqual(browser.required, true);
  assert.strictEqual(browser.versionHealth, 'outdated');
  assert.strictEqual(browser.latestVersion, '0.2.9');
  assert.strictEqual(browser.desiredVersion, '0.3.0');
  assert.deepStrictEqual(browser.versions.map((v) => v.version), ['0.2.9', '0.3.0']);
  assert.deepStrictEqual(browser.platforms, ['chrome_mv3']);
  const endpoint = report.sensors.find((s) => s.source === 'endpoint_agent');
  assert.strictEqual(endpoint.events, 2);
  assert.strictEqual(endpoint.versionHealth, 'current');
  assert.strictEqual(endpoint.installHealth.state, 'attention');
  assert.deepStrictEqual(endpoint.installHealth.failedChecks, ['handoff_secret']);
  assert.strictEqual(report.sensors.find((s) => s.source === 'proxy').versionHealth, 'missing');
  assert.deepStrictEqual(report.desktopCollector, {
    events: 1,
    lastSeen: '2026-06-26T13:30:00.000Z',
    destinations: ['claude.ai'],
  });
  assert.ok(report.posture.some((p) => p.id === 'desktop_collector' && p.state === 'covered'));
  assert.ok(report.posture.some((p) => p.id === 'endpoint_agent' && p.state === 'attention' && /failed checks/.test(p.detail)));
  assert.ok(report.posture.some((p) => p.id === 'proxy' && p.state === 'attention' && /required/.test(p.detail)));
  assert.ok(report.posture.some((p) => p.id === 'sensor_versions' && p.state === 'attention'));
  assert.ok(report.posture.some((p) => p.id === 'sensor_health' && p.state === 'attention'));
  assert.ok(report.score > 0 && report.score < 100);
  assert.ok(!JSON.stringify(report).includes('Member [US_SSN]'));
  assert.ok(!JSON.stringify(report).includes('524-71-9043'));
});

test('coverage marks desktop collector attention when no native handoff evidence exists', () => {
  const report = coverage.summarize([], policy);
  assert.deepStrictEqual(report.desktopCollector, { events: 0, lastSeen: null, destinations: [] });
  assert.ok(report.posture.some((p) => p.id === 'desktop_collector' && p.state === 'attention'));
});

test('coverage marks reviewed shadow AI as governed by policy state', () => {
  const rows = [{
    id: 'q1',
    createdAt: '2026-06-26T10:00:00.000Z',
    status: 'shadow_ai',
    user: 'analyst@example.test',
    destination: 'poe.com',
    source: 'browser_extension',
    sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
  }];

  const report = coverage.summarize(rows, { allowedDestinations: ['poe.com'] });
  assert.strictEqual(report.totals.unresolvedShadowDestinations, 0);
  assert.strictEqual(report.shadowDestinations[0].destination, 'poe.com');
  assert.strictEqual(report.shadowDestinations[0].policyState, 'allowed');
  assert.strictEqual(report.shadowDestinations[0].governed, true);
  assert.ok(report.posture.some((p) => p.id === 'shadow_ai' && p.state === 'covered'));
});

test('destination normalization removes schemes, paths, and www prefixes', () => {
  assert.strictEqual(coverage.normalizeDestination('https://www.chatgpt.com/g/g-test'), 'chatgpt.com');
  assert.strictEqual(coverage.normalizeDestination('claude.ai/chat'), 'claude.ai');
  assert.strictEqual(coverage.normalizeDestination(''), 'unknown');
});

test('coverage route stays session protected', () => {
  assert.match(serverSource, /app\.get\('\/api\/coverage', auth\.requireAuth/);
});
