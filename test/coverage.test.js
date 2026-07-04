'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const coverage = require('../server/coverage');

const serverSource = fs.readFileSync(path.join(__dirname, '..', 'server/app.js'), 'utf8');
const dashboardHtml = fs.readFileSync(path.join(__dirname, '..', 'server/public/index.html'), 'utf8');
const dashboardJs = fs.readFileSync(path.join(__dirname, '..', 'server/public/dashboard.js'), 'utf8');
const coverageFileFlowJs = fs.readFileSync(path.join(__dirname, '..', 'server/public/coverage-file-flow.js'), 'utf8');

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
      id: 'q7',
      createdAt: '2026-06-26T11:30:00.000Z',
      status: 'sensor_heartbeat',
      user: 'analyst@example.test',
      destination: 'browser-install',
      source: 'browser_extension',
      channel: 'sensor_health',
      sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
      redactedPrompt: '[sensor heartbeat] browser_extension',
      installChecks: [
        { id: 'managed_config', ok: true, detail: 'configured' },
        { id: 'managed_identity', ok: true, detail: 'present' },
      ],
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
        { id: 'ai_tool_inventory', ok: true, detail: 'detected:2' },
        { id: 'ai_tool_cursor', ok: true, detail: 'detected' },
        { id: 'ai_tool_claude_desktop', ok: false, detail: 'unapproved detected' },
        { id: 'endpoint_file_flow_profiles', ok: true, detail: 'configured:2' },
        { id: 'endpoint_file_flow_profile_lending', ok: true, detail: 'configured directory' },
        { id: 'endpoint_file_flow_profile_call_center', ok: false, detail: 'missing directory' },
        { id: 'handoff_secret', ok: false, detail: 'missing handoff secret' },
      ],
    },
  ];

  const report = coverage.summarize(rows, policy);
  assert.strictEqual(report.totals.events, 7);
  assert.strictEqual(report.totals.governedDestinations, 3);
  assert.strictEqual(report.totals.governedActive, 3);
  assert.strictEqual(report.totals.shadowEvents, 1);
  assert.strictEqual(report.totals.unresolvedShadowDestinations, 1);
  assert.strictEqual(report.totals.requiredSensors, 4);
  assert.strictEqual(report.totals.activeRequiredSensors, 3);
  assert.strictEqual(report.totals.activeSensorVersionGaps, 1);
  assert.strictEqual(report.totals.activeSensorHealthWarnings, 1);
  assert.strictEqual(report.totals.fleetRows, 12);
  assert.strictEqual(report.totals.fleetCovered, 1);
  assert.strictEqual(report.totals.fleetAttention, 11);
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
  assert.deepStrictEqual(endpoint.installHealth.failedChecks, ['endpoint_file_flow_profile_call_center', 'handoff_secret']);
  assert.deepStrictEqual(endpoint.installHealth.aiToolInventory, {
    detected: 2,
    reported: 2,
    unapproved: 1,
    truncated: false,
    state: 'attention',
    tools: [
      { id: 'claude_desktop', label: 'Claude Desktop', approved: false, state: 'unapproved', detail: 'unapproved detected' },
      { id: 'cursor', label: 'Cursor', approved: true, state: 'approved', detail: 'detected' },
    ],
  });
  assert.deepStrictEqual(endpoint.installHealth.fileFlowProfiles, {
    configured: 2,
    reported: 2,
    attention: 1,
    state: 'attention',
    profiles: [
      { id: 'call_center', state: 'attention', detail: 'missing directory' },
      { id: 'lending', state: 'covered', detail: 'configured directory' },
    ],
  });
  assert.strictEqual(report.sensors.find((s) => s.source === 'proxy').versionHealth, 'missing');
  assert.deepStrictEqual(report.desktopCollector, {
    events: 1,
    lastSeen: '2026-06-26T13:30:00.000Z',
    destinations: ['claude.ai'],
  });
  assert.ok(report.posture.some((p) => p.id === 'desktop_collector' && p.state === 'covered'));
  assert.ok(report.posture.some((p) => p.id === 'endpoint_agent' && p.state === 'attention' && /failed checks/.test(p.detail)));
  assert.ok(report.posture.some((p) => p.id === 'endpoint_ai_tools' && p.state === 'attention' && /1 unapproved/.test(p.detail)));
  assert.ok(report.posture.some((p) => p.id === 'endpoint_file_flow_profiles' && p.state === 'attention' && /2 configured \/ 1 missing/.test(p.detail)));
  assert.ok(report.posture.some((p) => p.id === 'proxy' && p.state === 'attention' && /required/.test(p.detail)));
  assert.ok(report.posture.some((p) => p.id === 'sensor_versions' && p.state === 'attention'));
  assert.ok(report.posture.some((p) => p.id === 'sensor_health' && p.state === 'attention'));
  const analystBrowser = report.fleet.find((item) => item.user === 'analyst@example.test' && item.source === 'browser_extension');
  assert.strictEqual(analystBrowser.state, 'covered');
  assert.strictEqual(analystBrowser.installHealth.state, 'covered');
  assert.deepStrictEqual(analystBrowser.installHealth.failedChecks, []);
  const opsBrowser = report.fleet.find((item) => item.user === 'ops@example.test' && item.source === 'browser_extension');
  assert.strictEqual(opsBrowser.state, 'outdated');
  assert.strictEqual(opsBrowser.latestVersion, '0.2.9');
  const techEndpoint = report.fleet.find((item) => item.user === 'tech@example.test' && item.source === 'endpoint_agent');
  assert.strictEqual(techEndpoint.state, 'attention');
  assert.deepStrictEqual(techEndpoint.installHealth.failedChecks, ['endpoint_file_flow_profile_call_center', 'handoff_secret']);
  assert.strictEqual(report.totals.endpointAiInventoryReports, 1);
  assert.strictEqual(report.totals.endpointAiToolDetections, 2);
  assert.strictEqual(report.totals.endpointAiToolUnapproved, 1);
  assert.strictEqual(report.totals.endpointFileFlowReports, 1);
  assert.strictEqual(report.totals.endpointFileFlowProfiles, 2);
  assert.strictEqual(report.totals.endpointFileFlowAttention, 1);
  assert.deepStrictEqual(report.endpointAiTools.map((tool) => [tool.id, tool.user, tool.approved]), [
    ['claude_desktop', 'tech@example.test', false],
    ['cursor', 'tech@example.test', true],
  ]);
  assert.deepStrictEqual(report.endpointFileFlowProfiles.map((profile) => [profile.id, profile.user, profile.state, profile.detail]), [
    ['call_center', 'tech@example.test', 'attention', 'missing directory'],
    ['lending', 'tech@example.test', 'covered', 'configured directory'],
  ]);
  assert.ok(report.fleet.some((item) => item.user === 'analyst@example.test' && item.source === 'proxy' && item.state === 'missing'));
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

test('coverage reports discovery feed freshness without prompt bodies', () => {
  const now = new Date().toISOString();
  const report = coverage.summarize([
    {
      id: 'q_fresh_discovery',
      createdAt: now,
      lastSeen: now,
      status: 'shadow_ai',
      mode: 'discovery',
      user: 'discovery-import',
      destination: 'perplexity.ai',
      source: 'proxy',
      channel: 'shadow_ai',
      discoverySource: 'zscaler',
      discoveryEvents: 7,
      discoveryCategory: 'chatbot',
      redactedPrompt: '[AI discovery import] perplexity.ai',
    },
    {
      id: 'q_stale_discovery',
      createdAt: '2026-01-01T00:00:00.000Z',
      lastSeen: '2026-01-01T00:00:00.000Z',
      status: 'shadow_ai',
      mode: 'discovery',
      user: 'discovery-import',
      destination: 'old-ai.example',
      source: 'proxy',
      channel: 'shadow_ai',
      discoverySource: 'netskope',
      discoveryEvents: 3,
      discoveryCategory: 'chatbot',
      redactedPrompt: '[AI discovery import] old-ai.example',
    },
    {
      id: 'q_missing_timestamp_discovery',
      status: 'shadow_ai',
      mode: 'discovery',
      user: 'discovery-import',
      destination: 'unknown-ai.example',
      source: 'proxy',
      channel: 'shadow_ai',
      discoverySource: 'cloudflare',
      discoveryEvents: 2,
      discoveryCategory: 'chatbot',
      redactedPrompt: '[AI discovery import] unknown-ai.example',
    },
  ], { requiredSensors: ['proxy'] });

  assert.strictEqual(report.totals.discoveryFeeds, 3);
  assert.strictEqual(report.totals.freshDiscoveryFeeds, 1);
  assert.strictEqual(report.totals.staleDiscoveryFeeds, 2);
  assert.strictEqual(report.totals.lastDiscoveryAt, now);
  assert.deepStrictEqual(report.discoveryFeeds.map((feed) => [feed.source, feed.state, feed.observations]), [
    ['netskope', 'stale', 3],
    ['cloudflare', 'missing', 2],
    ['zscaler', 'fresh', 7],
  ]);
  assert.ok(report.posture.some((p) => p.id === 'discovery_freshness' && p.state === 'attention' && /1\/3 fresh feeds/.test(p.detail)));
  assert.ok(!JSON.stringify(report.discoveryFeeds).includes('[AI discovery import]'));
});

test('fleet posture reports required sensors instead of API source rows', () => {
  const report = coverage.summarize([{
    id: 'q1',
    createdAt: '2026-06-26T10:00:00.000Z',
    status: 'allowed',
    user: 'analyst@example.test',
    destination: 'chatgpt.com',
    source: 'api',
    redactedPrompt: 'benign',
  }], {
    governedDestinations: ['chatgpt.com'],
    requiredSensors: ['browser_extension'],
    desiredSensorVersions: { browser_extension: '0.3.0' },
  });

  assert.strictEqual(report.totals.fleetRows, 1);
  assert.strictEqual(report.fleet[0].source, 'browser_extension');
  assert.strictEqual(report.fleet[0].state, 'missing');
  assert.ok(!report.fleet.some((item) => item.source === 'api'));
});

test('destination normalization removes schemes, paths, and www prefixes', () => {
  assert.strictEqual(coverage.normalizeDestination('https://www.chatgpt.com/g/g-test'), 'chatgpt.com');
  assert.strictEqual(coverage.normalizeDestination('claude.ai/chat'), 'claude.ai');
  assert.strictEqual(coverage.normalizeDestination('www.bad host/path?x=1'), 'bad host');
  assert.strictEqual(coverage.normalizeDestination(''), 'unknown');
});

test('coverage policy matching supports wildcard destination patterns', () => {
  const report = coverage.summarize([
    {
      id: 'q_allowed_wildcard',
      createdAt: '2026-06-26T12:00:00.000Z',
      status: 'shadow_ai',
      user: 'analyst@example.test',
      destination: 'sub.example.com',
      source: 'browser_extension',
    },
    {
      id: 'q_blocked_wildcard',
      createdAt: '2026-06-26T12:01:00.000Z',
      status: 'shadow_ai',
      user: 'analyst@example.test',
      destination: 'team.example.org',
      source: 'browser_extension',
    },
  ], {
    allowedDestinations: ['*.example.com'],
    blockedDestinations: ['*example.org'],
  });

  const byDestination = Object.fromEntries(report.shadowDestinations.map((item) => [item.destination, item]));
  assert.strictEqual(byDestination['sub.example.com'].policyState, 'allowed');
  assert.strictEqual(byDestination['team.example.org'].policyState, 'blocked');
  assert.strictEqual(report.totals.unresolvedShadowDestinations, 0);
});

test('coverage counts response scan block and redaction outcomes', () => {
  const report = coverage.summarize([
    {
      id: 'q_response_redacted',
      createdAt: '2026-06-26T12:00:00.000Z',
      status: 'response_redacted',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'mcp_guard',
      channel: 'ai_response',
      redactedPrompt: '[AI response] [REDACTED: CONFIDENTIAL_BUSINESS]',
    },
    {
      id: 'q_response_blocked',
      createdAt: '2026-06-26T12:01:00.000Z',
      status: 'response_blocked',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'mcp_guard',
      channel: 'ai_response',
      redactedPrompt: '[AI response] SSN **** 9043',
    },
  ], policy);

  const chatgpt = report.governedDestinations.find((d) => d.destination === 'chatgpt.com');
  assert.strictEqual(chatgpt.redacted, 1);
  assert.strictEqual(chatgpt.blocked, 1);
});

test('coverage counts browser action blocks as policy stops', () => {
  const report = coverage.summarize([{
    id: 'q_action_blocked',
    createdAt: '2026-06-26T12:00:00.000Z',
    status: 'action_blocked',
    user: 'analyst@example.test',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'paste',
    redactedPrompt: '[browser action blocked] paste chatgpt.com',
  }], policy);

  const chatgpt = report.governedDestinations.find((d) => d.destination === 'chatgpt.com');
  assert.strictEqual(report.totals.blocked, 1);
  assert.strictEqual(chatgpt.blocked, 1);
});

test('coverage route stays session protected', () => {
  assert.match(serverSource, /app\.get\('\/api\/coverage', auth\.requireAuth/);
});

test('lineage route and dashboard render sanitized lineage view', () => {
  assert.match(serverSource, /app\.get\('\/api\/lineage', auth\.requireAuth/);
  assert.match(serverSource, /lineage: evidence\.buildLineage\(queries\)/);
  assert.match(dashboardHtml, /data-tab="lineage"/);
  assert.match(dashboardHtml, /id="lineageSummary"/);
  assert.match(dashboardHtml, /id="lineageUsers"/);
  assert.match(dashboardHtml, /id="lineageDestinations"/);
  assert.match(dashboardHtml, /id="lineageSensors"/);
  assert.match(dashboardHtml, /id="lineageChannels"/);
  assert.match(dashboardHtml, /id="lineageCategories"/);
  assert.match(dashboardHtml, /id="lineageDecisions"/);
  assert.match(dashboardJs, /async function loadLineage\(\)/);
  assert.match(dashboardJs, /api\('\/api\/lineage\?limit=1000'\)/);
  assert.match(dashboardJs, /function renderLineageRows/);
  assert.match(dashboardJs, /function lineageTotals/);
});

test('coverage dashboard renders fleet install health posture', () => {
  assert.match(dashboardHtml, /Fleet Install Health/);
  assert.match(dashboardHtml, /id="fleetRows"/);
  assert.match(dashboardHtml, /Endpoint AI Tools/);
  assert.match(dashboardHtml, /id="endpointAiToolRows"/);
  assert.match(dashboardHtml, /Endpoint File Flow/);
  assert.match(dashboardHtml, /id="endpointFileFlowRows"/);
  assert.match(dashboardJs, /totals\.fleetAttention/);
  assert.match(dashboardJs, /totals\.freshDiscoveryFeeds/);
  assert.match(dashboardJs, /Feeds fresh/);
  assert.match(dashboardJs, /endpointAiTools/);
  assert.match(coverageFileFlowJs, /endpointFileFlowProfiles/);
  assert.match(coverageFileFlowJs, /Local path: not reported/);
  assert.match(dashboardJs, /function endpointAiToolTone/);
  assert.match(dashboardJs, /function fleetTone/);
  assert.match(dashboardJs, /no install-health heartbeat/);
});
