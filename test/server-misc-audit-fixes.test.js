'use strict';

// Regression coverage for the server-misc audit fixes:
//   - env quoted-value/inline-comment and escaped-backslash parsing
//   - OpenAPI response drift (heartbeat companions, discovery destinations)
//   - insights prototype-pollution hardening
//   - posture governed-shadow inventory state and metadata redaction
//   - control-readiness evidence-timestamp honesty
//   - coverage posture id uniqueness

const test = require('node:test');
const assert = require('node:assert');

const env = require('../server/env');
const openapi = require('../server/openapi');
const insights = require('../server/insights');
const posture = require('../server/posture');
const controlReadiness = require('../server/control-readiness');
const coverage = require('../server/coverage');

test('env: a quoted value followed by an inline comment keeps neither quotes nor comment', () => {
  const { parsed } = env.parseEnv('REDACTWALL_SECRET="s3cret-value" # session key\n');
  assert.strictEqual(parsed.REDACTWALL_SECRET, 's3cret-value');
});

test('env: an escaped backslash before n is not corrupted into a newline', () => {
  const { parsed } = env.parseEnv('ADMIN_PASSWORD="pa\\\\ss\\\\north"\n');
  assert.strictEqual(parsed.ADMIN_PASSWORD, 'pa\\ss\\north');
});

test('openapi: heartbeat companions is an object map and discovery destinations are objects', () => {
  const doc = openapi.document();
  const companions = doc.components.schemas.HeartbeatResponse.properties.companions;
  assert.strictEqual(companions.type, 'object');
  assert.deepStrictEqual(companions.additionalProperties.enum, ['active', 'stale', 'missing']);
  const destItems = doc.components.schemas.DiscoveryResponse.properties.destinations.items;
  assert.strictEqual(destItems.type, 'object');
  assert.ok(destItems.properties.id && destItems.properties.destination);
});

test('insights: a user named __proto__ does not pollute Object.prototype', () => {
  const rows = [
    { status: 'blocked', createdAt: '2026-07-02T10:00:00.000Z', user: '__proto__', riskScore: 50, maxSeverity: 4, findings: [], categories: [], destination: 'chatgpt.com' },
    { status: 'allowed', createdAt: '2026-07-02T11:00:00.000Z', user: 'constructor', accountType: 'personal', riskScore: 10, findings: [], categories: [], destination: 'chatgpt.com' },
  ];
  insights.summarize(rows, { now: '2026-07-03T00:00:00.000Z', windowDays: 30 });
  assert.strictEqual({}.events, undefined, 'Object.prototype.events must not be set');
  assert.strictEqual({}.riskSum, undefined, 'Object.prototype.riskSum must not be set');
});

test('posture: a reviewed-and-governed shadow destination lands sanctioned, not shadow', () => {
  const coverageReport = {
    totals: {},
    governedDestinations: [],
    ungovernedDestinations: [],
    shadowDestinations: [
      { destination: 'reviewed-ai.example', governed: true, events: 6, blocked: 0, redacted: 0, shadow: 6, users: 2, lastSeen: '2026-07-02T10:00:00.000Z' },
    ],
  };
  const inventory = posture.aiInventory({ coverageReport });
  const app = inventory.apps.find((a) => a.name === 'reviewed-ai.example');
  assert.ok(app, 'expected the reviewed destination in the inventory');
  assert.strictEqual(app.state, 'sanctioned');
});

test('posture: space-grouped PANs in metadata labels are redacted in behavior baselines', () => {
  const nowMs = Date.parse('2026-07-03T00:00:00.000Z');
  const rows = [
    { id: 'a', status: 'blocked', createdAt: '2026-07-02T23:00:00.000Z', user: '4111 1111 1111 1111', destination: 'chatgpt.com', source: 'browser_extension', riskScore: 80, maxSeverity: 4, findings: [{ type: 'PAN', severity: 4 }], categories: ['PII'] },
    { id: 'b', status: 'blocked', createdAt: '2026-07-02T23:30:00.000Z', user: '4111 1111 1111 1111', destination: 'chatgpt.com', source: 'browser_extension', riskScore: 80, maxSeverity: 4, findings: [{ type: 'PAN', severity: 4 }], categories: ['PII'] },
  ];
  const baselines = posture.behaviorBaselines({ rows, nowMs });
  const raw = JSON.stringify(baselines);
  assert.ok(!raw.includes('4111 1111 1111 1111'), 'grouped PAN must not appear in baseline output');
  const userDim = baselines.dimensions.find((d) => d.kind === 'user');
  if (userDim) assert.strictEqual(userDim.label, 'redacted_label');
});

test('control-readiness: catalog rows without lastSeen do not fabricate evidence timestamps', () => {
  const coverageReport = {
    generatedAt: '2026-07-03T00:00:00.000Z',
    totals: { governedDestinations: 1 },
    governedDestinations: [{ destination: 'chatgpt.com', events: 0 }],
    shadowDestinations: [],
    ungovernedDestinations: [],
    sensors: [],
  };
  const readiness = controlReadiness.assetDiscoveryReadiness({ policy: {}, coverageReport });
  const proof = readiness.proofs.find((p) => p.id === 'asset_catalog_seeded');
  assert.strictEqual(proof.evidenceAt, null, 'no real lastSeen means evidenceAt must be null, not generatedAt');
});

test('coverage: posture rows have unique ids when mcp_guard is a required sensor', () => {
  const policy = { requiredSensors: ['browser_extension', 'endpoint_agent', 'mcp_guard'], governedDestinations: [] };
  const rows = [
    { id: 'm1', createdAt: '2026-07-02T10:00:00.000Z', status: 'allowed', user: 'a@x.test', destination: 'claude.ai', source: 'mcp_guard', sensor: { name: 'mcp_guard', version: '0.3.0' } },
  ];
  const report = coverage.summarize(rows, policy);
  const ids = report.posture.map((item) => item.id);
  assert.strictEqual(new Set(ids).size, ids.length, `duplicate posture ids: ${ids.join(', ')}`);
  assert.strictEqual(ids.filter((id) => id === 'mcp_guard').length, 1);
});
