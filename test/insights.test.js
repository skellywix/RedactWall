'use strict';
/**
 * Insights aggregation (server/insights.js) — the dashboard's who/what/where
 * summaries. Pure-function tests over crafted rows: the payload must carry
 * counts, buckets, and masked labels only, never prompt bodies or finding
 * values.
 */
const test = require('node:test');
const assert = require('node:assert');
const insights = require('../server/insights');

const NOW = '2026-07-04T12:00:00.000Z';

function row(overrides = {}) {
  return {
    status: 'allowed',
    createdAt: NOW,
    user: 'user@example.test',
    destination: 'chat.openai.com',
    riskScore: 0,
    maxSeverity: 0,
    findings: [],
    categories: [],
    ...overrides,
  };
}

test('decisionOf maps every stored status onto a dashboard decision', () => {
  assert.strictEqual(insights.decisionOf('allowed'), 'allowed');
  assert.strictEqual(insights.decisionOf('warned_sent'), 'allowed', 'user proceeded, so it counts as allowed');
  assert.strictEqual(insights.decisionOf('pending'), 'blocked');
  assert.strictEqual(insights.decisionOf('injection_blocked'), 'blocked');
  assert.strictEqual(insights.decisionOf('paste_flagged'), 'flagged');
  assert.strictEqual(insights.decisionOf('shadow_ai'), 'shadow');
  assert.strictEqual(insights.decisionOf('made_up_status'), 'other');
});

test('summarize buckets decisions, risk bands, and confidence tiers', () => {
  const rows = [
    row({ status: 'allowed', riskScore: 0 }),
    row({ status: 'pending', riskScore: 80, maxSeverity: 4, findings: [{ type: 'US_SSN', confidence: 'very_likely' }] }),
    row({ status: 'redacted', riskScore: 30, findings: [{ type: 'US_SSN', confidence: 'very_likely' }, { type: 'EMAIL_ADDRESS', confidence: 'possible' }] }),
    row({ status: 'warned', riskScore: 10, categories: [{ category: 'CONFIDENTIAL_BUSINESS' }] }),
    row({ status: 'sensor_heartbeat' }),
  ];
  const s = insights.summarize(rows, { windowDays: 7, now: NOW });

  assert.strictEqual(s.totals.considered, 4, 'operational heartbeats are excluded');
  assert.strictEqual(s.totals.blocked, 1);
  assert.strictEqual(s.totals.redacted, 1);
  assert.strictEqual(s.totals.allowed, 1);
  assert.strictEqual(s.totals.avgRisk, Math.round((0 + 80 + 30 + 10) / 4));

  const bands = Object.fromEntries(s.riskBands.map((b) => [b.id, b.count]));
  assert.strictEqual(bands.none, 1);
  assert.strictEqual(bands.low, 1);
  assert.strictEqual(bands.medium, 1);
  assert.strictEqual(bands.critical, 1);

  assert.deepStrictEqual(s.confidence, { possible: 1, likely: 0, very_likely: 2 });
  assert.deepStrictEqual(s.topDetectors[0], { key: 'US_SSN', count: 2 });
  assert.deepStrictEqual(s.topCategories[0], { key: 'CONFIDENTIAL_BUSINESS', count: 1 });
});

test('summarize builds a dense day series and drops rows outside the window', () => {
  const rows = [
    row({ createdAt: NOW }),
    row({ createdAt: '2026-07-03T08:00:00.000Z', status: 'pending' }),
    row({ createdAt: '2025-01-01T00:00:00.000Z' }), // outside the window, still counted in totals
  ];
  const s = insights.summarize(rows, { windowDays: 3, now: NOW });

  assert.strictEqual(s.series.length, 3, 'one bucket per day in the window');
  assert.deepStrictEqual(s.series.map((d) => d.date), ['2026-07-02', '2026-07-03', '2026-07-04']);
  assert.strictEqual(s.series[2].allowed, 1);
  assert.strictEqual(s.series[1].blocked, 1);
  assert.strictEqual(s.series.reduce((a, d) => a + d.total, 0), 2, 'out-of-window row has no series bucket');
  assert.strictEqual(s.totals.considered, 3);
});

test('summarize clamps the window and tolerates junk input', () => {
  assert.strictEqual(insights.summarize([], { windowDays: 9999, now: NOW }).windowDays, 90);
  assert.strictEqual(insights.summarize([], { windowDays: -5, now: NOW }).windowDays, 1, 'negative windows clamp to the one-day floor');
  assert.strictEqual(insights.summarize([], { windowDays: 0, now: NOW }).windowDays, 30, 'unset window falls back to the default');
  const empty = insights.summarize(null, { now: NOW });
  assert.strictEqual(empty.totals.considered, 0);
  assert.strictEqual(empty.totals.avgRisk, 0);
});

test('summarize attributes shadow AI to providers and ranks users by weighted risk', () => {
  const rows = [
    row({ status: 'shadow_ai', destination: 'chat.openai.com', user: 'heavy@example.test', riskScore: 60 }),
    row({ status: 'shadow_ai', destination: 'chat.openai.com', user: 'heavy@example.test', riskScore: 60 }),
    row({ status: 'pending', destination: 'claude.ai', user: 'heavy@example.test', riskScore: 90, maxSeverity: 4 }),
    row({ status: 'allowed', destination: 'unknown', user: 'light@example.test', riskScore: 0 }),
  ];
  const s = insights.summarize(rows, { windowDays: 7, now: NOW });

  assert.ok(s.shadowByProvider.length >= 1, 'shadow usage rolls up by provider');
  assert.strictEqual(s.shadowByProvider.reduce((a, p) => a + p.count, 0), 2);
  assert.ok(!s.topDestinations.some((d) => d.destination === 'unknown'), 'unknown destinations are excluded');

  assert.strictEqual(s.topUsers[0].user, 'heavy@example.test');
  assert.strictEqual(s.topUsers[0].events, 3);
  assert.strictEqual(s.topUsers[0].blocked, 1);
  assert.strictEqual(s.topUsers[0].maxSeverity, 4);
});

test('summarize output carries no prompt bodies or raw finding values', () => {
  const rows = [row({
    status: 'pending',
    prompt: 'Member SSN is 412-22-7843',
    findings: [{ type: 'US_SSN', value: '412-22-7843', confidence: 'very_likely' }],
    riskScore: 80,
  })];
  const out = JSON.stringify(insights.summarize(rows, { now: NOW }));
  assert.ok(!out.includes('412-22-7843'), 'raw finding value must not appear');
  assert.ok(!out.includes('Member SSN'), 'prompt text must not appear');
});
