'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const coverage = require('../src/coverage');

const serverSource = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

const policy = {
  governedDestinations: ['chatgpt.com', 'claude.ai', 'copilot.microsoft.com'],
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
      redactedPrompt: 'tokenized',
    },
    {
      id: 'q3',
      createdAt: '2026-06-26T12:00:00.000Z',
      status: 'shadow_ai',
      user: 'ops@example.test',
      destination: 'notebooklm.google.com',
      source: 'browser_extension',
      redactedPrompt: '[shadow-AI] visit',
    },
  ];

  const report = coverage.summarize(rows, policy);
  assert.strictEqual(report.totals.events, 3);
  assert.strictEqual(report.totals.governedDestinations, 3);
  assert.strictEqual(report.totals.governedActive, 2);
  assert.strictEqual(report.totals.shadowEvents, 1);
  assert.strictEqual(report.governedDestinations.find((d) => d.destination === 'chatgpt.com').blocked, 1);
  assert.strictEqual(report.governedDestinations.find((d) => d.destination === 'claude.ai').redacted, 1);
  assert.strictEqual(report.shadowDestinations[0].destination, 'notebooklm.google.com');
  assert.strictEqual(report.sensors.find((s) => s.source === 'endpoint_agent').events, 0);
  assert.ok(report.score > 0 && report.score < 100);
  assert.ok(!JSON.stringify(report).includes('Member [US_SSN]'));
  assert.ok(!JSON.stringify(report).includes('524-71-9043'));
});

test('destination normalization removes schemes, paths, and www prefixes', () => {
  assert.strictEqual(coverage.normalizeDestination('https://www.chatgpt.com/g/g-test'), 'chatgpt.com');
  assert.strictEqual(coverage.normalizeDestination('claude.ai/chat'), 'claude.ai');
  assert.strictEqual(coverage.normalizeDestination(''), 'unknown');
});

test('coverage route stays session protected', () => {
  assert.match(serverSource, /app\.get\('\/api\/coverage', auth\.requireAuth/);
});
