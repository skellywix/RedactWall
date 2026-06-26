'use strict';
/** Examiner evidence export must not leak prompt bodies or audit details. */
const test = require('node:test');
const assert = require('node:assert');
const evidence = require('../src/evidence');

test('evidence pack omits raw prompt, redacted prompt body, token vault, and audit detail text', () => {
  const pack = evidence.buildEvidencePack({
    version: '0.3.0',
    generatedAt: '2026-06-26T12:00:00.000Z',
    queryLimit: 1,
    auditLimit: 1,
    policy: { enforcementMode: 'block' },
    stats: { total: 1 },
    auditIntegrity: { ok: true, count: 1 },
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
      redactedPrompt: 'Member John Carter has SSN [US_SSN]',
      _rawPrompt: 'Member John Carter has SSN 524-71-9043',
      _tokenVault: 'sealed-vault',
      decisionNote: 'contains member SSN 524-71-9043',
      retentionPurgedAt: '2026-06-27T12:00:00.000Z',
      retentionPurgedFields: ['rawPrompt'],
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
  assert.strictEqual(pack.queries[0].retentionPurgedAt, '2026-06-27T12:00:00.000Z');
  assert.deepStrictEqual(pack.queries[0].retentionPurgedFields, ['rawPrompt']);
  assert.ok(!wire.includes('524-71-9043'));
  assert.ok(!wire.includes('Member John Carter'));
  assert.ok(!wire.includes('sealed-vault'));
  assert.ok(!wire.includes('contains member SSN'));
  assert.ok(wire.includes('**** 9043'));
});

test('server exposes protected evidence export route', () => {
  const fs = require('fs');
  const path = require('path');
  const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(server, /app\.get\('\/api\/export\/evidence', auth\.requireAuth/);
  assert.match(server, /evidence\.buildEvidencePack/);
});
