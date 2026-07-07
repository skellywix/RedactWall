'use strict';

const test = require('node:test');
const assert = require('node:assert');
const ncuaReadiness = require('../server/ncua-readiness');
const controlMap = require('../server/control-map');

const FCU_POLICY = {
  alwaysBlock: ['US_SSN', 'MEMBER_ID', 'LOAN_NUMBER', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'SECRET_KEY'],
  governedDestinations: ['chat.openai.com'],
  blockUnapprovedAiDestinations: true,
};

function baseInput(overrides = {}) {
  return {
    generatedAt: '2026-07-07T12:00:00.000Z',
    scope: { rawPromptBodiesIncluded: false },
    policy: FCU_POLICY,
    detectors: [{ id: 'MEMBER_ID' }, { id: 'PROMPT_ATTACK' }],
    auditIntegrity: { ok: true, count: 12 },
    coverage: { totals: { requiredSensors: 2, activeRequiredSensors: 2 } },
    policyExceptionReview: { total: 2, active: 1, expiringSoon: 1, reviewDue: 0, expired: 1, disabled: 0, reviewWindowDays: 14 },
    edm: { enabled: true, fingerprints: 120, minLength: 6, severity: 4 },
    catalog: [
      { sanctionedStatus: 'sanctioned', eventCount: 40 },
      { sanctionedStatus: 'unsanctioned', eventCount: 7 },
      { sanctionedStatus: 'under_review', eventCount: 3 },
    ],
    queries: [
      { status: 'pending', findings: [{ type: 'MEMBER_ID' }] },
      { status: 'denied', findings: [{ type: 'US_SSN' }, { type: 'EMAIL' }] },
      { status: 'redacted', findings: [{ type: 'EXACT_MATCH' }] },
      { status: 'approved', findings: [{ type: 'LOAN_NUMBER' }] },
      { status: 'sent', findings: [{ type: 'EMAIL' }] },
    ],
    ...overrides,
  };
}

test('ncua readiness summarizes member-data outcomes without prompt content', () => {
  const report = ncuaReadiness.summarize(baseInput());

  assert.strictEqual(report.profile, 'federal_credit_union');
  assert.strictEqual(report.generatedAt, '2026-07-07T12:00:00.000Z');
  assert.deepStrictEqual(report.panels.memberData, {
    identifiers: controlMap.MEMBER_IDENTIFIERS,
    events: 4,
    prevented: 2,
    redacted: 1,
    released: 1,
  });
  assert.strictEqual(report.panels.audit.verified, true);
  const serialized = JSON.stringify(report);
  assert.ok(!serialized.includes('salt'));
  assert.ok(!serialized.includes('fingerprintList'));
});

test('ncua readiness scores provided controls only and reports next actions', () => {
  const report = ncuaReadiness.summarize(baseInput());
  const provided = report.controls.filter((c) => c.state !== 'not_provided');
  const covered = provided.filter((c) => c.state === 'covered').length;

  assert.strictEqual(report.score, Math.round((covered / provided.length) * 100));
  assert.ok(report.controls.some((c) => c.id === 'member_information_safeguards' && c.state === 'covered'));
  assert.ok(report.controls.some((c) => c.id === 'ai_use_inventory' && c.state === 'not_provided'));
  for (const action of report.nextActions) {
    assert.strictEqual(typeof action.label, 'string');
    assert.ok(action.priority >= 1);
  }
});

test('ncua readiness reports blocked when the audit chain fails verification', () => {
  const report = ncuaReadiness.summarize(baseInput({ auditIntegrity: { ok: false, count: 12, reason: 'chain' } }));
  assert.strictEqual(report.state, 'blocked');
  assert.strictEqual(report.panels.audit.verified, false);
});

test('ncua readiness surfaces EDM setup state when unconfigured', () => {
  const report = ncuaReadiness.summarize(baseInput({ edm: { enabled: false, fingerprints: 0 } }));

  assert.deepStrictEqual(report.panels.edm, { configured: false, enabled: false, fingerprints: 0, minLength: 0, severity: 0 });
  const control = report.controls.find((c) => c.id === 'member_information_safeguards');
  assert.strictEqual(control.state, 'attention');
  assert.match(control.summary, /EDM fingerprints are not configured/);
});

test('ncua readiness shadow-AI rollup counts catalog statuses and unreviewed events', () => {
  const report = ncuaReadiness.summarize(baseInput());
  assert.deepStrictEqual(report.panels.shadowAi, {
    totalApps: 3,
    sanctioned: 1,
    underReview: 1,
    tolerated: 0,
    unsanctioned: 1,
    blocked: 0,
    unreviewedEvents: 10,
  });
});

test('ncua readiness tolerates missing optional inputs', () => {
  const report = ncuaReadiness.summarize({ policy: FCU_POLICY, auditIntegrity: { ok: true, count: 0 } });

  assert.strictEqual(report.panels.exceptions, null);
  assert.deepStrictEqual(report.panels.exportHealth, { scheduled: false });
  assert.strictEqual(report.panels.memberData.events, 0);
  assert.strictEqual(report.panels.shadowAi.totalApps, 0);
});

test('control map flags incomplete member-identifier hard stops', () => {
  const mappings = controlMap.buildControlMappings({
    generatedAt: '2026-07-07T12:00:00.000Z',
    policy: { alwaysBlock: ['US_SSN'] },
    edm: { enabled: true, fingerprints: 10 },
  });
  const control = mappings.find((c) => c.id === 'member_information_safeguards');

  assert.strictEqual(control.state, 'attention');
  assert.match(control.summary, /MEMBER_ID/);
});

test('control map keeps slice-2/3 controls not_provided with honest summaries', () => {
  const mappings = controlMap.buildControlMappings({ generatedAt: '2026-07-07T12:00:00.000Z', policy: FCU_POLICY });
  for (const id of ['ai_use_inventory', 'vendor_service_provider_oversight', 'incident_readiness', 'board_reporting']) {
    const control = mappings.find((c) => c.id === id);
    assert.strictEqual(control.state, 'not_provided');
    assert.match(control.summary, /not yet attached/);
  }
});
