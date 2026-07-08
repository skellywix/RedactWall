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

  assert.deepStrictEqual(report.panels.edm, { configured: false, enabled: false, active: false, fingerprints: 0, minLength: 0, severity: 0 });
  const control = report.controls.find((c) => c.id === 'member_information_safeguards');
  assert.strictEqual(control.state, 'attention');
  assert.match(control.summary, /EDM fingerprints are not configured/);
});

test('a loaded-but-disabled EDM watchlist is never reported active', () => {
  const report = ncuaReadiness.summarize(baseInput({ edm: { enabled: false, fingerprints: 120 } }));

  assert.strictEqual(report.panels.edm.configured, true);
  assert.strictEqual(report.panels.edm.active, false);
  const control = report.controls.find((c) => c.id === 'member_information_safeguards');
  assert.strictEqual(control.state, 'attention');
});

test('ncua readiness drops decoy free text and secrets at the input boundary', () => {
  const report = ncuaReadiness.summarize(baseInput({
    edm: { enabled: true, fingerprints: 9, salt: 'edm-salt-decoy-should-not-appear', fingerprintList: ['deadbeefdecoy'] },
    catalog: [
      { sanctionedStatus: 'unsanctioned', eventCount: 2, notes: 'catalog-notes-decoy', owner: 'owner-decoy@example.test' },
    ],
    queries: [
      { status: 'pending', findings: [{ type: 'MEMBER_ID', value: '99887766-decoy', masked: '**** 7766' }] },
    ],
  }));

  const wire = JSON.stringify(report);
  assert.ok(!wire.includes('edm-salt-decoy-should-not-appear'));
  assert.ok(!wire.includes('deadbeefdecoy'));
  assert.ok(!wire.includes('catalog-notes-decoy'));
  assert.ok(!wire.includes('owner-decoy'));
  assert.ok(!wire.includes('99887766-decoy'));
});

test('scoring internals: empty control set scores 0 and the ready boundary sits at 90', () => {
  const { scoreControls, stateFor } = ncuaReadiness._internal;
  assert.strictEqual(scoreControls([]), 0);
  assert.strictEqual(scoreControls([{ state: 'not_provided' }]), 0);
  assert.strictEqual(scoreControls([{ state: 'covered' }, { state: 'covered' }, { state: 'not_provided' }]), 100);
  assert.strictEqual(stateFor(90, true), 'ready');
  assert.strictEqual(stateFor(89, true), 'attention');
  assert.strictEqual(stateFor(100, false), 'blocked');
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

test('controls without evidence inputs stay not_provided with honest summaries', () => {
  const mappings = controlMap.buildControlMappings({ generatedAt: '2026-07-07T12:00:00.000Z', policy: FCU_POLICY });
  for (const id of ['ai_use_inventory', 'vendor_service_provider_oversight', 'incident_readiness', 'board_reporting']) {
    const control = mappings.find((c) => c.id === id);
    assert.strictEqual(control.state, 'not_provided');
    assert.match(control.summary, /not yet attached/);
  }
});

test('use-case summary rolls up counts, overdue reviews, and vendor status', () => {
  const rows = [
    { reviewStatus: 'approved', vendorStatus: 'reviewed', nextReviewAt: '2027-01-01T00:00:00Z' },
    { reviewStatus: 'under_review', vendorStatus: 'pending', nextReviewAt: '2026-01-01T00:00:00Z' },
    { reviewStatus: 'restricted' },
    { reviewStatus: 'retired', vendorStatus: 'not_reviewed' },
  ];
  const summary = ncuaReadiness.useCasesSummary(rows, '2026-07-07T12:00:00.000Z');

  assert.deepStrictEqual(summary, {
    total: 4,
    approved: 1,
    underReview: 1,
    restricted: 1,
    retired: 1,
    overdue: 1,
    activeTotal: 3,
    vendorReviewed: 1,
    vendorPending: 1,
    vendorNotReviewed: 1,
  });
  assert.strictEqual(ncuaReadiness.useCasesSummary(undefined, '2026-07-07T12:00:00.000Z'), null);
});

test('use-case controls go live from the summary and never leak free text', () => {
  const currentSummary = ncuaReadiness.useCasesSummary(
    [{ reviewStatus: 'approved', vendorStatus: 'reviewed', owner: 'owner-decoy', approvedUse: 'use-decoy' }],
    '2026-07-07T12:00:00.000Z',
  );
  const report = ncuaReadiness.summarize(baseInput({ useCases: currentSummary }));

  const inventory = report.controls.find((c) => c.id === 'ai_use_inventory');
  const vendor = report.controls.find((c) => c.id === 'vendor_service_provider_oversight');
  assert.strictEqual(inventory.state, 'covered');
  assert.strictEqual(vendor.state, 'covered');
  assert.strictEqual(report.panels.useCases.total, 1);
  const wire = JSON.stringify(report);
  assert.ok(!wire.includes('owner-decoy'));
  assert.ok(!wire.includes('use-decoy'));

  const overdueSummary = ncuaReadiness.useCasesSummary(
    [{ reviewStatus: 'approved', vendorStatus: 'not_reviewed', nextReviewAt: '2026-01-01T00:00:00Z' }],
    '2026-07-07T12:00:00.000Z',
  );
  const stale = ncuaReadiness.summarize(baseInput({ useCases: overdueSummary }));
  assert.strictEqual(stale.controls.find((c) => c.id === 'ai_use_inventory').state, 'attention');
  assert.strictEqual(stale.controls.find((c) => c.id === 'vendor_service_provider_oversight').state, 'attention');
});
