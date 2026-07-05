'use strict';
/** Customer detector packs must be bounded, policy-addressable, and sensor-safe. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const customDetectorPath = path.join(os.tmpdir(), 'redactwall-custom-detectors-' + crypto.randomBytes(6).toString('hex') + '.json');
process.env.REDACTWALL_CUSTOM_DETECTORS_PATH = customDetectorPath;
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'redactwall-custom-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.writeFileSync(customDetectorPath, JSON.stringify({
  detectors: [
    {
      id: 'CU_MEMBER_NUMBER',
      label: 'Credit union member number',
      severity: 3,
      score: 0.86,
      pattern: '\\bCU-[0-9]{7}\\b',
      validators: { minDigits: 7, maxDigits: 7, requireDigit: true },
    },
    {
      id: 'US_SSN',
      label: 'Attempted built-in override',
      pattern: '\\bOVERRIDE-[0-9]+\\b',
    },
    {
      id: 'BAD_BACKTRACK',
      label: 'Unsafe regex',
      pattern: '(a+)+$',
    },
  ],
}, null, 2));

const D = require('../detection-engine/detect');
const customDetectors = require('../server/custom-detectors');
const policy = require('../server/policy');
const validation = require('../server/validation');

test('custom detector packs reject built-in overrides and unsafe regexes', () => {
  const loaded = customDetectors.loadCustomDetectors();

  assert.strictEqual(customDetectors.CONFIG_PATH, customDetectorPath);
  assert.deepStrictEqual(loaded.map((item) => item.id), ['CU_MEMBER_NUMBER']);
  assert.strictEqual(loaded[0].severity, 3);
  assert.strictEqual(loaded[0].custom, true);
  assert.ok(!JSON.stringify(loaded).includes('BAD_BACKTRACK'));
  assert.ok(!JSON.stringify(loaded).includes('OVERRIDE'));
});

test('custom detectors participate in analysis and disabled-detector policy', () => {
  const cfg = customDetectors.loadCustomDetectors();
  const hit = D.analyze('Member record CU-1234567 needs loan-servicing review.', { customDetectors: cfg });
  const disabled = D.analyze('Member record CU-1234567 needs loan-servicing review.', {
    customDetectors: cfg,
    disabledDetectors: ['CU_MEMBER_NUMBER'],
  });

  assert.ok(hit.findings.some((item) => item.type === 'CU_MEMBER_NUMBER'));
  assert.strictEqual(hit.entityCounts.CU_MEMBER_NUMBER, 1);
  assert.strictEqual(disabled.findings.some((item) => item.type === 'CU_MEMBER_NUMBER'), false);
});

test('custom detector IDs are listed and accepted by policy validation', () => {
  const ids = new Set(D.listDetectors({ customDetectors: customDetectors.loadCustomDetectors() }).map((item) => item.id));
  const opts = policy.analyzeOpts();

  assert.ok(ids.has('CU_MEMBER_NUMBER'));
  assert.ok(opts.customDetectors.some((item) => item.id === 'CU_MEMBER_NUMBER'));
  assert.strictEqual(validation.policyUpdateSchema.safeParse({
    alwaysBlock: ['CU_MEMBER_NUMBER'],
    approvalRoutingRules: [{
      id: 'cu-member-risk',
      detectors: ['CU_MEMBER_NUMBER'],
      assignedGroup: 'credit_union',
      assignedRole: 'security_admin',
      slaMinutes: 60,
    }],
  }).success, true);
  assert.strictEqual(validation.policyUpdateSchema.safeParse({ alwaysBlock: ['BAD_BACKTRACK'] }).success, false);
  assert.strictEqual(validation.gateSchema.safeParse({
    prompt: '[file inspected locally] member record',
    clientPreRedacted: true,
    clientFindings: [{ type: 'CU_MEMBER_NUMBER', severity: 3, score: 0.86, masked: '**** 4567' }],
    clientRiskScore: 21,
    clientMaxSeverity: 3,
    clientMaxSeverityLabel: 'high',
    clientOutcome: 'redacted_available',
  }).success, true);
});

test('custom detector loader accepts array configs and falls back on invalid JSON', () => {
  fs.writeFileSync(customDetectorPath, JSON.stringify([{
    id: 'BRANCH_MEMBER_ID',
    label: 'Branch member id',
    severity: 3,
    pattern: '\\bBR-[0-9]{6}\\b',
  }]));
  assert.deepStrictEqual(customDetectors.loadRaw().detectors.map((item) => item.id), ['BRANCH_MEMBER_ID']);
  assert.deepStrictEqual(customDetectors.listDetectorIds(), ['BRANCH_MEMBER_ID']);

  fs.writeFileSync(customDetectorPath, '{not json');
  assert.deepStrictEqual(customDetectors.loadRaw(), { detectors: [] });
  assert.deepStrictEqual(customDetectors.loadCustomDetectors(), []);
});

test.after(() => {
  for (const file of [customDetectorPath, process.env.REDACTWALL_POLICY_PATH]) {
    try { fs.unlinkSync(file); } catch {}
  }
});
