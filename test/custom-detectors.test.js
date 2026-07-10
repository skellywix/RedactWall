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
  ],
}, null, 2));

const D = require('../detection-engine/detect');
const customDetectors = require('../server/custom-detectors');
const policy = require('../server/policy');
const validation = require('../server/validation');

test('custom detector packs load a valid bounded detector', () => {
  const loaded = customDetectors.loadCustomDetectors();

  assert.strictEqual(customDetectors.CONFIG_PATH, customDetectorPath);
  assert.deepStrictEqual(loaded.map((item) => item.id), ['CU_MEMBER_NUMBER']);
  assert.strictEqual(loaded[0].severity, 3);
  assert.strictEqual(loaded[0].custom, true);
  assert.strictEqual(customDetectors.status().ok, true);
});

test('loader fails readiness and retains last-known-good on any rejected enabled entry', () => {
  const expected = ['CU_MEMBER_NUMBER'];
  const valid = {
    id: 'CU_MEMBER_NUMBER',
    label: 'Credit union member number',
    severity: 3,
    pattern: '\\bCU-[0-9]{7}\\b',
  };
  const rejectedPacks = [
    {
      detectors: [valid, { id: 'BAD_BACKTRACK', pattern: '(a+)+$' }],
    },
    {
      detectors: [valid, { ...valid, label: 'Duplicate ID' }],
    },
    {
      detectors: Array.from({ length: 101 }, (_, index) => ({
        id: `CUSTOM_MEMBER_${String(index).padStart(3, '0')}`,
        pattern: `\\bCM${index}-[0-9]{2}\\b`,
      })),
    },
  ];

  for (const pack of rejectedPacks) {
    fs.writeFileSync(customDetectorPath, JSON.stringify(pack));
    assert.deepStrictEqual(customDetectors.loadCustomDetectors().map((item) => item.id), expected);
    const state = customDetectors.status();
    assert.strictEqual(state.ok, false);
    assert.strictEqual(state.configured, true);
    assert.strictEqual(state.usingLastKnownGood, true);
    assert.match(state.error, /invalid|duplicate|limit|enabled detector/i);
  }
});

test('a successfully loaded default-path detector pack fails loud if it disappears', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-default-detectors-'));
  const detectorPath = path.join(dir, 'custom-detectors.json');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(detectorPath, JSON.stringify({
    detectors: [{ id: 'DEFAULT_MEMBER_ID', pattern: '\\bDM-[0-9]{6}\\b' }],
  }));

  const loader = customDetectors.createLoader(detectorPath, false);
  assert.strictEqual(loader.status().ok, true);
  assert.deepStrictEqual(loader.loadCustomDetectors().map((item) => item.id), ['DEFAULT_MEMBER_ID']);

  fs.unlinkSync(detectorPath);
  assert.deepStrictEqual(loader.loadCustomDetectors().map((item) => item.id), ['DEFAULT_MEMBER_ID']);
  assert.deepStrictEqual(loader.status(), {
    ok: false,
    configured: true,
    detectors: 1,
    error: 'detector pack disappeared after a successful load',
    usingLastKnownGood: true,
  });
});

test('an optional default-path detector pack treats inspection failures as unhealthy', () => {
  const deniedFs = {
    statSync() {
      const error = new Error('synthetic access denied');
      error.code = 'EACCES';
      throw error;
    },
  };
  const loader = customDetectors.createLoader('default-custom-detectors.json', false, deniedFs);

  assert.deepStrictEqual(loader.status(), {
    ok: false,
    configured: true,
    detectors: 0,
    error: 'detector pack could not be inspected',
    usingLastKnownGood: false,
  });
});

test('custom detector loader retries a transient read failure without a metadata change', () => {
  const payload = JSON.stringify({
    detectors: [{ id: 'RECOVERED_MEMBER_ID', pattern: '\\bRM-[0-9]{6}\\b' }],
  });
  let reads = 0;
  const flakyFs = {
    statSync: () => ({ mtimeMs: 1, ctimeMs: 1, size: payload.length }),
    readFileSync() {
      reads += 1;
      if (reads === 1) {
        const error = new Error('synthetic read failure');
        error.code = 'EIO';
        throw error;
      }
      return payload;
    },
  };
  const loader = customDetectors.createLoader('flaky-custom-detectors.json', true, flakyFs);

  assert.strictEqual(loader.status().ok, false);
  assert.strictEqual(loader.status().ok, true);
  assert.deepStrictEqual(loader.loadCustomDetectors().map((item) => item.id), ['RECOVERED_MEMBER_ID']);
  assert.strictEqual(reads, 2);
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

test('custom detector loader accepts array configs and retains them on invalid JSON', () => {
  fs.writeFileSync(customDetectorPath, JSON.stringify([{
    id: 'BRANCH_MEMBER_ID',
    label: 'Branch member id',
    severity: 3,
    pattern: '\\bBR-[0-9]{6}\\b',
  }]));
  assert.deepStrictEqual(customDetectors.loadRaw().detectors.map((item) => item.id), ['BRANCH_MEMBER_ID']);
  assert.deepStrictEqual(customDetectors.listDetectorIds(), ['BRANCH_MEMBER_ID']);
  assert.strictEqual(customDetectors.status().ok, true);

  fs.writeFileSync(customDetectorPath, '{not json');
  assert.deepStrictEqual(customDetectors.loadRaw(), { detectors: [] });
  assert.deepStrictEqual(customDetectors.loadCustomDetectors().map((item) => item.id), ['BRANCH_MEMBER_ID']);
  assert.deepStrictEqual(customDetectors.status(), {
    ok: false,
    configured: true,
    detectors: 1,
    error: 'detector pack is not valid JSON',
    usingLastKnownGood: true,
  });
});

test.after(() => {
  for (const file of [customDetectorPath, process.env.REDACTWALL_POLICY_PATH]) {
    try { fs.unlinkSync(file); } catch {}
  }
});
