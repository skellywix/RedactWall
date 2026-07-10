'use strict';

const test = require('node:test');
const assert = require('node:assert');
const smoke = require('../scripts/aws-silo-smoke');
const packer = require('../scripts/export-evidence-pack');

// Fake runtime modules so the examiner-export check exercises the REAL packer
// end to end without a live database (mirrors test/evidence-pack.test.js).
function fakeExportOptions() {
  return {
    dbModule: {
      listQueries(filter) { return filter && filter.all ? [] : []; },
      listAudit() { return []; },
      stats() { return { total: 0 }; },
      verifyAuditChain() { return { ok: true, count: 1 }; },
    },
    policyModule: {
      loadPolicy() { return { alwaysBlock: ['US_SSN', 'MEMBER_ID', 'LOAN_NUMBER', 'BANK_ACCOUNT', 'ROUTING_NUMBER'] }; },
      policyExceptionReview() { return { total: 0, active: 0, expiringSoon: 0, reviewDue: 0, expired: 0, disabled: 0, reviewWindowDays: 14, items: [] }; },
    },
    coverageModule: { summarize() { return { score: 100, totals: {}, sensors: [], fleet: [], governedDestinations: [], ungovernedDestinations: [], shadowDestinations: [], posture: [] }; } },
    detectorModule: { listDetectors() { return [{ id: 'MEMBER_ID' }]; } },
    customDetectorsModule: { loadCustomDetectors() { return []; } },
    exactMatchModule: { publicSummary() { return { enabled: true, fingerprints: 7, minLength: 20, maxWords: 1, severity: 4 }; } },
    appCatalogModule: { reviewRollup() { return []; } },
    licenseModule: { entitled() { return true; }, refresh() {} },
    packageInfo: { version: '0.4.0' },
    backupModule: {},
  };
}

function deps() {
  const opts = fakeExportOptions();
  return { dbModule: opts.dbModule, exportOptions: { ...opts, packModule: packer }, packModule: packer };
}

test('aws-silo smoke passes when the silo is examiner-ready', () => {
  const result = smoke.runSmoke(deps());
  assert.strictEqual(result.ok, true, JSON.stringify(result.checks));
  const byId = new Map(result.checks.map((c) => [c.id, c]));
  assert.strictEqual(byId.get('cloud_synced_path_rejected').ok, true);
  assert.strictEqual(byId.get('audit_chain_verified').ok, true);
  assert.strictEqual(byId.get('examiner_profile_export').ok, true);
});

test('the cloud-synced path guard actually discriminates', () => {
  // A safe path handed in as the "cloud" candidate must FAIL the check — proving
  // it is really testing the guard, not passing vacuously.
  const bad = smoke.checkCloudSyncedPathGuard({ cloudPath: '/var/lib/redactwall/redactwall.db' });
  assert.strictEqual(bad.ok, false);
  const good = smoke.checkCloudSyncedPathGuard({ cloudPath: '/home/user/OneDrive/redactwall.db' });
  assert.strictEqual(good.ok, true);
});

test('the audit-chain check fails closed on a broken chain', () => {
  const res = smoke.checkAuditChain({ dbModule: { verifyAuditChain() { return { ok: false, count: 3 }; } } });
  assert.strictEqual(res.ok, false);
});
