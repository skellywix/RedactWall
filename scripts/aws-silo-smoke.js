'use strict';
/**
 * AWS customer-silo acceptance smoke.
 *
 * Proves an already-deployed single-tenant silo is examiner-ready BEFORE handover.
 * It asserts behavior that already ships — it does not change anything:
 *   1. cloud-synced evidence-store paths are rejected (no Dropbox/OneDrive/Box/…);
 *   2. the tamper-evident audit chain verifies (verifyAuditChain -> ok:true);
 *   3. a federal-credit-union examiner pack exports at schemaVersion 3, prompt-free.
 *
 * require()-able so test/aws-silo-smoke.test.js can drive it with fakes; run as
 * `node scripts/aws-silo-smoke.js` (or `npm run silo:smoke`) against a real silo.
 */

function checkCloudSyncedPathGuard(deps = {}) {
  const pf = deps.preflightModule || require('../server/preflight');
  const cloudPath = deps.cloudPath || '/home/ec2-user/Dropbox/redactwall/redactwall.db';
  const safePath = deps.safePath || '/var/lib/redactwall/redactwall.db';
  const reason = pf.cloudSyncedPathReason(cloudPath);
  const safeAccepted = pf.cloudSyncedPathReason(safePath) === null;
  return {
    id: 'cloud_synced_path_rejected',
    ok: !!reason && safeAccepted,
    detail: reason
      ? `cloud-synced evidence path flagged as ${reason}; local path accepted`
      : 'cloud-synced path guard failed to flag a cloud path',
  };
}

function checkAuditChain(deps = {}) {
  const db = deps.dbModule || require('../server/db');
  const res = db.verifyAuditChain();
  return {
    id: 'audit_chain_verified',
    ok: !!(res && res.ok === true),
    detail: res && res.ok ? `audit chain verified across ${Number(res.count) || 0} event(s)` : 'audit chain did not verify',
  };
}

function checkExaminerExport(deps = {}) {
  const packer = deps.packModule || require('./export-evidence-pack');
  const pack = packer.buildEvidencePackFromRuntime({ ...(deps.exportOptions || {}), examinerProfile: 'federal_credit_union' });
  const ok = !!pack
    && pack.schemaVersion === 3
    && pack.scope && pack.scope.examinerProfile === 'federal_credit_union'
    && pack.scope.rawPromptBodiesIncluded === false;
  return {
    id: 'examiner_profile_export',
    ok,
    detail: ok
      ? 'federal_credit_union pack exported at schemaVersion 3, prompt-free'
      : 'examiner-profile export did not produce a prompt-free schemaVersion-3 pack',
  };
}

function runSmoke(deps = {}) {
  const checks = [
    checkCloudSyncedPathGuard(deps),
    checkAuditChain(deps),
    checkExaminerExport(deps),
  ];
  return { ok: checks.every((c) => c.ok), checks };
}

if (require.main === module) {
  const result = runSmoke();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}

module.exports = { runSmoke, checkCloudSyncedPathGuard, checkAuditChain, checkExaminerExport };
