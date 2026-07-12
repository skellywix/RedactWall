'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');
const ts = require('../console/node_modules/typescript');

function loadDecoder() {
  const file = path.join(__dirname, '..', 'console', 'src', 'lib', 'strict-console-response.ts');
  const source = fs.readFileSync(file, 'utf8');
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const loaded = new Module(file, module);
  loaded.filename = file;
  loaded.paths = module.paths;
  loaded._compile(output, file);
  return loaded.exports;
}

function loadPolicyMatcher() {
  const file = path.join(__dirname, '..', 'console', 'src', 'api', 'policy-match.ts');
  const source = fs.readFileSync(file, 'utf8');
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const loaded = new Module(file, module);
  loaded.filename = file;
  loaded.paths = module.paths;
  loaded._compile(output, file);
  return loaded.exports.policyMatchesCoreUpdate;
}

const decoder = loadDecoder();
const ISO = '2026-07-12T12:00:00.000Z';

function source(relativePath) {
  return fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');
}

function adminUser(overrides = {}) {
  return {
    id: 'local:user-1',
    userName: 'operator@example.test',
    displayName: 'Example Operator',
    role: 'operator',
    roleLabel: 'Operator',
    active: true,
    source: 'local_invite',
    sourceLabel: 'Local invite',
    sources: ['local_invite'],
    orgId: null,
    firstSeen: null,
    lastSeen: ISO,
    events: 4,
    licenseState: 'in_use',
    licenseReason: '',
    licenseUpdatedAt: null,
    mutable: true,
    ...overrides,
  };
}

function invitation(overrides = {}) {
  return {
    id: 'invite-1',
    userName: 'invitee@example.test',
    displayName: 'Invitee',
    role: 'auditor',
    roleLabel: 'Auditor',
    status: 'pending',
    expiresAt: ISO,
    acceptedAt: null,
    createdAt: ISO,
    updatedAt: ISO,
    ...overrides,
  };
}

function seatSummary(overrides = {}) {
  return {
    tenantId: null,
    saasMode: false,
    seatLimit: 0,
    seatLimitValid: true,
    seatsUsed: 0,
    seatsRemaining: null,
    overLimit: false,
    users: [],
    ...overrides,
  };
}

function licenseStatus(overrides = {}) {
  return {
    state: 'active',
    plan: 'standard',
    seats: 25,
    customer: 'Texas FCU',
    customerId: 'texas-fcu',
    features: ['ncua_readiness'],
    expires: '2099-01-01T00:00:00.000Z',
    graceEndsAt: '2099-01-31T00:00:00.000Z',
    daysRemaining: 26471,
    reason: null,
    ...overrides,
  };
}

test('exact mutation receipts reject truthy, partial, and contradictory bodies', () => {
  const state = {
    status: 'restart-scheduled',
    restartRequired: true,
    restartScheduledAt: ISO,
    updatedAt: ISO,
  };
  assert.strictEqual(decoder.isExactEmailSuccess({ ok: true }), true);
  assert.strictEqual(decoder.isExactEmailSuccess({ ok: true, error: 'failed' }), false);
  assert.strictEqual(decoder.isExactEmailSuccess({ ok: 'true' }), false);
  assert.strictEqual(decoder.isExactRestartScheduled({ ok: true, scheduled: true, state }), true);
  assert.strictEqual(decoder.isExactRestartScheduled({ ok: true, scheduled: true }), false);
  assert.strictEqual(decoder.isExactRestartScheduled({ ok: true }), false);
  assert.strictEqual(decoder.isExactRestartScheduled({ ok: true, scheduled: 'true', state }), false);
  assert.strictEqual(decoder.isExactRestartScheduled({ ok: true, scheduled: true, state: { ...state, restartRequired: false } }), false);
  assert.strictEqual(decoder.isExactRestartScheduled({ ok: true, scheduled: true, state: { ...state, unexpected: true } }), false);
});

test('policy save verification accepts real advanced normalization and rejects normalized mismatches', () => {
  const matches = loadPolicyMatcher();
  const serverPolicy = require('../server/policy');
  const update = {
    requiredSensors: ['browser_extension', 'endpoint_agent', 'browser_extension'],
    desiredSensorVersions: { Browser_Extension: ' 0.4.0 ', endpoint_agent: '0.4.0' },
    mcpAllowedTools: ['drive.read*', 'drive.read*'],
    mcpBlockedTools: ['*.delete*'],
    mcpApprovalRequiredTools: ['database.write*'],
    approvalRoutingRules: [{
      id: 'lending_high_risk', assignedGroup: 'lending', assignedRole: 'approver', slaMinutes: 60,
      groups: ['RedactWall Lending'], detectors: ['SECRET_KEY'], minRiskScore: 70, reason: 'lending_review',
    }],
    blockedBrowserActions: [{
      id: 'block_chatgpt_paste', action: 'paste', destinations: ['chatgpt.com'], reason: 'member_policy',
    }],
    policyScopes: [{
      id: 'legal_review', groups: ['Legal'], destinations: ['claude.ai'], enforcementMode: 'block',
      blockMinSeverity: 3, blockRiskScore: 55, alwaysBlockAdd: ['SECRET_KEY'], reason: 'legal_policy',
    }],
    policyExceptions: [{
      id: 'vendor_review', groups: ['Legal'], destinations: ['vendor.example'], action: 'allow',
      expiresAt: '2030-01-02T03:04:05Z', reviewAfter: '2030-01-01T03:04:05Z',
      ownerGroup: 'legal', reviewerRole: 'approver', reason: 'vendor_review',
    }],
    alwaysBlock: ['US_SSN'],
  };
  const policy = serverPolicy.normalizePolicy({ ...serverPolicy.DEFAULT_POLICY, ...update });
  assert.strictEqual(matches(policy, update), true, 'real server normalization is accepted');
  for (const key of ['requiredSensors', 'desiredSensorVersions', 'mcpAllowedTools', 'approvalRoutingRules', 'blockedBrowserActions', 'policyScopes', 'policyExceptions']) {
    const changed = structuredClone(policy);
    changed[key] = Array.isArray(changed[key]) ? [] : {};
    assert.strictEqual(matches(changed, update), false, key);
  }
  assert.strictEqual(matches(policy, { ...update, alwaysBlock: ['US_SSN', 'NOT_PRESENT'] }), false);
});

test('SOC notification receipt requires an exact boolean result and complete posture receipt', () => {
  const posture = { generatedAt: ISO, score: 91, state: 'ready' };
  assert.deepStrictEqual(decoder.decodeSocNotifyResponse({ sent: true, status: 204, posture }), { sent: true });
  assert.deepStrictEqual(decoder.decodeSocNotifyResponse({ sent: false, reason: 'disabled', posture }), { sent: false, reason: 'disabled' });
  assert.strictEqual(decoder.decodeSocNotifyResponse({ sent: 'true', status: 204, posture }), null);
  assert.strictEqual(decoder.decodeSocNotifyResponse({ sent: true, posture }), null);
  assert.strictEqual(decoder.decodeSocNotifyResponse({ sent: true, status: 204, posture, extra: true }), null);
});

test('identity roles, directory, users, invitations, and seat report are decoded completely', () => {
  const roles = {
    roles: [{
      id: 'operator',
      label: 'Operator',
      permissions: { administration: 'read', approvals: 'none', evidence: 'none', platform: 'operate sensors and updates' },
    }],
  };
  const directory = { users: [adminUser()], invitations: [invitation()], seatReport: seatSummary() };
  assert.strictEqual(decoder.isCompleteRolesResponse(roles), true);
  assert.strictEqual(decoder.isCompleteAdminDirectoryResponse(directory), true);
  assert.strictEqual(decoder.isCompleteInvitationResponse({ ...invitation(), inviteUrl: '/accept-invite.html#token=synthetic' }, true), true);

  assert.strictEqual(decoder.isCompleteRolesResponse({ roles: [{ id: 'operator', label: 'Operator', permissions: {} }] }), false);
  assert.strictEqual(decoder.isCompleteAdminDirectoryResponse({ ...directory, users: [adminUser({ events: '4' })] }), false);
  assert.strictEqual(decoder.isCompleteAdminDirectoryResponse({ ...directory, seatReport: { ...directory.seatReport, seatLimitValid: 'true' } }), false);
  assert.strictEqual(decoder.isCompleteInvitationResponse({ id: 'invite-1' }, true), false);
});

test('license and seat decoders reject empty, error, and malformed successful bodies', () => {
  const renewal = { id: 'renewal-1', status: 'pending', requestedSeats: 30, contactEmail: '', createdAt: ISO };
  const status = licenseStatus({ renewalRequests: [renewal] });
  const { renewalRequests, ...seatLicense } = status;
  const seats = {
    license: seatLicense,
    ...seatSummary(),
    assignedSeats: 0,
    releasedSeats: 0,
    users: [adminUser()],
  };
  assert.strictEqual(decoder.isCompleteLicenseStatusResponse(status, true), true);
  assert.strictEqual(decoder.isCompleteLicenseSeatsResponse(seats), true);
  assert.strictEqual(decoder.isCompleteRenewalResponse({ request: renewal }), true);
  assert.strictEqual(decoder.isCompleteLicenseStatusResponse({}, true), false);
  assert.strictEqual(decoder.isCompleteLicenseStatusResponse({ error: 'license_write_failed' }), false);
  assert.strictEqual(decoder.isCompleteLicenseSeatsResponse({ ...seats, users: [{}] }), false);
  assert.strictEqual(decoder.isCompleteLicenseSeatsResponse({ ...seats, seatsRemaining: 0 }), false);
});

test('license install correlation binds the response to submitted customer and entitlement fields', () => {
  const payload = {
    customer: 'Texas FCU',
    customerId: 'texas-fcu',
    plan: 'standard',
    seats: 25,
    features: ['ncua_readiness'],
    expires: '2099-01-01T00:00:00.000Z',
  };
  const signed = `${Buffer.from(JSON.stringify(payload)).toString('base64')}.synthetic-signature`;
  const submitted = decoder.decodeSubmittedLicensePayload(signed);
  assert.deepStrictEqual(submitted, payload);
  assert.strictEqual(decoder.licenseStatusMatchesSubmitted(licenseStatus(), submitted), true);
  assert.strictEqual(decoder.licenseStatusMatchesSubmitted(licenseStatus({ customerId: 'other-customer' }), submitted), false);
  assert.strictEqual(decoder.licenseStatusMatchesSubmitted(licenseStatus({ state: 'unlicensed' }), submitted), false);
  assert.strictEqual(decoder.decodeSubmittedLicensePayload('not-a-license'), null);
});

test('detector test decoder requires a known decision and complete bounded rationale', () => {
  const result = {
    decision: 'block',
    reasons: ['Hard-stop entity present: US_SSN'],
    riskScore: 100,
    maxSeverityLabel: 'critical',
    regulations: ['GLBA'],
    findings: [{ type: 'US_SSN', severity: 4, severityLabel: 'critical', confidence: 'validated', masked: '***-**-6789', regulations: ['GLBA'] }],
    categories: [],
    scoreBreakdown: [{ kind: 'finding', type: 'US_SSN', severity: 4, severityLabel: 'critical', confidence: 'validated', points: 32, regulations: ['GLBA'] }],
  };
  assert.strictEqual(decoder.isCompleteDetectorTestResult(result), true);
  assert.strictEqual(decoder.isCompleteDetectorTestResult({ ...result, decision: 'proceed' }), false);
  assert.strictEqual(decoder.isCompleteDetectorTestResult({ ...result, riskScore: '100' }), false);
  assert.strictEqual(decoder.isCompleteDetectorTestResult({ ...result, reasons: [{}] }), false);
  assert.strictEqual(decoder.isCompleteDetectorTestResult({ ...result, findings: [{}] }), false);
});

test('coverage decoder accepts the real complete report and rejects invented zero posture', () => {
  const report = require('../server/coverage').summarize([], {});
  assert.strictEqual(decoder.isCompleteCoverageReport(report), true);
  assert.strictEqual(decoder.isCompleteCoverageReport({}), false);
  assert.strictEqual(decoder.isCompleteCoverageReport({ ...report, totals: {} }), false);
  assert.strictEqual(decoder.isCompleteCoverageReport({ ...report, score: '0' }), false);
});

test('SIEM decoder verifies the real package contract and all count/privacy/profile claims', () => {
  const pkg = require('../server/siem-package').integrationPackage({ generatedAt: ISO });
  assert.strictEqual(decoder.isCompleteSiemPackageResponse(pkg), true);
  assert.strictEqual(decoder.isCompleteSiemPackageResponse({ ...pkg, summary: { ...pkg.summary, packageFiles: 0 } }), false);
  assert.strictEqual(decoder.isCompleteSiemPackageResponse({ ...pkg, privacy: { ...pkg.privacy, rawPromptBodies: 'false' } }), false);
  assert.strictEqual(decoder.isCompleteSiemPackageResponse({ ...pkg, profiles: [{ id: 'splunk' }] }), false);
});

test('affected console views wire strict decoders into every successful response path', () => {
  const policyApi = source('console/src/api/policy.ts');
  const policy = source('console/src/api/policy-match.ts');
  assert.match(policyApi, /export \{ policyMatchesCoreUpdate \} from '\.\/policy-match'/);
  for (const field of [
    'requiredSensors', 'desiredSensorVersions', 'mcpAllowedTools', 'mcpBlockedTools', 'mcpApprovalRequiredTools',
    'approvalRoutingRules', 'blockedBrowserActions', 'policyScopes', 'policyExceptions',
  ]) assert.match(policy, new RegExp(`'${field}'`), field);
  assert.match(policy, /required\.every/);

  const integrations = source('console/src/views/Integrations.tsx');
  assert.match(integrations, /res\.status === 200/);
  assert.match(integrations, /isExactEmailSuccess/);
  assert.match(integrations, /body\.ok === true/);

  const updates = source('console/src/views/Updates.tsx');
  assert.match(updates, /isExactRestartScheduled\(result\.data\)/);
  assert.match(updates, /Restart response could not be verified/);

  const monitor = source('console/src/views/Monitor.tsx');
  assert.match(monitor, /isCompleteSiemPackageResponse/);
  assert.match(monitor, /decodeSocNotifyResponse/);
  assert.match(monitor, /body\?\.sent === true && response\.status === 200/);

  const identity = source('console/src/views/Identity.tsx');
  assert.match(identity, /isCompleteAdminDirectoryResponse/);
  assert.match(identity, /isCompleteRolesResponse/);
  assert.match(identity, /isCompleteInvitationResponse/);

  const detector = source('console/src/views/Policy.tsx');
  assert.match(detector, /isCompleteDetectorTestResult/);
  assert.match(detector, /Test response could not be verified\./);

  const coverage = source('console/src/views/Coverage.tsx');
  assert.match(coverage, /isCompleteCoverageReport/);
  assert.match(coverage, /candidate\.destination !== request\.destination/);
  assert.doesNotMatch(coverage, /EMPTY_REPORT/);

  const licensing = source('console/src/views/Licensing.tsx');
  assert.match(licensing, /isCompleteLicenseStatusResponse/);
  assert.match(licensing, /isCompleteLicenseSeatsResponse/);
  assert.match(licensing, /licenseStatusMatchesSubmitted/);

  const liveStatus = source('console/src/components/LiveStatus.tsx');
  assert.match(liveStatus, /postureState === 'loading'/);
  assert.match(liveStatus, /LAST VERIFIED/);
  assert.match(liveStatus, /POSTURE VERIFIED/);
  assert.doesNotMatch(liveStatus, />POSTURE VERIFIED \{lastUpdated\}</);
});
