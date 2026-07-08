'use strict';
/** Security trust package exports procurement proof without secrets or prompt content. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const AdmZip = require('adm-zip');

const securityPackage = require('../server/security-package');
const packer = require('../scripts/export-security-package');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-security-package-test-'));

function fixtureLockfile() {
  return {
    name: 'redactwall',
    version: '0.3.0',
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'redactwall',
        version: '0.3.0',
        dependencies: { 'adm-zip': '^0.5.17', express: '^5.2.1' },
        devDependencies: { '@playwright/test': '^1.61.1' },
      },
      'node_modules/adm-zip': {
        version: '0.5.17',
        resolved: `file:${tempRoot}/secret-local-cache/adm-zip.tgz`,
        integrity: 'sha512-testhash',
        license: 'MIT',
      },
      'node_modules/express': {
        version: '5.2.1',
        resolved: 'https://registry.npmjs.org/express/-/express-5.2.1.tgz',
        integrity: 'sha512-expresshash',
        license: 'MIT',
      },
      'node_modules/@playwright/test': {
        version: '1.61.1',
        resolved: 'https://registry.npmjs.org/@playwright/test/-/test-1.61.1.tgz',
        integrity: 'sha512-playwrighthash',
        license: 'Apache-2.0',
        dev: true,
      },
    },
  };
}

function buildFixturePackage() {
  return securityPackage.trustPackage({
    generatedAt: '2026-07-04T12:00:00.000Z',
    packageInfo: {
      name: 'redactwall',
      version: '0.3.0',
      description: 'Inline DLP gateway for AI chat prompts.',
      engines: { node: '>=22' },
      license: 'UNLICENSED',
    },
    lockfile: fixtureLockfile(),
    policy: {
      blockUnapprovedAiDestinations: true,
      responseScanMode: 'block',
      requiredSensors: ['browser_extension', 'endpoint_agent', 'mcp_guard'],
      approvalRoutingRules: [{ id: 'privacy_route' }],
      rawRetentionDays: 45,
      storeRawForApproval: true,
    },
    auditIntegrity: { ok: true, count: 12 },
    preflight: {
      checks: [
        { id: 'admin_mfa', ok: true, severity: 'error' },
        { id: 'secure_cookie', ok: true, severity: 'error' },
        { id: 'session_secret_strength', ok: true, severity: 'error' },
        { id: 'data_key_strength', ok: true, severity: 'error' },
      ],
    },
    coverage: { totals: { activeRequiredSensors: 3, requiredSensors: 3 } },
    posture: {
      hardening: {
        mission: { proofLedger: { verified: 4 } },
        areas: [{ id: 'ai_gateway_enforcement', state: 'ready' }],
      },
    },
    env: {
      SIEM_WEBHOOK_URL: 'https://soc.example.test/redactwall',
      REDACTWALL_DATA_KEY: 'unit-data-key-stable-should-not-export',
    },
  });
}

test('security trust package contains controls and SBOM without sensitive values', () => {
  const ssn = '524-71-9043';
  const apiKey = 'sk-proj-secret-should-not-export';
  const pack = buildFixturePackage();
  const wire = JSON.stringify(pack);

  assert.strictEqual(pack.schemaVersion, securityPackage.SCHEMA_VERSION);
  assert.strictEqual(pack.privacyContract.rawPromptBodies, false);
  assert.strictEqual(pack.privacyContract.secretsOrCredentials, false);
  assert.ok(pack.summary.controlCoverage.verified >= 9);
  assert.ok(pack.controls.some((item) => item.id === 'llm_gateway' && item.status === 'verified'));
  assert.ok(pack.sbom.components.some((item) => item.name === 'adm-zip' && item.scope === 'required'));
  assert.ok(pack.sbom.components.some((item) => item.name === '@playwright/test' && item.scope === 'excluded'));
  assert.strictEqual(pack.sbom.directDependencies.production.includes('express'), true);
  assert.strictEqual(pack.sbom.summary.components, 3);
  assert.ok(pack.questionnaire.some((item) => /dependency inventory/i.test(item.answer)));
  assert.strictEqual(wire.includes(ssn), false);
  assert.strictEqual(wire.includes(apiKey), false);
  assert.strictEqual(wire.includes(tempRoot), false);
  assert.strictEqual(wire.includes('secret-local-cache'), false);
  assert.strictEqual(wire.includes('unit-data-key-stable-should-not-export'), false);

  const complianceWire = JSON.stringify({
    soc2Readiness: pack.soc2Readiness,
    vulnerabilityPolicy: pack.vulnerabilityPolicy,
    dpaBaaPosture: pack.dpaBaaPosture,
    retentionLegalHold: pack.retentionLegalHold,
  });
  assert.strictEqual(complianceWire.includes(ssn), false);
  assert.strictEqual(complianceWire.includes(apiKey), false);
  assert.strictEqual(complianceWire.includes(tempRoot), false);
  assert.strictEqual(complianceWire.includes('unit-data-key-stable-should-not-export'), false);
});

test('security trust package maps controls to SOC 2 criteria with worst-status rollup', () => {
  const pack = buildFixturePackage();
  const controlIds = new Set(pack.controls.map((item) => item.id));
  const soc2 = pack.soc2Readiness;

  assert.ok(soc2.criteria.length >= 5);
  assert.ok(pack.controls.every((item) => Array.isArray(item.soc2Criteria) && item.soc2Criteria.length >= 1));
  for (const criterion of soc2.criteria) {
    assert.match(criterion.id, /^CC[1-9]\.\d+$/);
    assert.ok(criterion.title.length > 0);
    assert.ok(criterion.controls.length >= 1);
    assert.ok(criterion.controls.every((id) => controlIds.has(id)));
    assert.ok(['verified', 'attention', 'missing'].includes(criterion.status));
  }
  assert.strictEqual(soc2.summary.criteria, soc2.criteria.length);
  assert.strictEqual(
    soc2.summary.verified + soc2.summary.attention + soc2.summary.missing,
    soc2.criteria.length,
  );
  assert.match(soc2.summary.note, /not a SOC 2 report/i);
  assert.ok(soc2.criteria.every((criterion) => criterion.status === 'verified'));
});

test('SOC 2 criterion status inherits the worst mapped control state', () => {
  const soc2 = securityPackage.soc2Readiness([
    { id: 'admin_mfa', status: 'missing', soc2Criteria: ['CC6.1'] },
    { id: 'secure_sessions', status: 'verified', soc2Criteria: ['CC6.1'] },
    { id: 'audit_chain', status: 'attention', soc2Criteria: ['CC7.2'] },
  ]);

  assert.strictEqual(soc2.criteria.find((item) => item.id === 'CC6.1').status, 'missing');
  assert.strictEqual(soc2.criteria.find((item) => item.id === 'CC7.2').status, 'attention');
});

test('security trust package states vulnerability policy, DPA/BAA posture, and retention', () => {
  const pack = buildFixturePackage();

  const severities = pack.vulnerabilityPolicy.patchSlas.map((item) => item.severity);
  assert.deepStrictEqual(severities, ['critical', 'high', 'medium', 'low']);
  assert.strictEqual(pack.vulnerabilityPolicy.patchSlas[0].patchWithin, '72 hours');
  assert.match(pack.vulnerabilityPolicy.scanning.cadence, /npm audit/);
  assert.strictEqual(pack.vulnerabilityPolicy.dependencyPolicy.lockfilePinned, true);
  assert.strictEqual(pack.vulnerabilityPolicy.lastValidatedAt, '2026-07-04T12:00:00.000Z');

  assert.strictEqual(pack.dpaBaaPosture.dataHandling.promptEgress, false);
  assert.deepStrictEqual(pack.dpaBaaPosture.subProcessors, []);
  assert.strictEqual(pack.dpaBaaPosture.dpa.offered, true);
  assert.strictEqual(pack.dpaBaaPosture.hipaaBaa.available, true);

  assert.strictEqual(pack.retentionLegalHold.retention.rawRetentionDays, 45);
  assert.strictEqual(pack.retentionLegalHold.retention.storeRawForApproval, true);
  assert.strictEqual(pack.retentionLegalHold.legalHold.supported, false);
  assert.match(pack.retentionLegalHold.legalHold.note, /operator action/i);
});

test('security trust package lists whitepaper and incident-response docs that exist', () => {
  const pack = buildFixturePackage();
  const docPaths = pack.documents.map((item) => item.path);

  assert.ok(docPaths.includes('docs/security/SECURITY_WHITEPAPER.md'));
  assert.ok(docPaths.includes('docs/security/INCIDENT_RESPONSE.md'));
  for (const docPath of docPaths) {
    assert.ok(fs.existsSync(path.join(__dirname, '..', docPath)), `${docPath} should exist`);
  }
  assert.match(securityPackage.packageReadme(pack), /SOC 2 readiness/);
});

test('security trust package archive has manifest, package, SBOM, and readme files', () => {
  const pack = buildFixturePackage();
  const archive = new AdmZip(securityPackage.packageArchive(pack));
  const entries = archive.getEntries().map((entry) => entry.entryName).sort();

  assert.deepStrictEqual(entries, ['README.md', 'manifest.json', 'sbom/cyclonedx.json', 'security-trust-package.json']);
  assert.strictEqual(archive.readAsText('security-trust-package.json').includes(tempRoot), false);
  assert.match(archive.readAsText('README.md'), /RedactWall Security Trust Package/);
});

test('security package CLI writer emits JSON and ZIP artifacts', () => {
  const pack = buildFixturePackage();
  const result = packer.writeSecurityPackage({
    package: pack,
    outDir: path.join(tempRoot, 'packages'),
    zip: true,
  });

  assert.ok(fs.existsSync(result.file));
  assert.ok(fs.existsSync(result.zipFile));
  assert.strictEqual(JSON.parse(fs.readFileSync(result.file, 'utf8')).schemaVersion, securityPackage.SCHEMA_VERSION);
  assert.match(result.sha256, /^[a-f0-9]{64}$/);
  assert.match(result.zipSha256, /^[a-f0-9]{64}$/);
});

test.after(() => {
  try { fs.rmSync(tempRoot, { recursive: true, force: true }); } catch {}
});
