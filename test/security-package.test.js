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
    name: 'promptwall',
    version: '0.3.0',
    lockfileVersion: 3,
    packages: {
      '': {
        name: 'promptwall',
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
      name: 'promptwall',
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
      SIEM_WEBHOOK_URL: 'https://soc.example.test/promptwall',
      SENTINEL_DATA_KEY: 'unit-data-key-stable-should-not-export',
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
});

test('security trust package archive has manifest, package, SBOM, and readme files', () => {
  const pack = buildFixturePackage();
  const archive = new AdmZip(securityPackage.packageArchive(pack));
  const entries = archive.getEntries().map((entry) => entry.entryName).sort();

  assert.deepStrictEqual(entries, ['README.md', 'manifest.json', 'sbom/cyclonedx.json', 'security-trust-package.json']);
  assert.strictEqual(archive.readAsText('security-trust-package.json').includes(tempRoot), false);
  assert.match(archive.readAsText('README.md'), /PromptWall Security Trust Package/);
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
