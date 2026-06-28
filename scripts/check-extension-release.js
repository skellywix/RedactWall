'use strict';
/**
 * Build and validate the Chrome extension release handoff for a managed pilot.
 */
const fs = require('fs');
const path = require('path');

const { packageExtension, sha256 } = require('./package-extension');

const ROOT = path.join(__dirname, '..');
const CHROME_WEB_STORE_UPDATE_URL = 'https://clients2.google.com/service/update2/crx';
const EXTENSION_ID_RE = /^[a-p]{32}$/;

function readJson(root, relPath) {
  return JSON.parse(fs.readFileSync(path.join(root, relPath), 'utf8'));
}

function readText(root, relPath) {
  return fs.readFileSync(path.join(root, relPath), 'utf8');
}

function record(checks, id, passed, detail) {
  checks[id] = { passed: passed === true, detail };
}

function requireCheck(checks, id, passed, detail, problems) {
  record(checks, id, passed, detail);
  if (!passed) problems.push(`${id}: ${detail}`);
}

function validateExtensionId(extensionId) {
  if (!extensionId) return 'pending_chrome_web_store_upload';
  if (!EXTENSION_ID_RE.test(extensionId)) {
    throw new Error('Chrome extension id must be 32 lowercase characters in the a-p alphabet');
  }
  return 'provided';
}

function extensionSettingsPolicy(extensionId) {
  return {
    ExtensionSettings: {
      [extensionId]: {
        installation_mode: 'force_installed',
        update_url: CHROME_WEB_STORE_UPDATE_URL,
      },
    },
  };
}

function writeExtensionSettingsPolicy({ outDir, extensionVersion, extensionId }) {
  if (!extensionId) return null;
  const policyPath = path.join(outDir, `promptwall-extension-v${extensionVersion}.extension-settings.json`);
  fs.writeFileSync(policyPath, JSON.stringify(extensionSettingsPolicy(extensionId), null, 2) + '\n');
  return policyPath;
}

function validatePolicyExamples(root, checks, problems) {
  const schema = readJson(root, 'sensors/browser-extension/schema.json');
  const managed = readJson(root, 'docs/examples/chrome-managed-storage.policy.json');
  const settings = readJson(root, 'docs/examples/chrome-extension-settings.example.json');
  const schemaKeys = new Set(Object.keys((schema && schema.properties) || {}));
  const managedKeys = Object.keys(managed || {});
  const settingsEntry = settings.ExtensionSettings && settings.ExtensionSettings['<extension-id>'];

  requireCheck(
    checks,
    'managed_storage_schema_aligned',
    managedKeys.every((key) => schemaKeys.has(key)) && ['serverUrl', 'ingestKey', 'orgId'].every((key) => managedKeys.includes(key)),
    'managed storage example uses only schema-backed keys and includes serverUrl, ingestKey, and orgId',
    problems,
  );
  requireCheck(
    checks,
    'managed_storage_uses_placeholder_secret',
    managed.ingestKey === 'REPLACE_WITH_LONG_RANDOM_INGEST_KEY',
    'managed storage example keeps the ingest key as a placeholder',
    problems,
  );
  requireCheck(
    checks,
    'force_install_policy_example',
    !!settingsEntry && settingsEntry.installation_mode === 'force_installed',
    'Chrome ExtensionSettings example force-installs the extension',
    problems,
  );
  requireCheck(
    checks,
    'chrome_web_store_update_url',
    !!settingsEntry && settingsEntry.update_url === CHROME_WEB_STORE_UPDATE_URL,
    'Chrome ExtensionSettings example uses the Chrome Web Store update URL',
    problems,
  );
}

function validateDocs(root, checks, problems) {
  const managedGuide = readText(root, 'docs/MANAGED_EXTENSION_DEPLOYMENT.md');
  const checklist = readText(root, 'docs/EXTENSION_RELEASE_CHECKLIST.md');
  const technicianGuide = readText(root, 'docs/TECHNICIAN_DEPLOYMENT_GUIDE.md');

  requireCheck(
    checks,
    'release_checklist_present',
    /Private or unlisted Chrome Web Store release/i.test(checklist)
      && /npm run release:extension:check/i.test(checklist)
      && /rollback/i.test(checklist),
    'release checklist covers Web Store visibility, readiness command, and rollback',
    problems,
  );
  requireCheck(
    checks,
    'managed_deployment_docs_reference_release_check',
    /release:extension:check/i.test(managedGuide) && /private or unlisted/i.test(managedGuide),
    'managed extension guide references the release readiness command and private or unlisted channel',
    problems,
  );
  requireCheck(
    checks,
    'technician_handoff_mentions_release_readiness',
    /Extension release-readiness report/i.test(technicianGuide),
    'technician handoff packet includes the release-readiness report',
    problems,
  );
}

function validatePackageManifest(packageManifest, checks, problems) {
  for (const [id, value] of Object.entries(packageManifest.checks || {})) {
    requireCheck(checks, `package_${id}`, value === true, `package manifest check ${id} is true`, problems);
  }
  requireCheck(
    checks,
    'package_kind',
    packageManifest.kind === 'promptwall-extension-package',
    'package manifest has the expected kind',
    problems,
  );
}

function validateReleasePackage(packaged, checks, problems) {
  const packageManifest = packaged.packageManifest;
  const packageManifestBody = fs.readFileSync(packaged.manifestPath, 'utf8');
  const zipBody = fs.readFileSync(packaged.zipPath);

  requireCheck(
    checks,
    'package_sha256_matches_zip',
    packageManifest.sha256 === sha256(zipBody),
    'package manifest SHA-256 matches the generated zip',
    problems,
  );
  requireCheck(
    checks,
    'package_manifest_prompt_free',
    !/524-71-9043|4111 1111|REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key/i.test(packageManifestBody),
    'package manifest does not contain prompt bodies or secret placeholders',
    problems,
  );
  validatePackageManifest(packageManifest, checks, problems);
}

function validateRenderedExtensionSettingsPolicy(policyPath, extensionId, checks, problems) {
  if (!policyPath) return;
  const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
  const entry = policy.ExtensionSettings && policy.ExtensionSettings[extensionId];
  requireCheck(
    checks,
    'generated_extension_settings_policy',
    !!entry && entry.installation_mode === 'force_installed' && entry.update_url === CHROME_WEB_STORE_UPDATE_URL,
    'generated ExtensionSettings policy force-installs the supplied Chrome Web Store id',
    problems,
  );
  requireCheck(
    checks,
    'generated_extension_settings_prompt_free',
    !/REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key|promptwall\.example\.org|524-71-9043|4111 1111/i.test(JSON.stringify(policy)),
    'generated ExtensionSettings policy contains no managed-storage secrets or prompt examples',
    problems,
  );
}

function releaseReportFor({ now, extensionIdStatus, extensionId, extensionSettingsPolicyPath, packaged, checks, problems }) {
  const packageManifest = packaged.packageManifest;
  return {
    kind: 'promptwall-extension-release-readiness',
    status: problems.length ? 'blocked' : 'ready',
    createdAt: now.toISOString(),
    extensionIdStatus,
    extensionId: extensionIdStatus === 'provided' ? extensionId : null,
    extensionVersion: packageManifest.extensionVersion,
    appVersion: packageManifest.appVersion,
    packageName: path.basename(packaged.zipPath),
    packageManifest: path.basename(packaged.manifestPath),
    extensionSettingsPolicy: extensionSettingsPolicyPath ? path.basename(extensionSettingsPolicyPath) : null,
    packageSha256: packageManifest.sha256,
    chromeWebStore: {
      visibility: 'private_or_unlisted',
      updateUrl: CHROME_WEB_STORE_UPDATE_URL,
      reviewerNotesRequired: true,
    },
    policyExamples: [
      'docs/examples/chrome-extension-settings.example.json',
      'docs/examples/chrome-managed-storage.policy.json',
    ],
    requiredHandoffEvidence: [
      'Chrome Web Store item id or private listing URL',
      extensionSettingsPolicyPath
        ? `Rendered ExtensionSettings force-install policy: ${path.basename(extensionSettingsPolicyPath)}`
        : 'Rendered ExtensionSettings force-install policy from rerunning this command with --extension-id',
      'ExtensionSettings force-install policy exported from the customer OU',
      'Managed storage policy with tenant URL, org id, and secret-bearing ingest key stored outside source control',
      'Coverage Fleet Install Health row showing browser_extension covered for a managed test user',
      'Rollback owner and prior extension version',
    ],
    checks,
    sources: [
      'https://support.google.com/chrome/a/answer/6306504',
      'https://developer.chrome.com/docs/webstore/cws-dashboard-distribution',
    ],
  };
}

function checkExtensionRelease(opts = {}) {
  const root = opts.root || ROOT;
  const outDir = opts.outDir || path.join(root, 'dist', 'browser-extension');
  const now = opts.now || new Date();
  const extensionId = String(opts.extensionId || '').trim();
  const extensionIdStatus = validateExtensionId(extensionId);
  const packaged = packageExtension({ root, outDir, now });
  const extensionSettingsPolicyPath = extensionIdStatus === 'provided'
    ? writeExtensionSettingsPolicy({
      outDir,
      extensionVersion: packaged.packageManifest.extensionVersion,
      extensionId,
    })
    : null;
  const checks = {};
  const problems = [];

  validateReleasePackage(packaged, checks, problems);
  validateRenderedExtensionSettingsPolicy(extensionSettingsPolicyPath, extensionId, checks, problems);
  validatePolicyExamples(root, checks, problems);
  validateDocs(root, checks, problems);

  const releaseReport = releaseReportFor({ now, extensionIdStatus, extensionId, extensionSettingsPolicyPath, packaged, checks, problems });

  if (problems.length) {
    const err = new Error(`Extension release readiness failed: ${problems.join('; ')}`);
    err.problems = problems;
    err.report = releaseReport;
    throw err;
  }

  const reportPath = path.join(outDir, `promptwall-extension-v${packaged.packageManifest.extensionVersion}.release-readiness.json`);
  fs.writeFileSync(reportPath, JSON.stringify(releaseReport, null, 2) + '\n');
  return { ...packaged, extensionSettingsPolicyPath, reportPath, releaseReport };
}

function parseArgs(argv) {
  const args = [...argv];
  let outDir = path.join(ROOT, 'dist', 'browser-extension');
  let extensionId = '';
  let json = false;
  const positionals = [];
  while (args.length) {
    const arg = args.shift();
    if (arg === '--out') {
      outDir = path.resolve(args.shift() || '');
    } else if (arg === '--extension-id') {
      extensionId = String(args.shift() || '').trim();
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--help' || arg === '-h') {
      return { help: true, outDir, extensionId, json };
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
  if (positionals[0]) outDir = path.resolve(positionals[0]);
  if (positionals[1] && !extensionId) extensionId = String(positionals[1]).trim();
  if (positionals.length > 2) throw new Error('Too many positional arguments');
  return { outDir, extensionId, json };
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      console.log('Usage: node scripts/check-extension-release.js [--out <directory>] [--extension-id <chrome-web-store-id>] [--json]');
      console.log('   or: node scripts/check-extension-release.js [directory] [chrome-web-store-id]');
      return;
    }
    const result = checkExtensionRelease({ outDir: args.outDir, extensionId: args.extensionId });
    if (args.json) {
      console.log(JSON.stringify(result.releaseReport, null, 2));
      return;
    }
    console.log(`Wrote ${result.zipPath}`);
    console.log(`Wrote ${result.manifestPath}`);
    console.log(`Wrote ${result.reportPath}`);
    console.log(`Release readiness ${result.releaseReport.status}`);
  } catch (err) {
    console.error(err.message || err);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  CHROME_WEB_STORE_UPDATE_URL,
  checkExtensionRelease,
  extensionSettingsPolicy,
  parseArgs,
  validateExtensionId,
};
