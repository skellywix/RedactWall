'use strict';
/**
 * Build and validate browser extension release handoffs for a managed pilot.
 */
const fs = require('fs');
const path = require('path');

const { BROWSER_TARGETS, packageExtensions, sha256 } = require('./package-extension');

const ROOT = path.join(__dirname, '..');
const CHROME_WEB_STORE_UPDATE_URL = 'https://clients2.google.com/service/update2/crx';
const EDGE_ADDONS_UPDATE_URL = 'https://edge.microsoft.com/extensionwebstorebase/v1/crx';
const FIREFOX_EXTENSION_ID = 'promptwall@example.com';
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
  if (!extensionId) return 'pending_store_upload';
  if (!EXTENSION_ID_RE.test(extensionId)) {
    throw new Error('Chromium extension id must be 32 lowercase characters in the a-p alphabet');
  }
  return 'provided';
}

function chromiumExtensionSettingsPolicy(extensionId, updateUrl) {
  return {
    ExtensionSettings: {
      [extensionId]: {
        installation_mode: 'force_installed',
        update_url: updateUrl,
      },
    },
  };
}

function extensionSettingsPolicy(extensionId) {
  return chromiumExtensionSettingsPolicy(extensionId, CHROME_WEB_STORE_UPDATE_URL);
}

function edgeExtensionSettingsPolicy(extensionId) {
  return chromiumExtensionSettingsPolicy(extensionId, EDGE_ADDONS_UPDATE_URL);
}

function firefoxExtensionSettingsPolicy({ extensionId = FIREFOX_EXTENSION_ID, installUrl }) {
  return {
    policies: {
      ExtensionSettings: {
        [extensionId]: {
          installation_mode: 'force_installed',
          install_url: installUrl,
        },
      },
    },
  };
}

function writeJsonFile(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2) + '\n');
  return filePath;
}

function writeExtensionSettingsPolicy({ outDir, extensionVersion, extensionId, target }) {
  if (!extensionId) return null;
  const policyPath = path.join(outDir, `promptwall-${target}-extension-v${extensionVersion}.extension-settings.json`);
  const policy = target === 'edge' ? edgeExtensionSettingsPolicy(extensionId) : extensionSettingsPolicy(extensionId);
  return writeJsonFile(policyPath, policy);
}

function writeFirefoxExtensionSettingsPolicy({ outDir, extensionVersion, extensionId, installUrl }) {
  if (!installUrl) return null;
  const policyPath = path.join(outDir, `promptwall-firefox-extension-v${extensionVersion}.extension-settings.json`);
  return writeJsonFile(policyPath, firefoxExtensionSettingsPolicy({ extensionId, installUrl }));
}

function validatePolicyExamples(root, checks, problems) {
  const schema = readJson(root, 'sensors/browser-extension/schema.json');
  const managed = readJson(root, 'docs/examples/browser-managed-storage.policy.json');
  const firefoxManaged = readJson(root, 'docs/examples/firefox-managed-storage.policy.json');
  const chromeSettings = readJson(root, 'docs/examples/chrome-extension-settings.example.json');
  const edgeSettings = readJson(root, 'docs/examples/edge-extension-settings.example.json');
  const firefoxSettings = readJson(root, 'docs/examples/firefox-extension-settings.example.json');
  const schemaKeys = new Set(Object.keys((schema && schema.properties) || {}));
  const managedKeys = Object.keys(managed || {});
  const chromeEntry = chromeSettings.ExtensionSettings && chromeSettings.ExtensionSettings['<extension-id>'];
  const edgeEntry = edgeSettings.ExtensionSettings && edgeSettings.ExtensionSettings['<extension-id>'];
  const firefoxEntry = firefoxSettings.policies
    && firefoxSettings.policies.ExtensionSettings
    && firefoxSettings.policies.ExtensionSettings[FIREFOX_EXTENSION_ID];
  const firefoxManagedValues = firefoxManaged.policies
    && firefoxManaged.policies['3rdparty']
    && firefoxManaged.policies['3rdparty'].Extensions
    && firefoxManaged.policies['3rdparty'].Extensions[FIREFOX_EXTENSION_ID];

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
    'chrome_force_install_policy_example',
    !!chromeEntry && chromeEntry.installation_mode === 'force_installed',
    'Chrome ExtensionSettings example force-installs the extension',
    problems,
  );
  requireCheck(
    checks,
    'chrome_web_store_update_url',
    !!chromeEntry && chromeEntry.update_url === CHROME_WEB_STORE_UPDATE_URL,
    'Chrome ExtensionSettings example uses the Chrome Web Store update URL',
    problems,
  );
  requireCheck(
    checks,
    'edge_force_install_policy_example',
    !!edgeEntry && edgeEntry.installation_mode === 'force_installed' && edgeEntry.update_url === EDGE_ADDONS_UPDATE_URL,
    'Edge ExtensionSettings example force-installs the extension from Edge Add-ons',
    problems,
  );
  requireCheck(
    checks,
    'firefox_force_install_policy_example',
    !!firefoxEntry && firefoxEntry.installation_mode === 'force_installed' && /^https:\/\//.test(firefoxEntry.install_url || ''),
    'Firefox policies example force-installs the extension from an HTTPS XPI URL',
    problems,
  );
  requireCheck(
    checks,
    'firefox_managed_storage_example',
    !!firefoxManagedValues && Object.keys(firefoxManagedValues).every((key) => schemaKeys.has(key)) && firefoxManagedValues.ingestKey === 'REPLACE_WITH_LONG_RANDOM_INGEST_KEY',
    'Firefox managed-storage policy uses schema-backed keys and a placeholder ingest key',
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
    /Browser extension release checklist/i.test(checklist)
      && /npm run release:extension:check/i.test(checklist)
      && /rollback/i.test(checklist),
    'release checklist covers browser-store visibility, readiness command, and rollback',
    problems,
  );
  requireCheck(
    checks,
    'managed_deployment_docs_reference_release_check',
    /release:extension:check/i.test(managedGuide) && /Chrome, Edge, and Firefox/i.test(managedGuide),
    'managed extension guide references the release readiness command and Chrome, Edge, and Firefox targets',
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
    requireCheck(checks, `package_${packageManifest.browserTarget}_${id}`, value === true, `${packageManifest.browserTarget} package manifest check ${id} is true`, problems);
  }
  requireCheck(
    checks,
    `package_${packageManifest.browserTarget}_kind`,
    packageManifest.kind === 'promptwall-browser-extension-package',
    `${packageManifest.browserTarget} package manifest has the expected kind`,
    problems,
  );
}

function validateReleasePackage(packaged, checks, problems) {
  const packageManifest = packaged.packageManifest;
  const packageManifestBody = fs.readFileSync(packaged.manifestPath, 'utf8');
  const zipBody = fs.readFileSync(packaged.zipPath);

  requireCheck(
    checks,
    `package_${packageManifest.browserTarget}_sha256_matches_zip`,
    packageManifest.sha256 === sha256(zipBody),
    `${packageManifest.browserTarget} package manifest SHA-256 matches the generated zip`,
    problems,
  );
  requireCheck(
    checks,
    `package_${packageManifest.browserTarget}_manifest_prompt_free`,
    !/524-71-9043|4111 1111|REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key/i.test(packageManifestBody),
    `${packageManifest.browserTarget} package manifest does not contain prompt bodies or secret placeholders`,
    problems,
  );
  validatePackageManifest(packageManifest, checks, problems);
}

function validateRenderedExtensionSettingsPolicy(policyPath, extensionId, checks, problems, target = 'chrome') {
  if (!policyPath) return;
  const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
  const entry = policy.ExtensionSettings && policy.ExtensionSettings[extensionId];
  const updateUrl = target === 'edge' ? EDGE_ADDONS_UPDATE_URL : CHROME_WEB_STORE_UPDATE_URL;
  requireCheck(
    checks,
    `generated_${target}_extension_settings_policy`,
    !!entry && entry.installation_mode === 'force_installed' && entry.update_url === updateUrl,
    `generated ${target} ExtensionSettings policy force-installs the supplied store id`,
    problems,
  );
  requireCheck(
    checks,
    `generated_${target}_extension_settings_prompt_free`,
    !/REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key|promptwall\.example\.org|524-71-9043|4111 1111/i.test(JSON.stringify(policy)),
    `generated ${target} ExtensionSettings policy contains no managed-storage secrets or prompt examples`,
    problems,
  );
}

function validateRenderedFirefoxPolicy(policyPath, checks, problems) {
  if (!policyPath) return;
  const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
  const entry = policy.policies && policy.policies.ExtensionSettings && policy.policies.ExtensionSettings[FIREFOX_EXTENSION_ID];
  requireCheck(
    checks,
    'generated_firefox_extension_settings_policy',
    !!entry && entry.installation_mode === 'force_installed' && /^https:\/\//.test(entry.install_url || ''),
    'generated Firefox ExtensionSettings policy force-installs the supplied HTTPS XPI URL',
    problems,
  );
  requireCheck(
    checks,
    'generated_firefox_extension_settings_prompt_free',
    !/REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key|promptwall\.example\.org|524-71-9043|4111 1111/i.test(JSON.stringify(policy)),
    'generated Firefox ExtensionSettings policy contains no managed-storage secrets or prompt examples',
    problems,
  );
}

function releaseReportFor({ now, extensionIdStatus, extensionId, edgeExtensionIdStatus, edgeExtensionId, firefoxInstallUrl, extensionSettingsPolicyPaths, packaged, checks, problems }) {
  const byTarget = Object.fromEntries(packaged.map((item) => [item.packageManifest.browserTarget, item]));
  return {
    kind: 'promptwall-extension-release-readiness',
    status: problems.length ? 'blocked' : 'ready',
    createdAt: now.toISOString(),
    extensionIdStatus,
    extensionId: extensionIdStatus === 'provided' ? extensionId : null,
    edgeExtensionIdStatus,
    edgeExtensionId: edgeExtensionIdStatus === 'provided' ? edgeExtensionId : null,
    firefoxInstallUrl: firefoxInstallUrl || null,
    extensionVersion: byTarget.chrome.packageManifest.extensionVersion,
    appVersion: byTarget.chrome.packageManifest.appVersion,
    packages: packaged.map((item) => ({
      browserTarget: item.packageManifest.browserTarget,
      packageName: path.basename(item.zipPath),
      packageManifest: path.basename(item.manifestPath),
      packageSha256: item.packageManifest.sha256,
      backgroundModel: item.packageManifest.backgroundModel,
    })),
    extensionSettingsPolicies: Object.fromEntries(
      Object.entries(extensionSettingsPolicyPaths)
        .filter(([, filePath]) => !!filePath)
        .map(([target, filePath]) => [target, path.basename(filePath)])
    ),
    browserStores: {
      chrome: {
        visibility: 'private_or_unlisted',
        updateUrl: CHROME_WEB_STORE_UPDATE_URL,
        reviewerNotesRequired: true,
      },
      edge: {
        visibility: 'private_or_unlisted',
        updateUrl: EDGE_ADDONS_UPDATE_URL,
        reviewerNotesRequired: true,
      },
      firefox: {
        visibility: 'unlisted_or_organization_scoped',
        extensionId: FIREFOX_EXTENSION_ID,
        installUrlRequiredForPolicy: true,
      },
    },
    policyExamples: [
      'docs/examples/chrome-extension-settings.example.json',
      'docs/examples/edge-extension-settings.example.json',
      'docs/examples/firefox-extension-settings.example.json',
      'docs/examples/browser-managed-storage.policy.json',
      'docs/examples/firefox-managed-storage.policy.json',
    ],
    requiredHandoffEvidence: [
      'Chrome Web Store, Microsoft Edge Add-ons, or Firefox package/listing chosen for the customer browser fleet',
      'Rendered browser-specific force-install policy for each browser in scope',
      'ExtensionSettings force-install policy exported from the customer OU or browser-management profile',
      'Managed storage policy with tenant URL, org id, and secret-bearing ingest key stored outside source control',
      'Coverage Fleet Install Health row showing browser_extension covered for a managed test user',
      'Rollback owner and prior extension version',
    ],
    checks,
    sources: [
      'https://support.google.com/chrome/a/answer/6306504',
      'https://developer.chrome.com/docs/webstore/cws-dashboard-distribution',
      'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-manage-extensions-policies',
      'https://github.com/mozilla/policy-templates/blob/master/README.md#extensionsettings',
    ],
  };
}

function checkExtensionRelease(opts = {}) {
  const root = opts.root || ROOT;
  const outDir = opts.outDir || path.join(root, 'dist', 'browser-extension');
  const now = opts.now || new Date();
  const extensionId = String(opts.extensionId || opts.chromeExtensionId || '').trim();
  const edgeExtensionId = String(opts.edgeExtensionId || '').trim();
  const firefoxInstallUrl = String(opts.firefoxInstallUrl || '').trim();
  const firefoxExtensionId = String(opts.firefoxExtensionId || FIREFOX_EXTENSION_ID).trim();
  const extensionIdStatus = validateExtensionId(extensionId);
  const edgeExtensionIdStatus = validateExtensionId(edgeExtensionId);
  if (firefoxExtensionId !== FIREFOX_EXTENSION_ID) {
    throw new Error(`Firefox extension id must match the packaged gecko id: ${FIREFOX_EXTENSION_ID}`);
  }
  if (firefoxInstallUrl && !/^https:\/\//.test(firefoxInstallUrl)) {
    throw new Error('Firefox install URL must be HTTPS');
  }
  const packaged = packageExtensions({ root, outDir, now, targets: BROWSER_TARGETS });
  const chromePolicyPath = extensionIdStatus === 'provided'
    ? writeExtensionSettingsPolicy({
      outDir,
      extensionVersion: packaged[0].packageManifest.extensionVersion,
      extensionId,
      target: 'chrome',
    })
    : null;
  const edgePolicyPath = edgeExtensionIdStatus === 'provided'
    ? writeExtensionSettingsPolicy({
      outDir,
      extensionVersion: packaged[0].packageManifest.extensionVersion,
      extensionId: edgeExtensionId,
      target: 'edge',
    })
    : null;
  const firefoxPolicyPath = writeFirefoxExtensionSettingsPolicy({
    outDir,
    extensionVersion: packaged[0].packageManifest.extensionVersion,
    extensionId: firefoxExtensionId,
    installUrl: firefoxInstallUrl,
  });
  const checks = {};
  const problems = [];

  for (const item of packaged) validateReleasePackage(item, checks, problems);
  validateRenderedExtensionSettingsPolicy(chromePolicyPath, extensionId, checks, problems, 'chrome');
  validateRenderedExtensionSettingsPolicy(edgePolicyPath, edgeExtensionId, checks, problems, 'edge');
  validateRenderedFirefoxPolicy(firefoxPolicyPath, checks, problems);
  validatePolicyExamples(root, checks, problems);
  validateDocs(root, checks, problems);

  const extensionSettingsPolicyPaths = { chrome: chromePolicyPath, edge: edgePolicyPath, firefox: firefoxPolicyPath };
  const releaseReport = releaseReportFor({
    now,
    extensionIdStatus,
    extensionId,
    edgeExtensionIdStatus,
    edgeExtensionId,
    firefoxInstallUrl,
    extensionSettingsPolicyPaths,
    packaged,
    checks,
    problems,
  });

  if (problems.length) {
    const err = new Error(`Extension release readiness failed: ${problems.join('; ')}`);
    err.problems = problems;
    err.report = releaseReport;
    throw err;
  }

  const reportPath = path.join(outDir, `promptwall-browser-extension-v${packaged[0].packageManifest.extensionVersion}.release-readiness.json`);
  fs.writeFileSync(reportPath, JSON.stringify(releaseReport, null, 2) + '\n');
  return {
    packages: packaged,
    zipPath: packaged[0].zipPath,
    manifestPath: packaged[0].manifestPath,
    extensionSettingsPolicyPath: chromePolicyPath,
    edgeExtensionSettingsPolicyPath: edgePolicyPath,
    firefoxExtensionSettingsPolicyPath: firefoxPolicyPath,
    reportPath,
    releaseReport,
  };
}

function parseArgs(argv) {
  const args = [...argv];
  let outDir = path.join(ROOT, 'dist', 'browser-extension');
  let extensionId = '';
  let edgeExtensionId = '';
  let firefoxInstallUrl = '';
  let firefoxExtensionId = FIREFOX_EXTENSION_ID;
  let json = false;
  const positionals = [];
  while (args.length) {
    const arg = args.shift();
    if (arg === '--out') {
      outDir = path.resolve(args.shift() || '');
    } else if (arg === '--extension-id') {
      extensionId = String(args.shift() || '').trim();
    } else if (arg === '--chrome-extension-id') {
      extensionId = String(args.shift() || '').trim();
    } else if (arg === '--edge-extension-id') {
      edgeExtensionId = String(args.shift() || '').trim();
    } else if (arg === '--firefox-install-url') {
      firefoxInstallUrl = String(args.shift() || '').trim();
    } else if (arg === '--firefox-extension-id') {
      firefoxExtensionId = String(args.shift() || '').trim();
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--help' || arg === '-h') {
      return { help: true, outDir, extensionId, edgeExtensionId, firefoxInstallUrl, firefoxExtensionId, json };
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
  if (positionals[0]) outDir = path.resolve(positionals[0]);
  if (positionals[1] && !extensionId) extensionId = String(positionals[1]).trim();
  if (positionals.length > 2) throw new Error('Too many positional arguments');
  return { outDir, extensionId, edgeExtensionId, firefoxInstallUrl, firefoxExtensionId, json };
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      console.log('Usage: node scripts/check-extension-release.js [--out <directory>] [--chrome-extension-id <id>] [--edge-extension-id <id>] [--firefox-install-url <https-url>] [--json]');
      console.log('   or: node scripts/check-extension-release.js [directory] [chrome-web-store-id]');
      return;
    }
    const result = checkExtensionRelease({
      outDir: args.outDir,
      extensionId: args.extensionId,
      edgeExtensionId: args.edgeExtensionId,
      firefoxInstallUrl: args.firefoxInstallUrl,
      firefoxExtensionId: args.firefoxExtensionId,
    });
    if (args.json) {
      console.log(JSON.stringify(result.releaseReport, null, 2));
      return;
    }
    for (const packaged of result.packages) {
      console.log(`Wrote ${packaged.zipPath}`);
      console.log(`Wrote ${packaged.manifestPath}`);
    }
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
  EDGE_ADDONS_UPDATE_URL,
  FIREFOX_EXTENSION_ID,
  checkExtensionRelease,
  edgeExtensionSettingsPolicy,
  extensionSettingsPolicy,
  firefoxExtensionSettingsPolicy,
  parseArgs,
  validateExtensionId,
};
