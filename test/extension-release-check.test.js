'use strict';
/** Extension release readiness must be prompt-free and enterprise-policy aligned. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  CHROME_WEB_STORE_UPDATE_URL,
  EDGE_ADDONS_UPDATE_URL,
  FIREFOX_EXTENSION_ID,
  checkExtensionRelease,
  edgeExtensionSettingsPolicy,
  extensionSettingsPolicy,
  firefoxExtensionSettingsPolicy,
  main,
  parseArgs,
  validateExtensionId,
} = require('../scripts/check-extension-release');

function tempDir(t, prefix = 'ps-extension-release-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(['log', message]); },
    error(message) { lines.push(['error', message]); },
  };
}

function releaseRootFixture(t) {
  const sourceRoot = path.join(__dirname, '..');
  const root = tempDir(t, 'ps-extension-release-root-');
  fs.mkdirSync(path.join(root, 'sensors'), { recursive: true });
  fs.mkdirSync(path.join(root, 'docs', 'examples'), { recursive: true });
  fs.copyFileSync(path.join(sourceRoot, 'package.json'), path.join(root, 'package.json'));
  fs.cpSync(path.join(sourceRoot, 'detection-engine'), path.join(root, 'detection-engine'), { recursive: true });
  fs.cpSync(
    path.join(sourceRoot, 'sensors', 'browser-extension'),
    path.join(root, 'sensors', 'browser-extension'),
    { recursive: true },
  );
  for (const relPath of [
    'docs/MANAGED_EXTENSION_DEPLOYMENT.md',
    'docs/EXTENSION_RELEASE_CHECKLIST.md',
    'docs/TECHNICIAN_DEPLOYMENT_GUIDE.md',
    'docs/examples/browser-managed-storage.policy.json',
    'docs/examples/firefox-managed-storage.policy.json',
    'docs/examples/chrome-extension-settings.example.json',
    'docs/examples/edge-extension-settings.example.json',
    'docs/examples/firefox-extension-settings.example.json',
  ]) {
    fs.copyFileSync(path.join(sourceRoot, relPath), path.join(root, relPath));
  }
  return root;
}

test('release checker writes a prompt-free readiness report', (t) => {
  const outDir = tempDir(t);
  const result = checkExtensionRelease({
    outDir,
    now: new Date('2026-06-28T12:00:00.000Z'),
  });
  assert.ok(fs.existsSync(result.zipPath));
  assert.ok(fs.existsSync(result.manifestPath));
  assert.ok(fs.existsSync(result.reportPath));
  assert.strictEqual(result.releaseReport.kind, 'promptwall-extension-release-readiness');
  assert.strictEqual(result.releaseReport.status, 'ready');
  assert.deepStrictEqual(result.releaseReport.packages.map((item) => item.browserTarget), ['chrome', 'edge', 'firefox']);
  assert.strictEqual(result.releaseReport.browserStores.chrome.updateUrl, CHROME_WEB_STORE_UPDATE_URL);
  assert.strictEqual(result.releaseReport.browserStores.edge.updateUrl, EDGE_ADDONS_UPDATE_URL);
  assert.strictEqual(result.releaseReport.browserStores.firefox.extensionId, FIREFOX_EXTENSION_ID);
  assert.strictEqual(result.releaseReport.extensionIdStatus, 'pending_store_upload');
  assert.strictEqual(result.releaseReport.edgeExtensionIdStatus, 'pending_store_upload');
  assert.ok(result.releaseReport.requiredHandoffEvidence.some((item) => /Fleet Install Health/.test(item)));
  assert.ok(Object.values(result.releaseReport.checks).every((check) => check.passed === true));

  const wire = fs.readFileSync(result.reportPath, 'utf8');
  assert.doesNotMatch(wire, /REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key/);
  assert.doesNotMatch(wire, /524-71-9043|4111 1111|contains member SSN/i);
});

test('release checker writes final Chromium force-install policies when ids are supplied', (t) => {
  const outDir = tempDir(t);
  const extensionId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const edgeExtensionId = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const result = checkExtensionRelease({
    outDir,
    extensionId,
    edgeExtensionId,
    now: new Date('2026-06-28T12:00:00.000Z'),
  });
  assert.ok(fs.existsSync(result.extensionSettingsPolicyPath));
  assert.ok(fs.existsSync(result.edgeExtensionSettingsPolicyPath));
  assert.strictEqual(result.releaseReport.extensionIdStatus, 'provided');
  assert.strictEqual(result.releaseReport.extensionId, extensionId);
  assert.strictEqual(result.releaseReport.edgeExtensionIdStatus, 'provided');
  assert.strictEqual(result.releaseReport.edgeExtensionId, edgeExtensionId);
  assert.strictEqual(result.releaseReport.extensionSettingsPolicies.chrome, path.basename(result.extensionSettingsPolicyPath));
  assert.strictEqual(result.releaseReport.extensionSettingsPolicies.edge, path.basename(result.edgeExtensionSettingsPolicyPath));
  assert.strictEqual(result.releaseReport.checks.generated_chrome_extension_settings_policy.passed, true);
  assert.strictEqual(result.releaseReport.checks.generated_chrome_extension_settings_prompt_free.passed, true);
  assert.strictEqual(result.releaseReport.checks.generated_edge_extension_settings_policy.passed, true);

  const policy = JSON.parse(fs.readFileSync(result.extensionSettingsPolicyPath, 'utf8'));
  assert.deepStrictEqual(policy, extensionSettingsPolicy(extensionId));
  assert.strictEqual(policy.ExtensionSettings[extensionId].installation_mode, 'force_installed');
  assert.strictEqual(policy.ExtensionSettings[extensionId].update_url, CHROME_WEB_STORE_UPDATE_URL);
  assert.doesNotMatch(JSON.stringify(policy), /REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key|promptwall\.example\.org/i);

  const edgePolicy = JSON.parse(fs.readFileSync(result.edgeExtensionSettingsPolicyPath, 'utf8'));
  assert.deepStrictEqual(edgePolicy, edgeExtensionSettingsPolicy(edgeExtensionId));
  assert.strictEqual(edgePolicy.ExtensionSettings[edgeExtensionId].update_url, EDGE_ADDONS_UPDATE_URL);
});

test('release checker writes Firefox force-install policy when HTTPS install URL is supplied', (t) => {
  const outDir = tempDir(t);
  const installUrl = 'https://downloads.customer.example/promptwall-firefox.xpi';
  const result = checkExtensionRelease({
    outDir,
    firefoxInstallUrl: installUrl,
    now: new Date('2026-06-28T12:00:00.000Z'),
  });
  assert.ok(fs.existsSync(result.firefoxExtensionSettingsPolicyPath));
  assert.strictEqual(result.releaseReport.extensionSettingsPolicies.firefox, path.basename(result.firefoxExtensionSettingsPolicyPath));
  assert.strictEqual(result.releaseReport.checks.generated_firefox_extension_settings_policy.passed, true);

  const policy = JSON.parse(fs.readFileSync(result.firefoxExtensionSettingsPolicyPath, 'utf8'));
  assert.deepStrictEqual(policy, firefoxExtensionSettingsPolicy({ extensionId: FIREFOX_EXTENSION_ID, installUrl }));
});

test('release checker accepts only Chromium extension id shape', () => {
  assert.strictEqual(validateExtensionId('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), 'provided');
  assert.strictEqual(validateExtensionId(''), 'pending_store_upload');
  assert.throws(() => validateExtensionId('abc123'), /Chromium extension id/);
  assert.throws(() => validateExtensionId('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'), /Chromium extension id/);
});

test('release checker rejects mismatched Firefox policy metadata before packaging', (t) => {
  const outDir = tempDir(t);
  assert.throws(
    () => checkExtensionRelease({ outDir, firefoxExtensionId: 'different@example.com' }),
    /Firefox extension id must match/,
  );
  assert.throws(
    () => checkExtensionRelease({ outDir, firefoxInstallUrl: 'http://downloads.customer.example/promptwall.xpi' }),
    /must be HTTPS/,
  );
});

test('release checker returns a blocked report when release examples drift', (t) => {
  const root = releaseRootFixture(t);
  const outDir = path.join(root, 'dist', 'browser-extension');
  fs.writeFileSync(
    path.join(root, 'docs', 'examples', 'browser-managed-storage.policy.json'),
    JSON.stringify({
      serverUrl: 'https://promptwall.example.test',
      ingestKey: 'not-the-placeholder',
      orgId: 'credit-union-1',
    }, null, 2) + '\n',
  );

  assert.throws(
    () => checkExtensionRelease({ root, outDir }),
    (err) => {
      assert.match(err.message, /Extension release readiness failed/);
      assert.ok(err.problems.some((problem) => /managed_storage_uses_placeholder_secret/.test(problem)));
      assert.strictEqual(err.report.status, 'blocked');
      assert.strictEqual(err.report.checks.managed_storage_uses_placeholder_secret.passed, false);
      assert.doesNotMatch(JSON.stringify(err.report), /not-the-placeholder/);
      return true;
    },
  );
});

test('release checker cli args parse output, id, and json mode', () => {
  const parsed = parseArgs([
    '--out',
    'tmp-release',
    '--chrome-extension-id',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '--edge-extension-id',
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    '--firefox-install-url',
    'https://downloads.customer.example/promptwall.xpi',
    '--json',
  ]);
  assert.strictEqual(path.basename(parsed.outDir), 'tmp-release');
  assert.strictEqual(parsed.extensionId, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.strictEqual(parsed.edgeExtensionId, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
  assert.strictEqual(parsed.firefoxInstallUrl, 'https://downloads.customer.example/promptwall.xpi');
  assert.strictEqual(parsed.json, true);

  const npmStyle = parseArgs(['tmp-release', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']);
  assert.strictEqual(path.basename(npmStyle.outDir), 'tmp-release');
  assert.strictEqual(npmStyle.extensionId, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

  const alias = parseArgs([
    '--extension-id',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '--firefox-extension-id',
    FIREFOX_EXTENSION_ID,
  ]);
  assert.strictEqual(alias.extensionId, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.strictEqual(alias.firefoxExtensionId, FIREFOX_EXTENSION_ID);

  assert.strictEqual(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs(['--bogus']), /Unknown option/);
  assert.throws(() => parseArgs(['one', 'two', 'three']), /Too many positional/);
});

test('release checker main prints help, JSON, text summaries, and sanitized errors', () => {
  const helpIo = captureConsole();
  main(['--help'], { console: helpIo });
  assert.ok(helpIo.lines.some(([, message]) => /Usage: node/.test(message)));

  const result = {
    packages: [
      { zipPath: 'dist/chrome.zip', manifestPath: 'dist/chrome.manifest.json' },
      { zipPath: 'dist/edge.zip', manifestPath: 'dist/edge.manifest.json' },
    ],
    reportPath: 'dist/release-readiness.json',
    releaseReport: { status: 'ready', packages: [] },
  };

  const jsonIo = captureConsole();
  main(['--json'], {
    console: jsonIo,
    checkExtensionRelease(opts) {
      assert.strictEqual(opts.firefoxExtensionId, FIREFOX_EXTENSION_ID);
      return result;
    },
  });
  assert.deepStrictEqual(JSON.parse(jsonIo.lines[0][1]), result.releaseReport);

  const textIo = captureConsole();
  main([], {
    console: textIo,
    checkExtensionRelease: () => result,
  });
  assert.ok(textIo.lines.some(([, message]) => /Wrote dist\/chrome\.zip/.test(message)));
  assert.ok(textIo.lines.some(([, message]) => /Release readiness ready/.test(message)));

  let exitCode = 0;
  const errorIo = captureConsole();
  main(['--bogus'], {
    console: errorIo,
    setExitCode(code) { exitCode = code; },
  });
  assert.strictEqual(exitCode, 1);
  assert.ok(errorIo.lines.some(([level, message]) => level === 'error' && /Unknown option/.test(message)));
});
