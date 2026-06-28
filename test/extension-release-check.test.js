'use strict';
/** Extension release readiness must be prompt-free and enterprise-policy aligned. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  CHROME_WEB_STORE_UPDATE_URL,
  checkExtensionRelease,
  extensionSettingsPolicy,
  parseArgs,
  validateExtensionId,
} = require('../scripts/check-extension-release');

function tempDir(t, prefix = 'ps-extension-release-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
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
  assert.strictEqual(result.releaseReport.chromeWebStore.updateUrl, CHROME_WEB_STORE_UPDATE_URL);
  assert.strictEqual(result.releaseReport.extensionIdStatus, 'pending_chrome_web_store_upload');
  assert.ok(result.releaseReport.requiredHandoffEvidence.some((item) => /Fleet Install Health/.test(item)));
  assert.ok(Object.values(result.releaseReport.checks).every((check) => check.passed === true));

  const wire = fs.readFileSync(result.reportPath, 'utf8');
  assert.doesNotMatch(wire, /REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key/);
  assert.doesNotMatch(wire, /524-71-9043|4111 1111|contains member SSN/i);
});

test('release checker writes final force-install policy when extension id is supplied', (t) => {
  const outDir = tempDir(t);
  const extensionId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const result = checkExtensionRelease({
    outDir,
    extensionId,
    now: new Date('2026-06-28T12:00:00.000Z'),
  });
  assert.ok(fs.existsSync(result.extensionSettingsPolicyPath));
  assert.strictEqual(result.releaseReport.extensionIdStatus, 'provided');
  assert.strictEqual(result.releaseReport.extensionId, extensionId);
  assert.strictEqual(result.releaseReport.extensionSettingsPolicy, path.basename(result.extensionSettingsPolicyPath));
  assert.strictEqual(result.releaseReport.checks.generated_extension_settings_policy.passed, true);
  assert.strictEqual(result.releaseReport.checks.generated_extension_settings_prompt_free.passed, true);

  const policy = JSON.parse(fs.readFileSync(result.extensionSettingsPolicyPath, 'utf8'));
  assert.deepStrictEqual(policy, extensionSettingsPolicy(extensionId));
  assert.strictEqual(policy.ExtensionSettings[extensionId].installation_mode, 'force_installed');
  assert.strictEqual(policy.ExtensionSettings[extensionId].update_url, CHROME_WEB_STORE_UPDATE_URL);
  assert.doesNotMatch(JSON.stringify(policy), /REPLACE_WITH_LONG_RANDOM_INGEST_KEY|dev-ingest-key|promptwall\.example\.org/i);
});

test('release checker accepts only Chrome Web Store extension id shape', () => {
  assert.strictEqual(validateExtensionId('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), 'provided');
  assert.strictEqual(validateExtensionId(''), 'pending_chrome_web_store_upload');
  assert.throws(() => validateExtensionId('abc123'), /Chrome extension id/);
  assert.throws(() => validateExtensionId('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'), /Chrome extension id/);
});

test('release checker cli args parse output, id, and json mode', () => {
  const parsed = parseArgs(['--out', 'tmp-release', '--extension-id', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '--json']);
  assert.strictEqual(path.basename(parsed.outDir), 'tmp-release');
  assert.strictEqual(parsed.extensionId, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.strictEqual(parsed.json, true);

  const npmStyle = parseArgs(['tmp-release', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']);
  assert.strictEqual(path.basename(npmStyle.outDir), 'tmp-release');
  assert.strictEqual(npmStyle.extensionId, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
});
