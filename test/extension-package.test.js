'use strict';
/** Browser extension packages must be pilot-ready and verifiable. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const AdmZip = require('adm-zip');

const {
  BROWSER_TARGETS,
  manifestForTarget,
  packageExtension,
  packageExtensions,
  sha256,
} = require('../scripts/package-extension');

const root = path.join(__dirname, '..');

function tempDir(t, prefix = 'ps-extension-package-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function writeFile(file, body) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
}

function writeJson(file, value) {
  writeFile(file, JSON.stringify(value, null, 2) + '\n');
}

function writeFixture(rootDir, opts = {}) {
  const version = '9.9.9';
  writeJson(path.join(rootDir, 'package.json'), { version });
  writeFile(path.join(rootDir, 'detection-engine', 'detect.js'), 'const detector = 1;\n');
  writeFile(path.join(rootDir, 'detection-engine', 'adapters.js'), 'const adapters = 1;\n');
  writeFile(path.join(rootDir, 'sensors', 'browser-extension', 'lib', 'detect.js'), opts.drift ? 'const detector = 2;\n' : 'const detector = 1;\n');
  writeFile(path.join(rootDir, 'sensors', 'browser-extension', 'lib', 'adapters.js'), 'const adapters = 1;\n');
  writeFile(path.join(rootDir, 'sensors', 'browser-extension', 'background.js'), opts.devKey
    ? "const api = '/api/v1/heartbeat';\nfunction buildInstallChecks() {}\nconst check = 'managed_identity';\nconst ingestKey = 'dev-ingest-key';\n"
    : "const api = '/api/v1/heartbeat';\nfunction buildInstallChecks() {}\nconst check = 'managed_identity';\n");
  writeFile(path.join(rootDir, 'sensors', 'browser-extension', 'lib', 'browser-api.js'), 'globalThis.PWBrowserApi = {};\n');
  writeFile(path.join(rootDir, 'sensors', 'browser-extension', 'content.js'), 'console.log("content");\n');
  writeFile(path.join(rootDir, 'sensors', 'browser-extension', 'content.css'), 'body { color: black; }\n');
  writeFile(path.join(rootDir, 'sensors', 'browser-extension', 'popup.html'), '<html></html>\n');
  writeJson(path.join(rootDir, 'sensors', 'browser-extension', 'schema.json'), {
    type: 'object',
    properties: {
      serverUrl: { type: 'string' },
      ingestKey: { type: 'string' },
      orgId: { type: 'string' },
    },
  });
  writeJson(path.join(rootDir, 'sensors', 'browser-extension', 'manifest.json'), {
    manifest_version: 3,
    name: 'PromptWall',
    version,
    description: 'Fixture package',
    permissions: ['storage'],
    host_permissions: ['https://chatgpt.com/*'],
    background: { service_worker: 'background.js' },
    storage: { managed_schema: 'schema.json' },
    action: { default_popup: 'popup.html' },
    content_scripts: [{
      matches: ['https://chatgpt.com/*'],
      js: ['lib/browser-api.js', 'lib/detect.js', 'lib/adapters.js', 'content.js'],
      css: ['content.css'],
    }],
  });
}

test('package script writes browser target zips and prompt-free integrity manifests', (t) => {
  const outDir = tempDir(t);
  const results = packageExtensions({ outDir, now: new Date('2026-06-26T12:00:00.000Z') });
  assert.deepStrictEqual(results.map((item) => item.packageManifest.browserTarget), BROWSER_TARGETS);
  const result = results.find((item) => item.packageManifest.browserTarget === 'chrome');
  assert.ok(fs.existsSync(result.zipPath));
  assert.ok(fs.existsSync(result.manifestPath));

  const manifest = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8'));
  const zipBody = fs.readFileSync(result.zipPath);
  assert.strictEqual(manifest.kind, 'promptwall-browser-extension-package');
  assert.strictEqual(manifest.browserTarget, 'chrome');
  assert.strictEqual(manifest.sha256, sha256(zipBody));
  assert.strictEqual(manifest.extensionVersion, JSON.parse(fs.readFileSync(path.join(root, 'sensors', 'browser-extension', 'manifest.json'), 'utf8')).version);
  assert.strictEqual(manifest.appVersion, JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version);
  assert.strictEqual(manifest.checks.manifestV3, true);
  assert.strictEqual(manifest.checks.browserTargetManifest, true);
  assert.strictEqual(manifest.checks.syncedEngine, true);
  assert.strictEqual(manifest.checks.browserApiBridgeIncluded, true);
  assert.strictEqual(manifest.checks.installValidationIncluded, true);
  assert.strictEqual(manifest.checks.developmentIngestKeyAbsent, true);

  const zip = new AdmZip(result.zipPath);
  const entries = zip.getEntries().map((entry) => entry.entryName).sort();
  for (const required of ['manifest.json', 'background.js', 'content.js', 'content.css', 'popup.html', 'popup.js', 'schema.json', 'lib/browser-api.js', 'lib/detect.js', 'lib/adapters.js']) {
    assert.ok(entries.includes(required), required);
    assert.ok(manifest.files.some((file) => file.path === required), required);
  }

  const background = zip.readAsText('background.js');
  assert.match(background, /\/api\/v1\/heartbeat/);
  assert.match(background, /buildInstallChecks/);
  assert.doesNotMatch(background, /dev-ingest-key/);
  assert.doesNotMatch(JSON.stringify(manifest), /prompt\s*:/i);
  assert.doesNotMatch(JSON.stringify(manifest), /524-71-9043|4111 1111|REPLACE_WITH_LONG_RANDOM_INGEST_KEY/);
});

test('Firefox target manifest uses gecko id and background scripts', () => {
  const source = JSON.parse(fs.readFileSync(path.join(root, 'sensors', 'browser-extension', 'manifest.json'), 'utf8'));
  const manifest = manifestForTarget(source, 'firefox');
  assert.deepStrictEqual(manifest.background, { scripts: ['background.js'] });
  assert.strictEqual(manifest.browser_specific_settings.gecko.id, 'promptwall@example.com');
  assert.ok(manifest.content_scripts[0].js.includes('lib/browser-api.js'));
});

test('package script refuses synced engine drift', (t) => {
  const fixture = tempDir(t, 'ps-extension-drift-');
  writeFixture(fixture, { drift: true });
  assert.throws(
    () => packageExtension({ root: fixture, outDir: path.join(fixture, 'out') }),
    /Synced engine copy drifted/
  );
});

test('package script refuses packaged development ingest keys', (t) => {
  const fixture = tempDir(t, 'ps-extension-dev-key-');
  writeFixture(fixture, { devKey: true });
  assert.throws(
    () => packageExtension({ root: fixture, outDir: path.join(fixture, 'out') }),
    /development ingest key/
  );
});
