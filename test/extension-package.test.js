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
  backgroundModel,
  collectExtensionFiles,
  main,
  manifestForTarget,
  packageExtension,
  packageExtensions,
  parseArgs,
  sha256,
  validateManifest,
  validatePackageContents,
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
    name: 'RedactWall',
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
  assert.strictEqual(manifest.kind, 'redactwall-browser-extension-package');
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
  assert.strictEqual(manifest.browser_specific_settings.gecko.id, 'redactwall@example.com');
  assert.ok(manifest.content_scripts[0].js.includes('lib/browser-api.js'));
  assert.strictEqual(backgroundModel(manifest), 'background_scripts');
  assert.strictEqual(backgroundModel({}), 'missing');
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

function validManifest() {
  return {
    manifest_version: 3,
    name: 'RedactWall',
    version: '9.9.9',
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
  };
}

function validPackageFiles() {
  return [
    'manifest.json',
    'background.js',
    'schema.json',
    'popup.html',
    'lib/browser-api.js',
    'lib/detect.js',
    'lib/adapters.js',
    'content.js',
    'content.css',
  ].map((relPath) => ({ relPath }));
}

test('manifest validation covers browser target and managed-install guardrails', () => {
  const manifest = validManifest();
  const files = validPackageFiles();
  const schema = { properties: { serverUrl: {}, ingestKey: {}, orgId: {} } };
  assert.doesNotThrow(() => validateManifest({ manifest, schema, appVersion: '9.9.9', files }));
  assert.doesNotThrow(() => validateManifest({
    manifest: manifestForTarget(manifest, 'firefox'),
    schema,
    appVersion: '9.9.9',
    files,
    target: 'firefox',
  }));
  assert.throws(() => manifestForTarget(manifest, 'safari'), /Unsupported extension target/);

  const cases = [
    {
      name: 'manifest version',
      manifest: { ...manifest, manifest_version: 2 },
      message: /manifest_version must be 3/,
    },
    {
      name: 'missing metadata',
      manifest: { ...manifest, description: '' },
      message: /must include name, version, and description/,
    },
    {
      name: 'version mismatch',
      manifest: { ...manifest, version: '9.9.8' },
      message: /must match app version/,
    },
    {
      name: 'broad host permission',
      manifest: { ...manifest, host_permissions: ['<all_urls>'] },
      message: /must not request <all_urls>/,
    },
    {
      name: 'missing background declaration',
      manifest: { ...manifest, background: {} },
      message: /must include a background worker or script/,
    },
    {
      name: 'missing background file',
      files: files.filter((file) => file.relPath !== 'background.js'),
      message: /missing background\.js/,
    },
    {
      name: 'missing popup file',
      files: files.filter((file) => file.relPath !== 'popup.html'),
      message: /missing popup\.html/,
    },
    {
      name: 'missing schema file',
      files: files.filter((file) => file.relPath !== 'schema.json'),
      message: /missing schema\.json/,
    },
    {
      name: 'missing content script',
      files: files.filter((file) => file.relPath !== 'content.js'),
      message: /missing content\.js/,
    },
    {
      name: 'missing content stylesheet',
      files: files.filter((file) => file.relPath !== 'content.css'),
      message: /missing content\.css/,
    },
    {
      name: 'missing matches',
      manifest: { ...manifest, content_scripts: [{ js: ['lib/browser-api.js'], css: [] }] },
      message: /must declare match patterns/,
    },
    {
      name: 'missing browser API bridge',
      manifest: { ...manifest, content_scripts: [{ matches: ['https://chatgpt.com/*'], js: ['content.js'], css: [] }] },
      message: /must load lib\/browser-api\.js/,
    },
    {
      name: 'missing managed schema key',
      schema: { properties: { serverUrl: {}, orgId: {} } },
      message: /Managed storage schema is missing ingestKey/,
    },
    {
      name: 'firefox gecko id',
      manifest: { ...manifest, background: { scripts: ['background.js'] } },
      target: 'firefox',
      message: /Firefox package must include browser_specific_settings\.gecko\.id/,
    },
  ];

  for (const item of cases) {
    assert.throws(() => validateManifest({
      manifest: item.manifest || manifest,
      schema: item.schema || schema,
      appVersion: '9.9.9',
      files: item.files || files,
      target: item.target || 'chrome',
    }), item.message, item.name);
  }
});

test('package content validation covers hidden files and unsafe packaged values', (t) => {
  const fixture = tempDir(t, 'ps-extension-content-validation-');
  writeFixture(fixture);
  writeFile(path.join(fixture, 'sensors', 'browser-extension', '.DS_Store'), 'metadata');
  writeFile(path.join(fixture, 'sensors', 'browser-extension', 'nested', 'note.txt'), 'ok');
  const files = collectExtensionFiles(path.join(fixture, 'sensors', 'browser-extension'));
  assert.ok(files.some((file) => file.relPath === 'nested/note.txt'));
  assert.ok(!files.some((file) => file.relPath === '.DS_Store'));
  assert.doesNotThrow(() => validatePackageContents(files));

  assert.throws(
    () => validatePackageContents(files.filter((file) => file.relPath !== 'background.js')),
    /missing background\.js/
  );

  writeFile(path.join(fixture, 'sensors', 'browser-extension', 'background.js'), 'function buildInstallChecks() {}');
  assert.throws(
    () => validatePackageContents(collectExtensionFiles(path.join(fixture, 'sensors', 'browser-extension'))),
    /install validation with heartbeat/
  );

  writeFile(path.join(fixture, 'sensors', 'browser-extension', 'background.js'), "const api = '/api/v1/heartbeat';\nfunction buildInstallChecks() {}\nconst check = 'managed_identity';\n");
  writeFile(path.join(fixture, 'sensors', 'browser-extension', 'content.js'), 'const INGEST_API_KEY = "packaged-secret";\n');
  assert.throws(
    () => validatePackageContents(collectExtensionFiles(path.join(fixture, 'sensors', 'browser-extension'))),
    /environment assignment/
  );
});

test('extension packaging CLI parses targets and reports injected results', () => {
  const parsed = parseArgs(['--out', 'dist/ext', '--target', 'firefox']);
  assert.match(parsed.outDir, /dist[\\/]ext$/);
  assert.strictEqual(parsed.target, 'firefox');
  assert.match(parseArgs(['dist/positional-ext']).outDir, /dist[\\/]positional-ext$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs(['--target', 'safari']), /Unsupported extension target/);
  assert.throws(() => parseArgs(['--bad']), /Unknown option: --bad/);

  const logs = [];
  const errors = [];
  const exits = [];
  const io = {
    log: (line) => logs.push(String(line)),
    error: (line) => errors.push(String(line)),
  };
  const fakePackage = ({ outDir, target }) => ({
    zipPath: path.join(outDir, `${target}.zip`),
    manifestPath: path.join(outDir, `${target}.manifest.json`),
    packageManifest: { sha256: `${target}-sha` },
  });
  const one = main(['--out', 'dist/ext', '--target', 'edge'], {
    console: io,
    setExitCode: (code) => exits.push(code),
    packageExtension: fakePackage,
  });
  assert.strictEqual(one.length, 1);
  assert.match(one[0].zipPath, /edge\.zip$/);
  assert.ok(logs.some((line) => /edge-sha/.test(line)));

  const all = main(['--out', 'dist/ext'], {
    console: io,
    setExitCode: (code) => exits.push(code),
    packageExtensions: ({ outDir }) => BROWSER_TARGETS.map((target) => fakePackage({ outDir, target })),
  });
  assert.strictEqual(all.length, BROWSER_TARGETS.length);

  assert.deepStrictEqual(main(['--help'], { console: io, setExitCode: (code) => exits.push(code) }), []);
  assert.deepStrictEqual(main(['--target', 'safari'], { console: io, setExitCode: (code) => exits.push(code) }), []);
  assert.ok(errors.some((line) => /Unsupported extension target/.test(line)));
  assert.ok(exits.includes(1));
});
