'use strict';
/** Endpoint agent package must be pilot-ready and prompt-free. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const AdmZip = require('adm-zip');

const {
  packageEndpointAgent,
  parseArgs,
  sha256,
  validateRuntimeFiles,
} = require('../scripts/package-endpoint-agent');

const root = path.join(__dirname, '..');

function tempDir(t, prefix = 'ps-endpoint-agent-package-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function minimalFiles(agentBody) {
  return [
    { path: 'package.json', body: Buffer.from('{"version":"0.0.0"}') },
    { path: 'package-lock.json', body: Buffer.from('{}') },
    { path: 'shared/detect.js', body: Buffer.from('module.exports = {};') },
    { path: 'src/env.js', body: Buffer.from('module.exports = {};') },
    { path: 'src/policy.js', body: Buffer.from('module.exports = {};') },
    { path: 'src/processors.js', body: Buffer.from('module.exports = {};') },
    { path: 'endpoint-agent/agent.js', body: Buffer.from(agentBody) },
    {
      path: 'scripts/install-endpoint-agent.ps1',
      body: Buffer.from('[Parameter(Mandatory = $true)]\n[string]$IngestKey\n$taskArgs = "-File runner.ps1"\n'),
    },
    {
      path: 'scripts/run-endpoint-agent.ps1',
      body: Buffer.from('$env:SENTINEL_ENV_PATH = $config\n'),
    },
    { path: 'scripts/uninstall-endpoint-agent.ps1', body: Buffer.from('Unregister-ScheduledTask\n') },
  ];
}

test('package script writes a prompt-free endpoint agent zip and integrity manifest', (t) => {
  const outDir = tempDir(t);
  const result = packageEndpointAgent({ outDir, now: new Date('2026-06-26T12:00:00.000Z') });
  assert.ok(fs.existsSync(result.zipPath));
  assert.ok(fs.existsSync(result.manifestPath));

  const manifest = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8'));
  const zipBody = fs.readFileSync(result.zipPath);
  assert.strictEqual(manifest.kind, 'promptsentinel-endpoint-agent-package');
  assert.strictEqual(manifest.sha256, sha256(zipBody));
  assert.strictEqual(manifest.appVersion, JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version);
  assert.strictEqual(manifest.checks.explicitIngestKeyRequired, true);
  assert.strictEqual(manifest.checks.localDetectionEngineIncluded, true);
  assert.strictEqual(manifest.checks.scheduledTaskInstallerIncluded, true);
  assert.strictEqual(manifest.checks.localConfigEnvPath, true);
  assert.strictEqual(manifest.checks.taskArgsDoNotExposeIngestKey, true);
  assert.strictEqual(manifest.checks.developmentIngestKeyAbsent, true);
  assert.strictEqual(manifest.checks.promptBodiesAbsent, true);

  const zip = new AdmZip(result.zipPath);
  const entries = zip.getEntries().map((entry) => entry.entryName).sort();
  for (const required of [
    'package.json',
    'package-lock.json',
    'shared/detect.js',
    'src/env.js',
    'src/policy.js',
    'src/processors.js',
    'endpoint-agent/agent.js',
    'scripts/install-endpoint-agent.ps1',
    'scripts/run-endpoint-agent.ps1',
    'scripts/uninstall-endpoint-agent.ps1',
  ]) {
    assert.ok(entries.includes(required), required);
    assert.ok(manifest.files.some((file) => file.path === required), required);
  }

  const agent = zip.readAsText('endpoint-agent/agent.js');
  assert.match(agent, /process\.env\.INGEST_API_KEY \|\| ''/);
  assert.doesNotMatch(agent, /dev-ingest-key|524-71-9043|4111 1111 1111 1111/);
  assert.doesNotMatch(JSON.stringify(manifest), /prompt\s*:/i);
  assert.doesNotMatch(JSON.stringify(manifest), /524-71-9043|4111 1111|REPLACE_WITH_LONG_RANDOM_INGEST_KEY/);
});

test('package validation refuses prompt bodies or development keys', () => {
  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';")),
    /development ingest key/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nconst sample = '524-71-9043';")),
    /synthetic SSN demo value/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nconst path = '/api/v1/scan-file';\nconst contentBase64 = 'abc';")),
    /without uploading file bodies/
  );
});

test('package args support explicit output directories', () => {
  const parsed = parseArgs(['--out', 'dist/custom-endpoint']);
  assert.match(parsed.outDir, /dist[\\/]custom-endpoint$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
});
