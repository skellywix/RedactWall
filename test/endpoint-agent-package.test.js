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
  assert.strictEqual(manifest.checks.endpointRedactionHandoffIncluded, true);
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
  assert.match(agent, /redacted_available/);
  assert.match(agent, /\.promptsentinel-redacted/);
  assert.doesNotMatch(agent, /dev-ingest-key|524-71-9043|4111 1111 1111 1111/);
  assert.doesNotMatch(JSON.stringify(manifest), /prompt\s*:/i);
  assert.doesNotMatch(JSON.stringify(manifest), /524-71-9043|4111 1111|REPLACE_WITH_LONG_RANDOM_INGEST_KEY/);
});

test('package validation refuses prompt bodies or development keys', () => {
  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';\nconst outcome = 'redacted_available';\nconst dir = '.promptsentinel-redacted';")),
    /development ingest key/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nconst outcome = 'redacted_available';\nconst dir = '.promptsentinel-redacted';\nconst sample = '524-71-9043';")),
    /synthetic SSN demo value/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || '';\nconst outcome = 'redacted_available';\nconst dir = '.promptsentinel-redacted';\nconst path = '/api/v1/scan-file';\nconst contentBase64 = 'abc';")),
    /without uploading file bodies/
  );

  assert.throws(
    () => validateRuntimeFiles(minimalFiles("const KEY = process.env.INGEST_API_KEY || '';")),
    /redacted companion handoff/
  );
});

test('packaged endpoint agent runs a package-to-install pilot smoke', async (t) => {
  const outDir = tempDir(t, 'ps-endpoint-agent-pilot-package-');
  const installRoot = tempDir(t, 'ps-endpoint-agent-pilot-install-');
  const watchDir = path.join(installRoot, 'watch');
  const configDir = path.join(installRoot, 'config');
  const configPath = path.join(configDir, 'endpoint-agent.env');
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(configPath, [
    'SENTINEL_URL=http://sentinel.package.test',
    'INGEST_API_KEY=pilot-ingest-key-000000000000000000000000000001',
    `ENDPOINT_AGENT_WATCH_DIR=${watchDir}`,
    'SENTINEL_REQUEST_TIMEOUT_MS=250',
  ].join('\n') + '\n');

  const packaged = packageEndpointAgent({ outDir, now: new Date('2026-06-26T13:00:00.000Z') });
  const zip = new AdmZip(packaged.zipPath);
  zip.extractAllTo(installRoot, true);

  const installScript = fs.readFileSync(path.join(installRoot, 'scripts', 'install-endpoint-agent.ps1'), 'utf8');
  const runnerScript = fs.readFileSync(path.join(installRoot, 'scripts', 'run-endpoint-agent.ps1'), 'utf8');
  const uninstallScript = fs.readFileSync(path.join(installRoot, 'scripts', 'uninstall-endpoint-agent.ps1'), 'utf8');
  assert.match(installScript, /Register-ScheduledTask/);
  assert.match(installScript, /INGEST_API_KEY=\$IngestKey/);
  assert.doesNotMatch(installScript, /"-IngestKey"/);
  assert.match(runnerScript, /\$env:SENTINEL_ENV_PATH = \$config/);
  assert.match(uninstallScript, /Unregister-ScheduledTask/);
  assert.match(uninstallScript, /endpoint-agent\.env/);

  const previousEnv = {};
  for (const key of ['SENTINEL_ENV_PATH', 'SENTINEL_URL', 'INGEST_API_KEY', 'ENDPOINT_AGENT_WATCH_DIR', 'SENTINEL_REQUEST_TIMEOUT_MS']) {
    previousEnv[key] = process.env[key];
    delete process.env[key];
  }
  process.env.SENTINEL_ENV_PATH = configPath;
  t.after(() => {
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  const agentPath = path.join(installRoot, 'endpoint-agent', 'agent.js');
  delete require.cache[agentPath];
  const agent = require(agentPath);
  t.after(() => { delete require.cache[agentPath]; });
  assert.strictEqual(agent.configuredKey({}), 'pilot-ingest-key-000000000000000000000000000001');

  fs.mkdirSync(watchDir, { recursive: true });
  const filename = 'member-524-71-9043.txt';
  fs.writeFileSync(path.join(watchDir, filename), 'Loan file. SSN 524-71-9043. Card 4111 1111 1111 1111.');

  const requests = [];
  const fetchImpl = async (url, opts = {}) => {
    requests.push({ url, method: opts.method || 'GET', body: opts.body || '' });
    assert.strictEqual(opts.headers['x-api-key'], 'pilot-ingest-key-000000000000000000000000000001');
    if (url === 'http://sentinel.package.test/api/v1/policy') {
      return {
        ok: true,
        json: async () => ({
          enforcementMode: 'redact',
          blockMinSeverity: 2,
          blockRiskScore: 20,
          alwaysBlock: ['US_SSN', 'CREDIT_CARD'],
          ignore: [],
          disabledDetectors: [],
          scanner: {
            ignoreDirectories: [],
            ignoreFilenames: [],
            ignoreExtensions: ['.tmp'],
            maxFileBytes: 4096,
          },
        }),
      };
    }
    if (url === 'http://sentinel.package.test/api/v1/gate') {
      const body = JSON.parse(opts.body);
      assert.strictEqual(body.clientOutcome, 'redacted_available');
      assert.strictEqual(body.clientPreRedacted, true);
      assert.strictEqual(body.source, 'endpoint_agent');
      assert.strictEqual(body.channel, 'file_upload');
      assert.match(body.prompt, /\[\[US_SSN_1\]\]/);
      assert.match(body.prompt, /\[\[CREDIT_CARD_1\]\]/);
      assert.match(body.note, /\.promptsentinel-redacted/);
      assert.ok(body.clientFindings.some((finding) => finding.type === 'US_SSN'));
      assert.ok(body.clientFindings.some((finding) => finding.type === 'CREDIT_CARD'));
      assert.ok(!JSON.stringify(body).includes('524-71-9043'));
      assert.ok(!JSON.stringify(body).includes('4111 1111 1111 1111'));
      assert.strictEqual(body.contentBase64, undefined);
      return {
        ok: true,
        json: async () => ({
          id: 'q_packaged_pilot',
          decision: 'redact',
          mode: 'redact',
          status: 'redacted',
          tokenizedPrompt: body.prompt,
          findings: body.clientFindings,
          categories: [],
          riskScore: body.clientRiskScore,
        }),
      };
    }
    throw new Error('unexpected packaged endpoint request: ' + url);
  };

  const scanner = await agent.refreshPolicy({ fetchImpl });
  assert.strictEqual(scanner.maxFileBytes, 4096);
  assert.ok(scanner.ignoreExtensions.has('.tmp'));

  const result = await agent.scanFile(filename, { user: 'pilot-user', fetchImpl });
  assert.strictEqual(result.decision, 'redact');
  assert.strictEqual(result.status, 'redacted');
  assert.ok(result.redactionHandoff);
  assert.match(result.redactionHandoff.relativePath, /^\.promptsentinel-redacted[\\/]/);
  assert.ok(!result.redactionHandoff.relativePath.includes('524-71-9043'));

  const companion = fs.readFileSync(result.redactionHandoff.path, 'utf8');
  assert.match(companion, /\[\[US_SSN_1\]\]/);
  assert.match(companion, /\[\[CREDIT_CARD_1\]\]/);
  assert.match(companion, /Original file: \[sensitive filename\]/);
  assert.ok(!companion.includes('524-71-9043'));
  assert.ok(!companion.includes('4111 1111 1111 1111'));
  assert.ok(requests.some((request) => request.url.endsWith('/api/v1/policy')));
  assert.ok(requests.some((request) => request.url.endsWith('/api/v1/gate')));
});

test('package args support explicit output directories', () => {
  const parsed = parseArgs(['--out', 'dist/custom-endpoint']);
  assert.match(parsed.outDir, /dist[\\/]custom-endpoint$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
});
